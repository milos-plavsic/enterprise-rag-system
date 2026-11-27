#!/usr/bin/env bash
set -euo pipefail
lab=$1
export RAG_LAB_PATH=$lab
export RAG_LAB_PROJECT="juniper-reference-$(printf '%s' "$lab" | sha256sum | cut -c1-12)"
echo 'PHASE: preparing disposable reference environment'
python3 scripts/reference_lab.py prepare "$lab"
# Only the lab runtime account can write the database; don't loosen host path permissions.
sudo chown 10001:10001 "$lab/data"
rag=(docker compose --env-file "$lab/compose.env" -p "$RAG_LAB_PROJECT" -f compose.production.yml -f compose.reference.yml)
cleanup() {
  rc=$?
  if ((rc)); then
    # IdP/API logs can contain authorization metadata. Never dump raw logs to
    # public CI output; report only disposable service/container status.
    echo 'PHASE: reference lab failed; reporting container state without logs' >&2
    timeout --signal=TERM --kill-after=5s 20s "${rag[@]}" ps --format table >&2 || true
  fi
  if ! "${rag[@]}" --profile local-model down -v --remove-orphans; then
    echo "Reference lab cleanup failed" >&2
    if ((rc == 0)); then rc=1; fi
  fi
  if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$RAG_LAB_PROJECT")" ||
        -n "$(docker network ls -q --filter "label=com.docker.compose.project=$RAG_LAB_PROJECT")" ||
        -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$RAG_LAB_PROJECT")" ]]; then
    echo "Reference lab left project resources behind" >&2
    if ((rc == 0)); then rc=1; fi
  fi
  exit "$rc"
}
trap cleanup EXIT
"${rag[@]}" config --quiet
"${rag[@]}" run --rm --no-deps api python production_admin.py init
"${rag[@]}" run --rm --no-deps api python production_admin.py sync-source /lab/source
"${rag[@]}" run --rm --no-deps api python production_admin.py grant 3b024b03-8260-484f-8f32-e5bdb744b319 analyst
"${rag[@]}" run --rm --no-deps api python production_admin.py grant 25d7591e-ce26-4352-bcf3-b8d15cc6c753 auditor
if [[ ${RAG_LAB_TEST_MODEL:-0} == 1 ]]; then
  echo 'PHASE: verifying pinned local model artifact'
  python3 scripts/reference_lab.py model "$lab"
  export RAG_REFERENCE_ANSWER=local
  echo 'PHASE: starting local model and authenticated application'
  timeout --signal=TERM --kill-after=15s 8m "${rag[@]}" --profile local-model up -d
  for _ in {1..60}; do
    if "${rag[@]}" exec -T api python -c 'from urllib.request import urlopen; urlopen("http://model:8080/health", timeout=2).close()' 2>/dev/null; then break; fi
    sleep 1
  done
  "${rag[@]}" exec -T api python -c 'from urllib.request import urlopen; urlopen("http://model:8080/health", timeout=2).close()'
else
  echo 'PHASE: starting authenticated application'
  timeout --signal=TERM --kill-after=15s 8m "${rag[@]}" up -d
fi
for _ in {1..90}; do
  if curl --silent --fail --max-time 4 --cacert "$lab/cert.pem" https://localhost:8443/realms/juniper/.well-known/openid-configuration -o /dev/null \
    && curl --silent --fail --max-time 8 http://localhost:8000/ready -o /dev/null; then break; fi
  sleep 1
done
curl --silent --fail --max-time 8 http://localhost:8000/ready -o /dev/null
echo 'PHASE: beginning strict Chromium lifecycle assertions'
timeout --signal=TERM --kill-after=20s 16m node scripts/reference_browser.cjs
echo 'PASS: strict Chromium lifecycle assertions completed'
