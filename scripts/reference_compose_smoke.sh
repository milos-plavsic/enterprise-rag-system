#!/usr/bin/env bash
set -euo pipefail
lab=$1
export RAG_LAB_PATH=$lab
python3 scripts/reference_lab.py prepare "$lab"
# Only the lab runtime account can write the database; don't loosen host path permissions.
sudo chown 10001:10001 "$lab/data"
rag=(docker compose --env-file "$lab/compose.env" -p juniper-reference -f compose.production.yml -f compose.reference.yml)
cleanup() {
  rc=$?
  if ((rc)); then "${rag[@]}" logs --no-color --tail 60 >&2 || true; fi
  "${rag[@]}" --profile local-model down -v --remove-orphans || true
}
trap cleanup EXIT
"${rag[@]}" config --quiet
"${rag[@]}" run --rm --no-deps api python production_admin.py init
"${rag[@]}" run --rm --no-deps api python production_admin.py sync-source /lab/source
"${rag[@]}" run --rm --no-deps api python production_admin.py grant 3b024b03-8260-484f-8f32-e5bdb744b319 analyst
"${rag[@]}" run --rm --no-deps api python production_admin.py grant 25d7591e-ce26-4352-bcf3-b8d15cc6c753 auditor
if [[ ${RAG_LAB_TEST_MODEL:-0} == 1 ]]; then
  python3 scripts/reference_lab.py model "$lab"
  export RAG_REFERENCE_ANSWER=local
  "${rag[@]}" --profile local-model up -d
  for _ in {1..60}; do
    if "${rag[@]}" exec -T api python -c 'from urllib.request import urlopen; urlopen("http://model:8080/health", timeout=2).close()' 2>/dev/null; then break; fi
    sleep 1
  done
  "${rag[@]}" exec -T api python -c 'from urllib.request import urlopen; urlopen("http://model:8080/health", timeout=2).close()'
else
  "${rag[@]}" up -d
fi
for _ in {1..90}; do
  if curl --silent --fail --max-time 4 --cacert "$lab/cert.pem" https://localhost:8443/realms/juniper/.well-known/openid-configuration -o /dev/null \
    && curl --silent --fail --max-time 8 http://localhost:8000/ready -o /dev/null; then break; fi
  sleep 1
done
curl --silent --fail --max-time 8 http://localhost:8000/ready -o /dev/null
node scripts/reference_browser.cjs
