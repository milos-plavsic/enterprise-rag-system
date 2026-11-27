#!/usr/bin/env bash
# Scan the exact saved image archive, never the workspace or host Docker socket.
set -euo pipefail
image_tar=${1:?image archive required}
output=${2:?report path required}
db_receipt=${3:?database evidence path required}
scanner=ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
test -f "$image_tar"
image_tar=$(realpath "$image_tar")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/cache"
chmod 0700 "$scratch/cache"
docker pull --platform linux/amd64 "$scanner"
common=(--rm --platform linux/amd64 --user "$(id -u):$(id -g)" --read-only
  --cap-drop ALL --security-opt no-new-privileges:true
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777)
# Network is permitted only to fetch Trivy's vulnerability database over TLS.
# into an otherwise empty, runner-owned cache.
docker run "${common[@]}" --mount "type=bind,src=$scratch/cache,dst=/cache" \
  "$scanner" --cache-dir /cache image --db-repository ghcr.io/aquasecurity/trivy-db:2 --download-db-only --no-progress
# Record the database bytes used by the offline scan; do not claim a signature
# was verified when only transport and content integrity have been checked.
metadata="$scratch/cache/db/metadata.json"
database="$scratch/cache/db/trivy.db"
test -s "$metadata" && test -s "$database"
before_db=$(sha256sum "$database" | cut -d" " -f1)
before_meta=$(sha256sum "$metadata" | cut -d" " -f1)
# The actual candidate scan has no network, credentials, source tree or Docker socket.
docker run "${common[@]}" --network none \
  --mount "type=bind,src=$scratch/cache,dst=/cache" \
  --mount "type=bind,src=$image_tar,dst=/input.tar,readonly" \
  "$scanner" --cache-dir /cache image --input /input.tar --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json --no-progress \
  --list-all-pkgs --ignorefile /dev/null --exit-code 0 > "$output"
[[ "$before_db" == "$(sha256sum "$database" | cut -d" " -f1)" ]]
[[ "$before_meta" == "$(sha256sum "$metadata" | cut -d" " -f1)" ]]
python3 - "$metadata" "$output" "$image_tar" "$db_receipt" "$before_db" "$before_meta" "$scanner" <<'PY'
import hashlib, json, sys
from pathlib import Path
metadata, report, archive, output = map(Path, sys.argv[1:5])
def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
raw = {"schema": 1, "metadata": json.loads(metadata.read_bytes()),
       "database_sha256": "sha256:" + sys.argv[5],
       "metadata_sha256": "sha256:" + sys.argv[6],
       "scanner_image": sys.argv[7], "report_sha256": digest(report),
       "archive_sha256": digest(archive)}
output.write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n")
PY
