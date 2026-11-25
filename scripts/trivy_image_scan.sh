#!/usr/bin/env bash
# Scan the exact saved image archive, never the workspace or host Docker socket.
set -euo pipefail
image_tar=${1:?image archive required}
output=${2:?report path required}
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
# Network is permitted only to fetch Trivy's signed vulnerability database
# into an otherwise empty, runner-owned cache.
docker run "${common[@]}" --mount "type=bind,src=$scratch/cache,dst=/cache" \
  "$scanner" --cache-dir /cache image --download-db-only --no-progress
# The actual candidate scan has no network, credentials, source tree or Docker socket.
docker run "${common[@]}" --network none \
  --mount "type=bind,src=$scratch/cache,dst=/cache" \
  --mount "type=bind,src=$image_tar,dst=/input.tar,readonly" \
  "$scanner" --cache-dir /cache image --input /input.tar --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json --no-progress \
  --exit-code 0 > "$output"
