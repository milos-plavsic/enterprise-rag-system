#!/usr/bin/env bash
# Scan the saved image, never the workspace or the host Docker socket.
set -euo pipefail
image=${1:?image required}
output=${2:?report path required}
scanner=ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/cache"
docker save "$image" -o "$scratch/image.tar"
chmod 0644 "$scratch/image.tar"
docker pull --platform linux/amd64 "$scanner"
common=(--rm --platform linux/amd64 --user "$(id -u):$(id -g)" --read-only
  --cap-drop ALL --security-opt no-new-privileges:true
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777)
docker run "${common[@]}" --mount "type=bind,src=$scratch/cache,dst=/cache" \
  "$scanner" --cache-dir /cache image --download-db-only --no-progress
# No credentials, host socket, source tree or egress during the actual scan.
docker run "${common[@]}" --network none \
  --mount "type=bind,src=$scratch/cache,dst=/cache" \
  --mount "type=bind,src=$image_tar,dst=/input.tar,readonly" \
  "$scanner" --cache-dir /cache image --input /input.tar --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json --no-progress \
  --exit-code 0 > "$output"
