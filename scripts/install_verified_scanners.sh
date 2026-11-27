#!/usr/bin/env bash
set -euo pipefail
dest="${1:?destination directory is required}"
mkdir -p "$dest"
# Immutable upstream release assets. SHA-256 values were independently read
# from the upstream GitHub releases API (not fetched from a mutable main branch).
install_one() {
  local tool="$1" version="$2" sha="$3" archive
  archive="$RUNNER_TEMP/${tool}_${version}_linux_amd64.tar.gz"
  curl --fail --show-error --silent --location --retry 3 --max-time 120 \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "https://github.com/anchore/$tool/releases/download/v$version/${tool}_${version}_linux_amd64.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$sha" "$archive" | sha256sum --check --status
  tar --extract --gzip --file "$archive" --directory "$dest" \
    --no-same-owner --no-same-permissions -- "$tool"
  chmod 0555 "$dest/$tool"
  "$dest/$tool" version
}
install_one grype 0.110.0 aaa98d27d2d7efd9317c6a1ad6d9b15f3e65bab320e7d03bde41e251387bb71c
install_one syft 1.42.3 0d6be741479eddd2c8644a288990c04f3df0d609bbc1599a005532a9dff63509
