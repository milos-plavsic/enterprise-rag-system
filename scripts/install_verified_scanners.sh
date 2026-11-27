#!/usr/bin/env bash
set -euo pipefail
dest="${1:?destination directory is required}"
mkdir -p "$dest"
# Pin the verifier itself before relying on its signature checks. Cosign v3.1.6
# is an immutable GitHub release asset. No untrusted install script is executed.
cosign_bin="$RUNNER_TEMP/cosign-linux-amd64-v3.1.6"
curl --fail --silent --show-error --location --retry 3 --max-time 180 \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://github.com/sigstore/cosign/releases/download/v3.1.6/cosign-linux-amd64 \
  --output "$cosign_bin"
printf '%s  %s\n' \
  318a99ade4156a0c4113aa983b46c0a0830fa7896a096c63121ee47b610a94c6 \
  "$cosign_bin" | sha256sum --check --status
chmod 0555 "$cosign_bin"
"$cosign_bin" version

# Immutable upstream release assets. SHA-256 values were independently read
# from the upstream GitHub releases API, and the checksum manifest is
# additionally verified against the maintainer workflow's Sigstore identity.
install_one() {
  local tool="$1" version="$2" sha="$3" archive
  archive="$RUNNER_TEMP/${tool}_${version}_linux_amd64.tar.gz"
  curl --fail --show-error --silent --location --retry 3 --max-time 120 \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "https://github.com/anchore/$tool/releases/download/v$version/${tool}_${version}_linux_amd64.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$sha" "$archive" | sha256sum --check --status
  # Pin the signature and signing certificate bytes too, so release metadata
  # drift cannot silently change the trust roots in this invocation.
  local checksums="$RUNNER_TEMP/${tool}_${version}_checksums.txt"
  local pem="$checksums.pem" sig="$checksums.sig"
  local checksums_hash pem_hash sig_hash
  case "$tool:$version" in
    grype:0.110.0)
      checksums_hash=210952ee17cafaf0636fea83e7049fe8c4f8503f4d7375ddd98b9defaf86ed34
      pem_hash=953adf75e6a84ee1fa9c0062e50d3436400798bfc73963316ba9add27d97b5be
      sig_hash=550f13a16ce278e464409f087ded03f80aeca8a3550212d763b43a2b0a0dfeb7 ;;
    syft:1.42.3)
      checksums_hash=3c4a66ddb6e0689fac2be19247064f6053e2a2746035dfbcef8609baa9088f92
      pem_hash=497aaaaec5b69edcb6dc426f97d7c8c5c28d8508bb550c917a084d8182d3af86
      sig_hash=349538abda800891805ed16de07d2cb98a0c04d8493b69893f7b224f45e5b423 ;;
    *) echo "Unreviewed scanner release" >&2; return 1 ;;
  esac
  local ext target expected
  for ext in '' '.pem' '.sig'; do
    target="$checksums$ext"
    case "$ext" in
      '') expected="$checksums_hash" ;;
      .pem) expected="$pem_hash" ;;
      .sig) expected="$sig_hash" ;;
    esac
    curl --fail --silent --show-error --location --retry 3 --max-time 60 \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      "https://github.com/anchore/$tool/releases/download/v$version/${tool}_${version}_checksums.txt$ext" \
      --output "$target"
    printf '%s  %s\n' "$expected" "$target" | sha256sum --check --status
  done
  "$cosign_bin" verify-blob "$checksums" \
    --certificate "$pem" --signature "$sig" \
    --certificate-identity-regexp "^https://github\\.com/anchore/$tool/\\.github/workflows/.+" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  (cd "$RUNNER_TEMP" && sha256sum --ignore-missing --check "$(basename "$checksums")")
  tar --extract --gzip --file "$archive" --directory "$dest" \
    --no-same-owner --no-same-permissions -- "$tool"
  chmod 0555 "$dest/$tool"
  "$dest/$tool" version
}
install_one grype 0.110.0 aaa98d27d2d7efd9317c6a1ad6d9b15f3e65bab320e7d03bde41e251387bb71c
install_one syft 1.42.3 0d6be741479eddd2c8644a288990c04f3df0d609bbc1599a005532a9dff63509
