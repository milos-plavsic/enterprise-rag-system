# Container supply-chain assurance

This document records the candidate assessment and the evidence required before a
new base image or vulnerability disposition can be accepted. It is not a
production certification or release approval.

## Current OpenSSL disposition (25 November 2026)

The production candidate uses exact Alpine `libssl3=3.5.9-r1` and
`libcrypto3=3.5.9-r1`. OpenSSL upstream rates the five remaining issues Low,
while the distribution/scanner feed used by CI reports them High. OpenSSL fixes
the 3.5 branch in 3.5.10; the evaluated Alpine v3.24 repository did not yet
provide that package when checked on 25 November 2026.

The repository therefore uses product-specific reachability evidence rather than
a broad CVE allowlist. The exact reviewed scope is stored in
`security/openssl-3.5.9-r1-dispositions.json`. A disposition is accepted only
for the exact CVE, package name, package version and APK package type, and only
while every required runtime invariant is true.

| CVE | Upstream affected path | Required runtime evidence |
| --- | --- | --- |
| CVE-2026-124709 | OpenSSL QUIC server rejected-stream handling | `no_quic_stack` |
| CVE-2026-107494 | OpenSSL QUIC connection-ID processing | `no_quic_stack` |
| CVE-2026-121482 | CMS/PKCS#7 verification with CRL checking | `no_cms_pkcs7_api`, `no_crl_check_configuration` |
| CVE-2026-84786 | DANE/TLSA client validation | `no_dane_api` |
| CVE-2026-107493 | PEM_X509_INFO parsing into an existing caller-supplied stack | `no_direct_pem_stack_api`, `python_tls_ca_loader_only` |

`scripts/openssl_reachability.py` runs inside the final candidate with no
network and a read-only filesystem. It verifies the explicit HTTP/1.1 `h11`
transport, absence of QUIC/DANE/CMS/PKCS#7/direct native application paths,
the final runtime's system-OpenSSL consumers, exact Alpine OpenSSL packages,
and the SQLite runtime/CLI invariants. Any package, protocol, source or native
consumer drift fails closed and requires a new review. A vendor-fixed package
should replace these dispositions as soon as it is available and passes the
same runtime tests.

Reference: [OpenSSL 3.5 advisories](https://openssl-library.org/news/vulnerabilities-3.5/).

## Comparative evaluation

The non-release **Base image evaluation** workflow collects isolated evidence
for the current Alpine recipe, Debian Bookworm and Trixie slim, Docker
Hardened Python 3.12 developer image and Chainguard Python 3.12 developer image.
It resolves public tags to a digest before building. All alternatives use the
same application files and hash-locked runtime dependencies. The candidate
recipe is not a hardened release recipe and developer images are not a
recommendation to deploy a development runtime.

The workflow records the requested and resolved base, exact source commit,
build log, build time, image ID and size, actual Python/SQLite/OpenSSL versions
and UID/GID, deployment and recovery smoke, raw Grype scan and existing gate
result, SPDX SBOM, and per-stage outcomes. Each runner has an independent
container environment. Failure or skipped status is not acceptance. The
evaluation workflow can succeed at collecting negative evidence even when no
candidate passes. It does not publish images, request registry secrets, sign
artifacts or replace the production gate.

Docker Hardened Images may require authenticated access to dhi.io. The free
Chainguard tier supplies current versions and may not include the 3.12 tag.
See the [DHI Python guide](https://hub.docker.com/hardened-images/catalog/dhi/python/guides)
and [Chainguard free-tier policy](https://support.chainguard.dev/hc/en-us/articles/40405733238299-Customer-Notice-Free-Image-Tier-Changes).
Record unavailable candidates as unavailable, not vulnerable or safe. Do not
substitute an unrelated Python minor version to obtain a green result.

A candidate must subsequently pass the existing production and reference
workflows using a reviewed, immutable, minimal runtime recipe. It must retain
SQLite >= 3.54.1 and absence of the affected CLI, non-root runtime, read-only
filesystem, parser isolation, recovery semantics, TLS policy and all retrieval
and authorization invariants. Record representative latency, peak RSS and
throughput separately; build and smoke duration are not serving benchmarks.
Verify vendor provenance/signatures, license/entitlement and support lifetime.
Only then change the production Dockerfile and repeat exact-tree CI.

## OCI identity, dual scanning and OpenVEX

The production workflow records Buildx metadata and validates it against the
raw Grype report before vulnerability evidence is accepted.
`scripts/image_identity.py` verifies the Buildx config digest, descriptor,
Grype config digest, Grype embedded manifest bytes and manifest-to-config
relationship. The validated local manifest digest becomes the candidate product
identity; the Buildx manifest digest is retained separately because local
Docker load/export can alter manifest representation while preserving the image
config. A future registry publication must use and attest the registry digest;
this workflow does not publish an image.

Grype is the primary scanner. Trivy 0.76.2 is a digest-pinned secondary scanner
that scans a saved image archive without the Docker socket, source-tree mount,
credentials or network access during the scan. Both raw reports are retained.
`scripts/compare_image_scans.py` records discrepancies but cannot waive them.

Two OpenVEX v0.2.0 documents are produced. The investigation document keeps
blocking findings `under_investigation` and is deterministic over the
candidate manifest, raw scan hash and generator hash. The reviewed release VEX
is produced only when the exact source-controlled disposition scope and runtime
evidence match. Both documents are validated using digest-pinned `vexctl` in
strict mode. VEX validity alone is not sufficient: the release-policy evaluator
must also report zero unresolved High, Critical or Unknown findings.

The existing SQLite disposition remains exact: only
`CVE-2026-119586` on Alpine `sqlite-libs` 3.54.1-r0 can be classified
`not_affected`, and only while the final runtime proves SQLite >= 3.54.1 and
the affected `sqlite3` CLI is absent.

Daily scheduled production assurance and manual dispatch are configured on the
default branch. The release bundle contains the raw scans, identity receipt,
reachability evidence, investigation and release VEX documents, SPDX and
CycloneDX inventories, checksums, and main-only build provenance. No registry
push or deployment is performed.

## Release acceptance checklist

- Exact-head Python and TLS regressions, static analysis and CodeQL.
- Confirm original code scanning finding disposition; a successful analysis
  job alone is not proof of alert closure.
- Comparative candidate evidence and explicit selection rationale.
- Independently reviewed CVE disposition or confirmed fixed packages;
  no unresolved blocking findings.
- Complete production image build, security gate, deployment and recovery,
  reference browser tests, retrieval benchmark and SBOM.
- Reviewed runtime performance and compatibility, provenance and licensing.
- Independent reviewer approval for the exact final commit and scope.
- After authorized merge, verify the existing main-only artifact attestation
  and the immutable release identity before any use.

Registry publication/signing, historical differential reports across scans,
Python dependency-lock update automation, repeated browser reliability runs
and deployment monitoring remain separate work requiring tested integration.
Cross-scanner differences are captured, not historical trends. Do not claim
these capabilities merely because the current workflow generates evidence.

The scanner image is pinned from the [official registry](https://github.com/aquasecurity/trivy/pkgs/container/trivy).
The [March 2026 incident advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
is a reminder that scanners are supply-chain dependencies too. Independently
verify the digest and provenance before accepting an update. This isolated
invocation is a risk reduction, not proof of scanner integrity.
