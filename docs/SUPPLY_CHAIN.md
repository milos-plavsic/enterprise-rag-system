# Container supply-chain assurance

This document records the candidate assessment and the evidence required before a
new base image or vulnerability disposition can be accepted. It is not a
production certification or release approval.

## Current OpenSSL disposition (25 November 2026)

The production candidate uses exact Alpine `libssl3=3.5.9-r1` and
`libcrypto3=3.5.9-r1`. OpenSSL upstream rates the seven reviewed 17/24 November advisories Low,
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
| CVE-2026-84785 | OpenSSL QUIC out-of-order stream fragment reassembly | `no_quic_stack` |
| CVE-2026-107494 | OpenSSL QUIC connection-ID processing | `no_quic_stack` |
| CVE-2026-121482 | CMS/PKCS#7 verification with CRL checking | `no_cms_pkcs7_api`, `no_crl_check_configuration` |
| CVE-2026-84786 | DANE/TLSA client validation | `no_dane_api` |
| CVE-2026-107493 | PEM_X509_INFO parsing into an existing caller-supplied stack | `no_direct_pem_stack_api`, `python_tls_ca_loader_only` |
| CVE-2026-124709 | OpenSSL QUIC server rejected-stream handling | `no_quic_stack` |
| CVE-2026-35190 | TLS 1.3 server key-share processing with the Suite B certificate flag | `no_suite_b_certificate_flag` |

`scripts/openssl_reachability.py` runs inside the final candidate with no
network and a read-only filesystem. It verifies the explicit HTTP/1.1 `h11`
transport, absence of QUIC/DANE/CMS/PKCS#7/Suite-B/direct native application paths,
the final runtime's system-OpenSSL consumers, exact Alpine OpenSSL packages,
and the SQLite runtime/CLI invariants. Any package, protocol, source or native
consumer drift fails closed and requires a new review. A vendor-fixed package
should replace these dispositions as soon as it is available and passes the
same runtime tests.

The separate archive inventory gate parses ELF dynamic tables without running
candidate binaries, reports direct and transitive dependencies, and pins
the full ELF file inventory, Python source inventory, and application source
digest to the recorded reference candidate. Any drift requires a reviewed
baseline change. This baseline is derived from the actual prior artifact;
it is not a substitute for independent code-path review. In particular,
static linkage does not prove the absence of dynamic loading or indirect
native calls. The OpenSSL dispositions remain conditional until independently
reviewed or replaced with verified vendor-fixed packages.

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

The production workflow saves the exact Docker image archive immediately after
the build and records Buildx metadata. Before vulnerability evidence is
accepted, `scripts/image_identity.py` hashes the archive, selects the exact
expected tag, hashes the config bytes, rejects duplicate or unsafe tar members,
and validates the single-manifest OCI `index.json`. The validator hashes the
actual OCI manifest blob, checks its config descriptor, and verifies the
compressed SHA-256 of every layer and its decompressed `rootfs.diff_ids`
SHA-256. Buildx's manifest digest must match the archive's canonical OCI
manifest whenever the exporter supplies that field.

Grype may reconstruct an image manifest with different bytes or layer digest
semantics. Its embedded manifest is independently hashed and recorded as
`scanner_manifest_digest`, not substituted for the deployable image identity.
The Grype image-config digest must match the archive config, tying its evidence
to the verified candidate filesystem. The canonical `manifest_digest` and
OpenVEX product ID/hash refer to the manifest actually present in the OCI
archive. The archive SHA-256, OCI manifest digest, scanner reconstruction and
config digest are preserved separately. Docker's implementation-specific
`.Id` is not treated as a portable manifest digest. A future registry
publication must attest its registry manifest digest and explicitly map it to
this verified candidate; this workflow does not publish an image.

Grype is the primary scanner. Trivy 0.76.2 is a digest-pinned secondary scanner
that scans a saved image archive without the Docker socket, source-tree mount,
credentials or network access during the scan. Both raw reports are retained.
`scripts/compare_image_scans.py` records discrepancies but cannot waive them.

Two OpenVEX v0.2.0 documents are produced. The investigation document keeps
blocking findings `under_investigation` and is deterministic over the
candidate manifest, raw scan hash and generator hash. The reviewed release VEX
is produced only when the exact source-controlled disposition scope and runtime
evidence match. Both documents are validated against the official OpenVEX v0.2.0 JSON Schema fetched from the immutable specification commit `50abcfe257f1fc36ded2a17cc78e25821958cca2`. Validation runs offline with a digest-pinned Sourcemeta JSON Schema engine and format assertions enabled. The latest released `vexctl` v0.4.4 predates its `validate` subcommand, so CI does not pretend that command exists or depend on an unreleased tool build.

The existing SQLite disposition remains exact: only
`CVE-2026-119586` on Alpine `sqlite-libs` 3.54.1-r0 can be classified
`not_affected`, and only while the final runtime proves SQLite >= 3.54.1 and
the affected `sqlite3` CLI is absent.

Daily scheduled production assurance and manual dispatch are configured on the
default branch. The release bundle contains the raw scans, identity receipt,
reachability evidence, investigation and release VEX documents, SPDX and
CycloneDX inventories, checksums, and main-only build provenance. The complete SHA256SUMS manifest is itself an attestation subject; authenticate it against the approved main commit before using it to verify the evidence files. No registry
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
Python dependency-lock update automation, broader cross-runner browser reliability testing
and deployment monitoring remain separate work requiring tested integration.
Cross-scanner differences are captured, not historical trends. Do not claim
these capabilities merely because the current workflow generates evidence.

The scanner image is pinned from the [official registry](https://github.com/aquasecurity/trivy/pkgs/container/trivy).
The [March 2026 incident advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
is a reminder that scanners are supply-chain dependencies too. Independently
verify the digest and provenance before accepting an update. This isolated
invocation is a risk reduction, not proof of scanner integrity.

## Build materials and security tooling

The Linux x86_64 Python 3.12 security tool environment is isolated and installs only wheels from `requirements-security-linux-py312.lock` with required SHA-256 hashes. The Dockerfile frontend and every manually upgraded APK are checksum pinned; APK signatures are checked and installation is offline. GitHub-hosted Ubuntu 24.04 runners still receive image updates; their image release and Docker/Buildx versions are captured in the authenticated checksum manifest. These controls narrow and record mutable inputs; they do not claim bit-for-bit reproducibility across hosted runner updates or intentionally refreshed vulnerability feeds.

## Scanner acquisition and export identity

Grype v0.110.0 and Syft v1.42.3 are acquired directly from immutable GitHub releases with exact reviewed SHA-256 archive digests recorded in `scripts/install_verified_scanners.sh`. Scripts from moving branches are never downloaded or executed. Version and digest verification precedes use. The SHA-256 digests anchor the reviewed release artifacts; they do not by themselves prove the maintainer's signing identity.

The Buildx `--load` exporter and Docker Engine `save` can serialise image manifests differently, including OCI vs Docker media types. The verified archive and Buildx manifest digests are recorded separately. Mismatch is only accepted if Buildx's config digest matches the independently verified image config, which commits to rootfs diff IDs; every archived layer's compressed digest and decompressed diff ID is validated. Runtime Docker inspection and scanner configuration identity remain independent checks. Divergent manifest digests must never be presented as byte-equal artifacts.

The native gate now pins the effective filesystem's entire 6,413-entry reviewed baseline (file contents, directory and link entries, modes and numeric owners), rather than only ELF and Python source subsets. Changes to startup configuration and indirectly loaded native code therefore require re-review. This remains a drift detector, not proof of non-reachability of every OpenSSL path.

The Grype/Syft checksum manifests are also authenticated using Sigstore Cosign v3.1.6, whose executable is itself digest-pinned. Verification checks the Fulcio certificate's GitHub Actions OIDC issuer and Anchore source-workflow identity, and validates each binary against the signed checksum manifest. Failure is fatal. Trusted transparency-log verification remains enabled; no insecure bypass is used.

### Deterministic runtime filesystem baseline

Two independent candidate builds were compared to the earlier successful archive. Of 6,413 effective entries, exactly 955 installed-site-package `.pyc` bytecode files changed their content hashes, as did the APK world specification and an APK installation log; all other entries agreed. Because bytecode and logs were unrepeatable, production builds now use pip `--no-compile`, delete residual site-package bytecode and empty cache directories, and remove the APK transaction log. Bytecode or an APK log in the final image fails the native gate. The reviewed baseline of 5,283 remaining content-addressed filesystem entries includes the exact updated `/etc/apk/world` digest plus all other files, directories, mode bits, owners, symbolic links and hard links. Unreviewed changes, including startup files, still fail. This normalization is an explicit removal of generated code, not an exclusion of deployable code from the review.

The first bytecode-free production build at commit `a84813c5538436b4f24365532523e01aa70d103f` intentionally failed its pre-change filesystem baseline. Its authenticated GitHub Actions diagnostic artifact #15206392126, SHA-256 `68831865e510109b60ce7d4d36dcdc5648b16643db2ad671f7bf5632ac344e95`, was compared against the previous reference. Exactly 22 `.dist-info/RECORD` files changed following pip `--no-compile`; no executable files, package source files, links, modes or other retained entries changed. The new exact 5,283-entry baseline SHA-256 is `16c33912cb6fb44ff490d1ba78da9ade1559f4a393a5a91f7dbae4eda4b1c50f`. The gate continues to reject any install bytecode, cache directory, APK installation log, OCI extended attribute, duplicate layer entry or unreviewed file hash. A separate subsequent candidate build must reproduce the new baseline; a stale prior release artifact cannot demonstrate that reproducibility.

### Bounded browser administration

The browser harness executes routine source, backup, grant and revoke operations inside the already-running API container using `docker compose exec -T`, avoiding ephemeral network-interface churn during live browser assertions. Only restore preparation while the API is stopped launches a separate container. All Docker Compose child processes have process-group-aware TERM/KILL timeouts; credential and authorization checks are never retried. Phase markers contain only public release numbers and no protected document or OAuth data.

### Buildx exporter metadata classification

A direct review of the successful 27 November `docker buildx build --load` metadata confirms that `containerimage.digest` equals `containerimage.config.digest` and **not** the separately verified saved OCI manifest digest. The identity validator now classifies that reported digest as `config` or `archived-manifest`; any unknown third digest fails closed. The archived manifest bytes and layer contents are always separately hashed and recorded. Previous receipt field `buildx_manifest_digest` was semantically misleading and has been replaced by `buildx_exporter_reported_digest` and `buildx_exporter_digest_kind`. No claim is made that the two manifest representations have identical bytes.

### Final native/VEX release binding

The production gate now independently checks that the full accepted filesystem inventory matches the exact reviewed baseline, including the content digest of startup files and all ELF/Python source entries, and that its archive/OCI image identities match the final release decisions and VEX product hashes. It emits `rag-native-release-binding.json`, which is included in the authenticated release checksum manifest and is mandatory for a passing production image job. Adversarial unit tests change the effective filesystem, library inventory, source identity, scanner decisions and VEX claims; each must fail closed. This is a deterministic evidence consistency gate, not a proof that every native OpenSSL code path is unreachable, and it cannot replace separate security review.
