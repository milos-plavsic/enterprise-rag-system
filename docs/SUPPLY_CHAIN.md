# Container supply-chain assurance

This document records the candidate assessment and the evidence required before a
new base image or vulnerability disposition can be accepted. It is not a
production certification or release approval.

## Current blocking findings (24 November 2026)

The candidate scan in [run 45392902786](https://github.com/milos-plavsic/enterprise-rag-system/actions/runs/45392902786)
found five distinct CVEs across Alpine libssl3 and libcrypto3 3.5.9-r1.
The upstream [OpenSSL 3.5 advisories](https://openssl-library.org/news/vulnerabilities-3.5/)
rate the issues low, while the container scan rates them high. Preserve the
scanner severity until an independent product-specific assessment exists.

| CVE | Upstream affected functionality | Required product-specific evidence |
| --- | --- | --- |
| CVE-2026-124709 | QUIC server stream resource retention | Inspect actual network protocols, native library users, ingress and any QUIC server entry points. |
| CVE-2026-107494 | QUIC connection-ID frame queuing | Check both client and server use of native QUIC, including transitive dependencies. |
| CVE-2026-121482 | CRL processing during X.509 verification, notably CMS/PKCS#7 | Inspect certificate verification flags, trust inputs and all CMS/PKCS#7 parsing paths. |
| CVE-2026-84786 | DANE API in non-SMTP clients | Inspect native library consumers and any DANE configuration or direct calls. |
| CVE-2026-107493 | PEM certificate parsing into an existing caller-supplied stack | Inspect Python SSL and native library call paths for the exact API preconditions and trust boundaries. |

All five are under investigation; none has a new release exception. The
upstream fix target is 3.5.10. The public Alpine edge package index still
reported 3.5.9-r1 when checked. A source patch is not evidence that a supported,
signed distribution package has been released. Debian's tracker also reports
unresolved findings for Trixie. Do not choose a base solely because its scanner
reports fewer CVEs; corroborate the distribution advisory and actual runtime.

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

## OpenVEX investigation inventory

The production workflow generates an OpenVEX v0.2.0 inventory from the raw
Grype JSON and checks its source image ID against the locally built OCI config
digest. The raw report SHA-256 is recorded in each grouped finding. All
generated statements are `under_investigation`. Empty findings are not a
claim that a product is vulnerability-free. The inventory is retained before
the release gate and is not consumed by the gate as an exception.

See the [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).
A future reviewed disposition must bind the exact product digest, CVE,
component identity, applicable version and scope to reproducible evidence.
A non-applicability claim requires a valid VEX justification, call-path or
component evidence, explicit review by someone independent of the author,
and a defined revalidation trigger. Never infer non-applicability from
application-language API names alone. No new automated allowlist is enabled.

The existing narrowly documented SQLite CLI disposition is unchanged. The
gate also rejects unknown severity and malformed severity labels.
Daily scheduled production assurance and manual dispatch are configured; GitHub
runs the schedule on the default branch only. This rebuilds and rescans the
source candidate, not a previously deployed registry digest. Existing
Dependabot Docker and GitHub Actions monitoring remains in place.

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

Secondary scanner, CycloneDX, image signing at registry publication, historical
differential reports, Python dependency-lock update automation and deployment
monitoring remain separate work requiring tested integration. Do not claim
these capabilities merely because the current workflow generates evidence.
