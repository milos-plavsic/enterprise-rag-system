# Critical-review record (not independent certification)

This document records internal findings and code changes. No independent
reviewer has signed off on this repository. A distinct qualified reviewer must
examine the exact final commit, CI and deployment before calling it certified.

## Findings from original prototype

- Caller-controlled user_id allowed role impersonation.
- Unsafe client filenames in file upload storage.
- PDF content was hardcoded, not parsed.
- Filtered document positions were mismatched with embedding rows.
- Region filtering was missing from sales aggregation.
- Policies diverged between source metadata and RBAC configuration.
- BM25 and cosine scores were combined on incomparable scales.
- Routing prevented selected employee queries.
- Production-ready and zero-hallucination claims were unsubstantiated.
- Automated tests were insufficient for security and correctness.

## Work implemented in this branch

Authenticated bearer roles, generated upload IDs, bounded actual document
parsing, stable evidence IDs, pre-ranking role/source filtering, rank fusion,
parameterized regional SQL, explicit routing, optional bounded model synthesis,
honest documentation, and functional/negative regression tests.

## Follow-up correctness work

- Replaced the sales keyword blacklist with a complete supported-request grammar.
  Unsupported filters, exclusions, comparisons and mixed scopes abstain.
- Document intent takes precedence over overlapping structured-source words.
- Source-level ranking removes duplicate sources before its cutoff. Retrieval
  evaluation can compare lexical, dense and hybrid modes at the same cutoff.
- Added a loopback model integration regression for permission-scoped evidence.
- Moved upload authorisation ahead of multipart reads and candidate index
  validation ahead of file promotion. Kept blocking index work off the API
  event loop.

The separate Astra High review of `d975908` requested changes for severity
aliases and log ordering, and flagged obsolete architecture claims. The
follow-up normalises severity aliases, sorts records by timezone-aware
timestamps before applying the limit, and replaces the obsolete notes.
It also rejects unsupported directory filters and documents the configurable
dense retrieval score floor.

## Open independent sign-off gates

- Real provider OIDC/SSO integration, role governance and revocation beyond the included JWT verifier.
- External penetration tests, PDF parser isolation and malware scanning.
- Realistic permissioned document connector validation.
- Independently labelled QA, citation entailment, uncertainty calibration.
- Prompt-injection red-team testing of the optional model.
- Real load tests, P95 latency, model cost and resource budgets.
- Cross-worker policy consistency, security monitoring, supply-chain review.
- Independently observed business return and governance signoff.

These are not waived merely because the internal CI passes.
