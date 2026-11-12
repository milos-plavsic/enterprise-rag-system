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

## Open independent sign-off gates

- Authenticated OIDC/SSO integration with secure lifecycle/revocation.
- External penetration tests, PDF parser isolation and malware scanning.
- Realistic permissioned document connector validation.
- Independently labelled QA, citation entailment, uncertainty calibration.
- Prompt-injection red-team testing of the optional model.
- Real load tests, P95 latency, model cost and resource budgets.
- Cross-worker policy consistency, security monitoring, supply-chain review.
- Independently observed business return and governance signoff.

These are not waived merely because the internal CI passes.
