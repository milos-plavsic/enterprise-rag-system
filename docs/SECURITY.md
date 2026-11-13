# Security model and explicit limitations

Assets include documents, SQL rows, logs, role data, upload files, model prompts
and secrets. The client request, uploaded material, retrieved content and model
responses are all untrusted inputs.

## Implemented controls

- All privileged routes use server-configured opaque bearer credentials
  or verified JWTs when OIDC is enabled.
  Callers cannot choose their own subject or role.
- At least 32-character tokens are checked with SHA-256 and constant-time
  digest comparison. Tokens are not intentionally written to request logs.
- Per-subject local quota of 30 protected requests per minute.
- File uploads require manager identity before multipart parsing and accept
  only PDF and UTF-8 text. An ingress byte limit also applies to chunked uploads.
  Generated filenames avoid traversal. Size, page count, extracted text,
  per-instance document count and total chunk count are bounded.
- No user-controlled SQL strings. Fixed parameterized SQL uses read-only
  database connections and matches the complete supported sales query.
- Source permissions are applied before retrieval ranking, and source
  identities are not reconstructed from filtered list offsets.
- Optional model has bounded input/output, no tools, approved endpoint
  scheme and validated JSON citation IDs. The model client does not inherit
  HTTP proxy settings from the process environment.
- UI renders server data with textContent, not innerHTML.

## Missing production security controls

- Demo opaque tokens can be replaced by the optional pinned OIDC RS256/JWKS
  verifier, which validates issuer, audience, time claims and role claim.
  Real IdP integration, group-role governance, revocation, MFA, SSO policy
  and lifecycle testing are not provided by this repository.
- Current roles are coarse; tenancy and row-level permissions are not present.
- PDF extraction is in-process: untrusted uploads require isolated processing,
  malware scanning and limits on CPU/memory beyond these Python checks.
- Local rate limiting does not work across distributed workers or hosts.
- No production ingress TLS configuration, secrets manager, SIEM, audit-event
  integrity service, DLP review or external penetration testing is included.
- Source membership is not equivalent to truthful content or model faithfulness.
- Prompt injection and malicious documents may affect optional synthesis.
- A security assessment is required before using real customer data.

Relevant references: OWASP ASVS 5.0 file handling and OWASP LLM Top 10 2025.
