# Implementation notes

This is an offline-first, single-worker retrieval prototype. The
[README](README.md) describes supported requests and setup. The
[security model](docs/SECURITY.md) and [evaluation guide](docs/EVALUATION.md)
explain what the prototype does and what has not been validated.

## Request paths

- `app/api.py` authenticates protected requests with provisioned demo tokens
  or the optional OIDC verifier in `auth_oidc.py`. It enforces a local
  request limit. The caller cannot supply a role in a query.
- `query_intent.py` routes document and structured requests. Sales
  calculations accept only supported totals, without dropping extra filters.
- `rag_service.py` filters document candidates before ranking. SQLite totals
  and the directory use fixed read-only SQL, and operational logs are a
  separate permission-checked source.
- The default response is computed data, retrieved evidence, or abstention.
  Optional synthesis validates citation membership, not factual entailment.
- A manager upload is staged privately. The new index must be buildable before
  the file is promoted. The service reloads committed uploads at startup.

## Demo policy

| Role | Structured sources | Documents |
| --- | --- | --- |
| Analyst | Sample sales totals | Financial report |
| Manager | Sample sales totals and employee directory | Financial report, security policy, employee handbook, uploads |
| Auditor | Operational log samples | Security policy |

These permissions come from the generated fixture policy. They are not a
general-purpose enterprise access model. The service does not include
multi-tenant isolation, a confidential-data classifier, or production audit
infrastructure.
