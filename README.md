# Permission-Aware Enterprise Retrieval (experimental v2)

For the separate, evidence-only enterprise deployment candidate, see [deployment and release gates](docs/PRODUCTION.md). The demo below is not a production deployment. To reproduce a fictional enterprise workflow with local sign-in and versioned citations, see the [Juniper Works reference lab](docs/REFERENCE_LAB.md).

Python demonstration of authenticated, permission-filtered retrieval over actual
PDF text, SQLite transactions and JSON logs. Optional sentence-transformer
embeddings and OpenAI-compatible citation-constrained synthesis are supported.
Offline deterministic retrieval is the default: no LLM API or model download.

**Status: experimental prototype, not production-certified.** The system does
not guarantee zero hallucinations, calibrated confidence, fully secure access,
or independently verified client ROI. Citations prove evidence membership,
not that a source entails an answer.

## Changes from the insecure prototype

- Caller-supplied user_id was removed. Bearer identity and role come from
  server-side demo configuration or a verified JWT.
- Actual PDF pages are parsed by pypdf instead of embedding hard-coded summaries.
- BM25 is the offline baseline; optional dense rankings are combined using
  reciprocal rank fusion, not incomparable raw score magnitudes.
- Original chunk IDs remain stable through permission-filtered ranking.
- Sales queries use parameterized SQL with region filters. Only an overall
  total or a total for one supported region is computed. Extra constraints
  cause abstention instead of being silently dropped.
- Manager-only uploads are authorised before multipart parsing. The request
  and file are bounded, and the candidate index is validated before promotion.
- SQL computations, evidence snippets and optional LLM synthesis have distinct
  output statuses. Unverified answer content is not labelled high confidence.
- Tests cover authentication, role isolation, SQL totals, uploads, evidence IDs,
  index alignment and authored synthetic benchmark cases.

## Local setup

Python 3.11 or newer:

    python -m pip install -r requirements.txt
    python synthetic_data.py
    python scripts/issue_demo_tokens.py

The last command prints a private JSON mapping from randomly generated bearer
tokens to synthetic identities. Set the complete JSON string as the environment
variable RAG_API_TOKENS_JSON. Do not check credentials into Git, share them in
logs, or reuse them. The service denies protected requests without them.

    uvicorn app.api:app --host 127.0.0.1 --port 8000

Use http://127.0.0.1:8000/docs or /ui. Example:

    POST /v1/query
    Authorization: Bearer YOUR_PRIVATE_TOKEN
    Content-Type: application/json

    {"query":"What is the total EMEA revenue?"}

The synthetic transaction answer should be $75,000 across two records. Its
financial-report PDF has a different reporting scope and must not be conflated.

Run offline checks:

    python -m pytest -q
    python eval_benchmark.py
    python eval_retrieval.py --ranking lexical --k 4

GET /health is public. Protected routes are POST /v1/query and
POST /v1/documents/upload. The previous user_id request parameter and
GET /v1/users endpoint are intentionally removed. Questions explicitly about
a policy, handbook, report, or PDF use permission-filtered document retrieval,
even if they mention logs, employees, or revenue.

For the synthetic directory, ask to list employees or employee names and
departments. Filtered directory requests abstain. Operational log results
recognise level aliases such as errors and warnings, apply message keywords
as an additional filter, and show up to 20 matches in newest-first order.

## Enterprise OIDC verification (optional)

Instead of RAG_API_TOKENS_JSON, configure RAG_OIDC_JWKS_URL (HTTPS),
RAG_OIDC_ISSUER and RAG_OIDC_AUDIENCE for an identity provider that signs
RS256 JWTs. The signed claim named enterprise_role must be analyst, manager
or auditor (override RAG_OIDC_ROLE_CLAIM only with a trusted issuer contract).
The verifier checks signature, expiry, issue time, audience, issuer and subject.
Do not configure local demo tokens and OIDC at the same time.
Real enterprise IdP onboarding, group mappings, consent, revocation and
operational assurance remain external validation requirements.

## Optional dense retrieval

    python -m pip install -r requirements-ml.txt

Set RAG_EMBEDDING_MODEL to an approved Sentence Transformers model. This may
download model weights. Review the licence, supply chain, deployment egress
and model performance before enabling. The baseline does not require this.
The dense ranking excludes candidates below a cosine score of 0.40 by default.
Hybrid retrieval can still include candidates from its lexical ranking.
Set `RAG_DENSE_MIN_SCORE` for a different approved model
or corpus after validating precision and abstention on held-out labels. The
floor is a heuristic, not an answer-confidence estimate.

## Optional LLM synthesis

Configure RAG_LLM_MODEL, RAG_LLM_ENDPOINT and RAG_LLM_API_KEY. Remote model egress also requires RAG_ALLOW_REMOTE_LLM=true.
Remote model endpoints must use HTTPS; loopback HTTP is allowed for local
servers. The LLM sees only the already-authorised evidence and cannot execute
tools. Its JSON citation IDs are validated against the retrieved evidence.

**No factual entailment guarantee** is made. Prompt injection, misleading
documents and unsupported generated conclusions remain open risks.

## Architecture

- rag_service.py: bounded parsing, permission-aware indexing, lexical and
  optional dense retrieval, SQL filtering, evidence responses, optional LLM.
- app/api.py: HTTP authentication, local rate limit, safe bounded uploads.
- synthetic_data.py: synthetic documents, database, logs and policy.
- fixtures/evaluation.json and eval_benchmark.py: authored functional cases.
- tests/: functional and adversarial regression coverage.

Read docs/SECURITY.md, docs/EVALUATION.md and docs/REVIEW.md for the
threat model, validation requirements, and known gaps.

## Important remaining work for real clients

This demo does not provide a deployed enterprise SSO integration or multi-tenant authorisation,
centralised token revocation, a distributed rate limiter, sandboxed PDF
extraction, AV scanning, a production document store, asynchronous indexing,
secret management, penetration testing, a statistically representative
human-labelled benchmark, or demonstrated business return. The offline
answer baseline is extractive, not free-form LLM generation.

The demo Compose file builds `Dockerfile.demo`, runs as a non-root user and binds to local loopback. `Dockerfile` builds the separate production candidate.
Do not expose the demo publicly or use it for confidential records.

Licence: MIT.
