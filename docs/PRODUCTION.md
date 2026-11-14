# Enterprise deployment candidate

This is an evidence-only profile for **one enterprise security domain, one linux/amd64 host and one API process**. It is not a hosted multi-tenant service or an HA system. It is not approved for enterprise data until the deployment-specific gates below are met. The local demo remains separate and keeps its structured synthetic queries, demo authentication, optional generation and browser interface. The production profile exposes document retrieval and does not execute demo SQL, generate text, load an embedding model or send evidence to a model provider.

The separately configured [Juniper Works reference lab](REFERENCE_LAB.md) is a fictional local demonstration, not a replacement for this profile or its enterprise release gates. Production continues to reject local answer mode and alternative ranking.

## Install and operate

1. Retrieve the CI image bundle, SBOM and checksum manifest from the approved `main` build. Verify the attestation with `gh attestation verify rag-image.tar.gz --repo milos-plavsic/enterprise-rag-system --signer-workflow milos-plavsic/enterprise-rag-system/.github/workflows/production.yml`, repeat for the SBOM and image ID, then verify `sha256sum -c SHA256SUMS`. Load the verified tar and compare `docker image inspect --format '{{.Id}}' IMAGE` with `rag-image.id`. Import that image into the approved registry and configure `RAG_IMAGE` using its **registry digest**, not a mutable tag. Use the same digest for the API and parser. The workflow does not auto-publish or deploy.
2. Provision an encrypted local block-backed directory `RAG_DATA_PATH`, owned by UID/GID 10001 with mode `0700`. Do not mount a network filesystem. Provision a unique audit HMAC key through a read-only file `RAG_AUDIT_KEY_PATH` readable by UID 10001 and restricted from other users. An encrypted dedicated backup target and central log transport are operator responsibilities.
3. Put a trusted TLS ingress in front of the Compose loopback listener. Enforce approved client networks and identity, pre-auth connection and request limits, body deadlines, TLS settings and an egress policy limiting API outbound connections to the approved IdP endpoint. Do not make `/ready` or `/health` public. The parser has no network and only mounts the Unix socket volume, not corpus data or identity/audit secrets.
4. Configure `RAG_OIDC_ISSUER`, `RAG_OIDC_AUDIENCE`, `RAG_OIDC_JWKS_URL` and, if different, `RAG_OIDC_ROLE_CLAIM`. The contract is an RS256 access token (`typ: at+jwt`, not an ID token) with an explicit key ID, an exact trusted issuer and API audience, a stable subject, the application role claim, and a lifetime of no more than five minutes. The app allows five seconds of clock skew. JWKS caching is bounded to one minute, and production also checks a local entitlement for each operation. Keep IdP and host clocks synchronised and pre-publish new keys before issuing tokens. An unavailable IdP is not bypassed. Cached keys remain valid until their cache expires, unless access was locally revoked.
5. Run the commands below from an operator account. Initialise once. Publish approved UTF-8 or PDF source files with explicit roles. For imports, mount a trusted temporary source directory read-only only on the operator container. There is no demo seeding on service startup. Backfill approved sources and grants deliberately when moving from the demo.

```sh
alias rag='docker compose -f compose.production.yml'
rag run --rm --no-deps api python production_admin.py init
rag run --rm --no-deps api python production_admin.py grant STABLE_IDP_SUBJECT analyst
rag up -d
curl --fail http://127.0.0.1:8000/ready
```

The application requires both the signed IdP role and the locally granted role. Operators run `grant SUBJECT ROLE` or `revoke SUBJECT` using the same `run` pattern. After a grant, wait at least six seconds on a synchronised clock before requesting a new access token. The accepted `iat` must exceed the recorded grant time by the five-second verifier skew allowance plus one second. A slower issuer clock can require a longer wait. Local revoke applies to subsequent requests without waiting for token expiry. A request authorised just before revocation may complete. An enterprise owner must connect IdP deprovisioning to this procedure or accept the documented maximum remaining token lifetime after the IdP stops issuing tokens. Test the actual provider before enabling access.

Uploaded documents are manager-only and private to the authenticated uploader, not shared across managers. An operator can publish reviewed documents to named roles, change the roles with `document-roles ID --role ROLE`, clear them by omitting `--role`, or remove the document with `delete ID`. Managers can delete only their own uploads. SQLite transactions persist the text chunks, document source ID and content hash together. Raw files are not retained or served. This does not make old snapshots or WAL history instantly disappear. Define deletion handling for encrypted backups and retention tiers, and reconcile deleted documents before any restored copy is brought online. The DB's policy history includes identifiers and is sensitive.

## Upgrade notes

Catalog schema 3 retains existing grants but extends each legacy token cutoff by the configured five-second clock-skew allowance. With the old service stopped and an independently verified backup retained, run `production_admin.py migrate` using the new image before startup. Migration also supports schema 1 directly. Migrate a schema 1 or 2 snapshot offline before using it with the new image. An old binary requires a compatible pre-migration snapshot. Do not use `activate-restore` across schemas. Either roll forward with a schema-compatible repair or roll back on a separate encrypted volume as follows:

1. Stop the API and operator jobs, close ingress, and leave the migrated volume unchanged. Copy the verified pre-migration snapshot into a new UID-owned `0700` volume as `catalog.sqlite3`.
2. Point `RAG_DATA_PATH` at the new volume and `RAG_IMAGE` at the verified previous digest. With that image's operator CLI, clear snapshot grants and reconcile all changes to managed and individually published documents against the current authoritative source. If the old schema or tooling cannot represent the required current policies, do not serve the old snapshot. Roll forward instead.
3. Start the previous image against only the new volume, still behind closed ingress. Check readiness and known-denied access, regrant only current subjects, then validate positive access with fresh tokens. Keep the original migrated volume available for a forward recovery. Rehearse this with the actual previous image before adopting it as a rollback plan.

## Recovery and monitoring

- `/health` is liveness. `/ready` checks the SQLite schema and write availability, a usable IdP key set and the parser socket. Alert on sustained readiness failures, ingress request latency and error rate, 429/503 responses, disk capacity, backup age, recovery drill failures and IdP/key-rotation errors. Route `rag_audit` structured events to a protected central sink. They contain status, latency, generated request ID, pseudonymous actor and returned source IDs. They omit token, query and document text. Ingress logs need separate redaction and retention configuration.
- For a live consistent backup, run `production_admin.py backup /var/lib/rag/snapshot.sqlite3` using the operator container, verify the resulting private file, and move a copy to approved off-host encrypted storage. Never copy just the live SQLite main file. Establish the interval from the accepted RPO and run a measured recovery drill for the RTO.
- For restore, stop the API, retain an encrypted copy of the current state, and stage the snapshot under a new name on the volume. Run `production_admin.py --database STAGED_FILE quarantine-restored-grants` to clear stale entitlements. Reconcile deleted documents and ACL changes against current authoritative records. Stop other operators from making changes during restore. Use `production_admin.py activate-restore STAGED_FILE` to checkpoint the old database and activate the quarantined stage while holding the API lock. Regrant only active subjects from current authoritative records after activation. Start behind a closed ingress and verify readiness, positive access and known-denied cases before reopening ingress.
- For application rollback, close ingress, verify that the prior attested image supports the active database schema, set its registry digest, recreate both containers, then repeat readiness and entitlement checks. If schema is incompatible, use the staged restore procedure. Do not restore old grants or ACLs simply to roll back code.
- Uploads and queries have separate concurrency bounds. The API performs no untrusted PDF parsing. Each parser child has CPU, memory and wall-clock limits. A failed or over-budget extraction creates no document. Production indexing reads current permitted chunks and does not require a global upload-time rebuild or distributed cache. The reference profile is capped at 100 documents and 3,000 chunks. The CI smoke batch is a regression check, not a workload sizing result.

### Disaster recovery when the active catalog is lost or corrupt

`activate-restore` is for a readable catalog. If it is absent or damaged, keep ingress closed and stop the API and operator jobs. Work on the replacement volume with a verified backup. Do not use the backup as the authority for what is current. Obtain a current recovery record and its approved SHA-256 from a trusted records custodian or independently maintained control plane, outside the failed volume. If you do not have that evidence, rebuild from authoritative sources or keep the service closed.

The recovery JSON must contain exactly three fields:

- `source_manifest_sha256` is the SHA-256 of the current complete managed-source `manifest.json`, or `null` if no managed documents are approved. Supply `--source` for a non-null value. Managed files are verified against the manifest and reconciled, including ACLs, current versions and withdrawals. A null manifest removes all managed documents from the recovered corpus.
- `source_history` maps every managed key, including withdrawals, to its highest authoritative version. Include withdrawal history even when the manifest is null. Use `{}` only if there is no managed history. Keep this record outside the failed volume alongside the approved release. It prevents resurrecting an old document version after losing the original catalog's history.
- `unmanaged` is the complete current allowlist of individually published or owner-private documents you choose to recover. Each row contains `id`, `sha256` of the original file, `owner` (subject or `null`), and `roles` (empty for private documents). Omitted documents are removed. An approved document that is missing from the snapshot, or whose digest or owner differs, stops recovery. A partial recovery must be explicitly authorised by the inventory, not inferred by the tool.

```sh
python production_admin.py --database /var/lib/rag/staged.sqlite3 quarantine-restored-grants
python production_admin.py recover-catalog /var/lib/rag/staged.sqlite3 \
  --authority /approved/current-recovery.json --authority-sha256 "$APPROVED_SHA256" \
  --source /approved/current-documents
```

The command refuses a healthy active catalog, verifies the recovery record against the independently supplied digest, reconciles a copy of the quarantined snapshot and installs it under the deployment lock. It does not infer that a valid hash is proof of freshness or who approved the record. It keeps the input snapshot and preserves the failed catalog and journal files in a private directory. Do not reopen ingress until readiness and positive/negative access checks pass with fresh grants. Keep or dispose of the preserved material using the organisation's retention policy.

## Release gates still requiring an enterprise environment

- Capture and review the actual ingress, encrypted storage, egress controls, audit sink and signed release digest. Exercise tenant/domain boundaries if requirements go beyond this profile.
- Run real IdP integration, key rollover, deprovisioning, role change and outage drills. Record evidence and the accepted maximum privilege-retention window.
- Benchmark representative concurrency, corpus size and latency, including simultaneous query and ingest. Set accepted SLOs, capacity and headroom, and verify backup/restore and image rollback against agreed RPO/RTO.
- Run held-out, independently labelled retrieval evaluation on authorised representative documents and queries with accepted thresholds by role and category. Include denied, stale and contradictory evidence. `python eval_production.py DATABASE MANIFEST` emits only aggregate per-cohort results and fails on permission leaks, missing cohorts or missed thresholds. The manifest declares `required_roles`, `required_categories`, `thresholds` (`min_per_cohort`, `min_recall`, `min_abstention`) and `cases` (`subject`, `issued_at`, `role`, `category`, `query`, independently labelled `allowed_sources` and `relevant_sources`). Do not commit a real manifest, tokens, queries, backups or corpus to this repository. See [evaluation guidance](EVALUATION.md).
- Record security and data governance approval, ownership, retention, authorised sources, exceptions and a named go/no-go decision. This profile intentionally does not support generated answers. Enabling those in a future profile requires separate answer and citation validation, data-egress and provider approval, and operational cost evidence.

Reference baselines for review include [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/), [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1) and [SLSA provenance](https://slsa.dev/spec/v1.2/provenance). These are reference points, not claims of certification or conformance.


## Image vulnerability disposition

The production image updates Alpine `zlib` and `krb5-libs` to the vendor fixed packages. It temporarily uses the checksum-pinned, signed Alpine `sqlite-libs` 3.54.1-r0 from the Alpine edge package repository because 3.24 still ships 3.53.4. No edge package repository is enabled in the image. Revisit the one package override when 3.24 provides a stable patched library. The [SQLite release history](https://www.sqlite.org/changes.html) and [Debian maintainer record](https://bugs.debian.org/1152790) document the upstream 3.54 library fixes.

The sole exact-match disposition in the high/critical scan gate is `CVE-2026-119586` on Alpine `sqlite-libs` 3.54.1-r0. The advisory describes the `sqlite3` command-line shell's `.recover` command, which is absent from this image. No application or restore command shells out to `sqlite3`. CI checks the actual runtime library and CLI absence before packaging. The raw report is retained even when the gate fails. A match on another package, version or advisory is not waived. See the [vendor advisory](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2026-119586).
