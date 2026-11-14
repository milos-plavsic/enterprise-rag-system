# Juniper Works reference lab

Juniper Works is fictional. The lab demonstrates enterprise policy retrieval on one Linux/amd64 host without company data, paid APIs or an external identity tenant. It does not change the evidence-only production deployment into an approved generated-answer service. Do not use the lab's development identity server, HTTP browser origin, disposable certificate or credentials for production.

## Run it locally

Prerequisites are Linux/amd64, rootful Docker with Compose v2, Python 3, OpenSSL and unused loopback ports 8000 and 8443. The first run downloads containers and build inputs. Use a new private directory. The example gives the non-root service UID ownership of only the database directory.

```sh
export LAB="$PWD/.juniper-lab"
python3 scripts/reference_lab.py prepare "$LAB"
sudo chown 10001:10001 "$LAB/data"
docker build --platform linux/amd64 -t juniper-rag:local .
rag() { docker compose --env-file "$LAB/compose.env" -p juniper-reference -f compose.production.yml -f compose.reference.yml "$@"; }
rag run --rm --no-deps api python production_admin.py init
rag run --rm --no-deps api python production_admin.py sync-source /lab/source
rag run --rm --no-deps api python production_admin.py grant 3b024b03-8260-484f-8f32-e5bdb744b319 analyst
rag run --rm --no-deps api python production_admin.py grant 25d7591e-ce26-4352-bcf3-b8d15cc6c753 auditor
rag up -d
curl --cacert "$LAB/cert.pem" --fail https://localhost:8443/realms/juniper/.well-known/openid-configuration
curl --fail http://localhost:8000/ready
```

Trust the generated certificate only in a disposable local browser profile. Its SHA-256 fingerprint can be checked with `openssl x509 -in "$LAB/cert.pem" -noout -sha256 -fingerprint`. Visit [Juniper search](http://localhost:8000/reference/) using `localhost`, not `127.0.0.1`, because the Keycloak redirect and CORS allowlists are exact. Use the generated `avery` credentials from `$LAB/keycloak/accounts.json`. The generated private Compose environment also contains a disposable lab operator credential for identity lifecycle drills. The browser uses OIDC authorisation code + S256 PKCE. The access token remains in page memory and the session is cleared when the token expires. The clear-session button clears this page, not all Keycloak sessions. Keycloak signs short-lived access tokens and the app additionally checks the local grant on every operation. The lab's loopback HTTP origin is a deliberate local-only shortcut.

## The demonstration

1. Ask **Which expenses need manager approval?** The first version cites the 250-credit rule. Open a verified passage and keep its URL.
2. Run `python3 reference/corpus.py "$LAB/source" 2` then `rag run --rm --no-deps api python production_admin.py sync-source /lab/source`. The new query returns the 150-credit rule, with a new passage URL. The old URL no longer resolves.
3. Save a snapshot using `rag run --rm --no-deps api python production_admin.py backup /var/lib/rag/lab-backup.sqlite3`. Revoke the analyst using `rag run --rm --no-deps api python production_admin.py revoke 3b024b03-8260-484f-8f32-e5bdb744b319`. A new search and opening a saved link now fail. The auditor cannot retrieve the expenses policy either. Revocation cannot erase content a person already saw or saved outside the app.
4. Publish fixture release 3 and sync it to withdraw the travel policy. Stop the API. Quarantine the backup's grants using `production_admin.py --database /var/lib/rag/lab-backup.sqlite3 quarantine-restored-grants`. Before activation sync the current authoritative release into that same staged file using `--database /var/lib/rag/lab-backup.sqlite3 sync-source /lab/source`. Activate with `production_admin.py activate-restore /var/lib/rag/lab-backup.sqlite3` and restart. The app does not reinstate old grants, and reconciling the current manifest keeps the withdrawn policy out of search. A snapshot alone cannot recover policy changes made after that snapshot.

The source connector reads a complete manifest from a trusted read-only mount. Each document has a monotonically increasing content version, digest, effective timestamp and explicit role list. Only effective versions are accepted. A manifest can change access without changing content version. Missing managed documents are withdrawn, but private uploads and individually published documents are not affected. Sync is explicit, atomic and rejects stale releases. The connector is not a generic crawler or a replacement for organisation-specific ingestion and permission mapping. Existing schema-1 deployments should take a verified backup, stop the API and run the new image's `production_admin.py migrate` before starting it. To roll back to the old image, use a compatible pre-migration snapshot and reconcile withdrawals and access before serving.

## Optional local answer mode

In a fresh lab, prepare the model with `python3 scripts/reference_lab.py model "$LAB"`. This downloads a 491 MB checksum-verified Qwen2.5-0.5B-Instruct GGUF, pinned to its upstream revision. Review the [model card and licence](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) before redistribution. Enable the opt-in sidecar using `RAG_REFERENCE_ANSWER=local rag --profile local-model up -d`. The model has no published port, no corpus mount and no internet route. It receives the question and bounded excerpts from the caller's permitted evidence. It may select verbatim quotes by index, but cannot write free-form claims or take actions. The application rechecks selected passages before returning them and falls back to evidence if model output is unavailable or invalid. Selection can still be irrelevant or omit relevant facts. A real model quality assessment is separate from the no-invented-quote guarantee.

## Reproduce the measurements

Run `python reference_benchmark.py` after installing the repo's Python dependencies. It compares keyword, a hand-written concept expansion and offline latent-semantic retrieval on the same authored fictional questions. The semantic comparator fits only the permitted corpus and is capped to 128 chunks before falling back to lexical retrieval. A separate small concurrent workload probe reports its boundary, runtime, machine context and observed latencies. Results are not enterprise SLOs. `eval_production.py` remains available for independently labelled representative data if a future deployment has it. Do not describe the fictional labels as externally validated.

The normal PR workflow builds, scans and packages the production application image and runs the existing container recovery check. The additional local reference browser check exercises the self-hosted identity provider, versioned corpus, citation access, revoke and restore. It also exercises actual signing-key rollover with a restarted verifier, a freshly issued role mismatch, account disablement and an identity outage with cold signing-key cache. These checks do not establish zero interruption with a warm verifier or immediate upstream revocation of already-issued tokens. The optional model stack is not approved for customer data. Company policy mapping, data classification and retention, deployed infrastructure review, workload targets, sign-off and release provenance remain external deployment decisions. Stop the lab with `rag down`; `rag down -v` also deletes the disposable identity data and parser volume. The host database directory is not deleted by Compose.
