"""Generate local demo tokens; do not commit or reuse the generated output."""
import json
import secrets
mapping={}
for subject,role in (("alice","analyst"),("bob","manager"),("charlie","auditor")):
    token=secrets.token_urlsafe(36)
    mapping[token]={"subject":subject,"role":role}
print("Set the following environment mapping privately:")
print("RAG_API_TOKENS_JSON="+json.dumps(mapping,separators=(",",":")))
print("Each randomly generated key is the bearer token for its indicated role.")
