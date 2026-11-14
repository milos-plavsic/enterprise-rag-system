"""Generate a private disposable Keycloak realm with random local passwords."""
import json
import os
import secrets
import sys
from pathlib import Path

ORIGIN = "http://localhost:8000"
CLIENT = "juniper-browser"
USERS = (("avery", "analyst", "3b024b03-8260-484f-8f32-e5bdb744b319"),
         ("drew", "manager", "f42c83d4-d68b-4cd6-99b4-1e6c65157b30"),
         ("robin", "auditor", "25d7591e-ce26-4352-bcf3-b8d15cc6c753"))


def private_json(path: Path, payload) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2)


def prepare(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    accounts = {name: {"password": secrets.token_urlsafe(24), "role": role, "sub": subject}
                for name, role, subject in USERS}
    private_json(directory / "accounts.json", accounts)
    private_json(directory / "juniper-realm.json", {
        "realm": "juniper", "enabled": True, "sslRequired": "all", "accessTokenLifespan": 60,
        "registrationAllowed": False, "bruteForceProtected": True, "rememberMe": False,
        "clients": [{"clientId": CLIENT, "enabled": True, "protocol": "openid-connect", "publicClient": True,
                     "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
                     "redirectUris": [ORIGIN + "/reference/"], "webOrigins": [ORIGIN], "fullScopeAllowed": False,
                     "attributes": {"pkce.code.challenge.method": "S256", "access.token.header.type.rfc9068": "true"},
                     "protocolMappers": [
                         {"name": "rag-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                          "config": {"included.custom.audience": "juniper-rag", "access.token.claim": "true", "id.token.claim": "false"}},
                         {"name": "rag-role", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
                          "config": {"user.attribute": "rag_role", "claim.name": "enterprise_role", "jsonType.label": "String",
                                     "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}},
                     ]}],
        "users": [{"id": data["sub"], "username": name, "enabled": True, "emailVerified": True,
                   "firstName": name.title(), "lastName": "Test", "email": name + "@juniper.invalid",
                   "attributes": {"rag_role": [data["role"]]},
                   "credentials": [{"type": "password", "value": data["password"], "temporary": False}]}
                  for name, data in accounts.items()],
    })


if __name__ == "__main__":
    prepare(Path(sys.argv[1]))
