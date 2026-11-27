"""OIDC verification tests with locally generated keys; no network access."""
from __future__ import annotations
import time
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from auth_oidc import OIDCAuthenticator

ISSUER="https://identity.example.test/"
AUDIENCE="enterprise-rag"
JWKS="https://identity.example.test/.well-known/jwks.json"

class FakeSigningKey:
    def __init__(self,public): self.key=public

class FakeJWKClient:
    def __init__(self,key): self.key=key
    def get_signing_key_from_jwt(self,token):
        return FakeSigningKey(self.key.public_key())

@pytest.fixture
def oidc():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    auth=OIDCAuthenticator(
        JWKS, ISSUER, AUDIENCE,
        jwks_client=FakeJWKClient(key))
    def bearer(**changes):
        now=int(time.time())
        claims={
            "iss":ISSUER,"aud":AUDIENCE,"sub":"verified-user",
            "iat":now,"exp":now+300,"enterprise_role":"manager",
        }
        claims.update(changes)
        return "Bearer "+jwt.encode(claims,key,algorithm="RS256",headers={"kid":"test"})
    return auth,bearer

def test_valid_signature_and_claims(oidc):
    auth,bearer=oidc
    user=auth.authenticate(bearer())
    assert user.subject=="verified-user"
    assert user.role=="manager"

@pytest.mark.parametrize("change",[
    {"aud":"wrong-audience"},
    {"iss":"https://imposter.test/"},
    {"exp":0},
    {"enterprise_role":"superadmin"},
    {"sub":""},
])
def test_invalid_token_claims_denied(oidc,change):
    auth,bearer=oidc
    assert auth.authenticate(bearer(**change)) is None

def test_unsigned_token_rejected(oidc):
    auth,bearer=oidc
    now=int(time.time())
    unsigned=jwt.encode({"iss":ISSUER,"aud":AUDIENCE,"sub":"fake",
                         "iat":now,"exp":now+300,"enterprise_role":"manager"},
                         key="",algorithm="none")
    assert auth.authenticate("Bearer "+unsigned) is None

def test_invalid_jwks_scheme_rejected():
    with pytest.raises(RuntimeError):
        OIDCAuthenticator("http://identity.example.test/jwks",ISSUER,AUDIENCE,
                          jwks_client=object())

def test_missing_configuration_denied(monkeypatch):
    from app.api import authenticator
    monkeypatch.setenv("RAG_OIDC_JWKS_URL",JWKS)
    monkeypatch.setenv("RAG_OIDC_ISSUER",ISSUER)
    monkeypatch.setenv("RAG_OIDC_AUDIENCE",AUDIENCE)
    monkeypatch.setenv("RAG_API_TOKENS_JSON",'{"A":"demo"}')
    authenticator.cache_clear()
    with pytest.raises(RuntimeError,match="not both"):
        authenticator()
    authenticator.cache_clear()


def test_partial_oidc_settings_never_fall_back_to_demo_tokens(monkeypatch):
    from app.api import authenticator
    monkeypatch.setenv("RAG_OIDC_ISSUER",ISSUER)
    monkeypatch.delenv("RAG_OIDC_JWKS_URL",raising=False)
    monkeypatch.delenv("RAG_OIDC_AUDIENCE",raising=False)
    monkeypatch.setenv("RAG_API_TOKENS_JSON",'{"A":"demo"}')
    authenticator.cache_clear()
    with pytest.raises(RuntimeError,match="must include"):
        authenticator()
    authenticator.cache_clear()


def test_real_jwks_cache_rotation_cooldown_expiry_and_outage(monkeypatch):
    import io
    import json
    from concurrent.futures import ThreadPoolExecutor
    from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
    from auth_oidc import BoundedJWKSClient

    clock = [1000.0]
    calls = []
    online = [True]

    def public_jwk(kid):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        row = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        return {**row, "kid": kid, "use": "sig", "alg": "RS256"}

    old, new = public_jwk("old"), public_jwk("new")
    published = [old]

    class Opener:
        def open(self, *args, **kwargs):
            calls.append(clock[0])
            if not online[0]:
                raise OSError("unavailable")
            return io.BytesIO(json.dumps({"keys": published}).encode())

    monkeypatch.setattr("auth_oidc.build_opener", lambda *args: Opener())
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    client = BoundedJWKSClient(JWKS, lifespan=60, cooldown_duration=15)
    assert client.get_signing_key("old").key_id == "old"
    assert len(calls) == 1
    published.append(new)
    clock[0] += 1
    with pytest.raises(PyJWKClientError):
        client.get_signing_key("new")
    assert len(calls) == 1, "unknown kid must respect the initial fetch cooldown"
    clock[0] += 15
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: client.get_signing_key("new").key_id, range(8))) == ["new"] * 8
    assert len(calls) == 2, "concurrent unknown kid must trigger only one successful refresh"
    assert client.get_signing_key("old").key_id == "old"
    online[0] = False
    clock[0] += 16
    with pytest.raises(PyJWKClientConnectionError):
        client.get_signing_key("unknown")
    assert client.get_signing_key("old").key_id == "old", "failed refresh must not wipe valid cache"
    clock[0] += 61
    with pytest.raises(PyJWKClientConnectionError):
        client.get_signing_key("old")
    online[0] = True
    published[:] = [new]
    assert client.get_signing_key("new").key_id == "new"
    with pytest.raises(PyJWKClientError):
        client.get_signing_key("old")
