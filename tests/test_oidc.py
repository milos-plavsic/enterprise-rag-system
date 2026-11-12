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
