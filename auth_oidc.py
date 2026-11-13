"""Optional OIDC RS256 JWT authentication against an operator-pinned issuer/JWKS.

This module validates signatures and claims. It is not a replacement for
IdP configuration, identity governance, TLS, or organisational role policy.
"""
from __future__ import annotations
import os
from urllib.parse import urlparse
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler
from urllib.error import HTTPError
import json
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
import jwt
from jwt import PyJWKClient
from rag_service import Identity

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "redirect refused", headers, fp)


class BoundedJWKSClient(PyJWKClient):
    def fetch_data(self):
        try:
            with build_opener(ProxyHandler({}), HTTPSHandler(), NoRedirect()).open(
                self.uri, timeout=self.timeout,
            ) as response:
                data = response.read(65_537)
        except OSError as exc:
            raise PyJWKClientConnectionError("JWKS unavailable") from exc
        if len(data) > 65_536:
            raise PyJWKClientError("JWKS too large")
        try:
            keys = json.loads(data)["keys"]
        except (KeyError, TypeError, ValueError) as exc:
            raise PyJWKClientError("invalid JWKS response") from exc
        if not isinstance(keys, list) or not 1 <= len(keys) <= 32 or any(not isinstance(k, dict) for k in keys):
            raise PyJWKClientError("invalid JWKS key set")
        return {"keys": keys}


class OIDCAuthenticator:
    def __init__(
        self,
        jwks_url: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        role_claim: str | None = None,
        jwks_client: object | None = None,
        *, production: bool = False,
    ) -> None:
        self.production = production
        self.jwks_url = jwks_url or os.getenv("RAG_OIDC_JWKS_URL", "")
        self.issuer = issuer or os.getenv("RAG_OIDC_ISSUER", "")
        self.audience = audience or os.getenv("RAG_OIDC_AUDIENCE", "")
        self.role_claim = role_claim or os.getenv("RAG_OIDC_ROLE_CLAIM", "enterprise_role")
        parsed = urlparse(self.jwks_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or parsed.query or not parsed.path):
            raise RuntimeError("OIDC JWKS must use an explicit HTTPS endpoint")
        issuer_url = urlparse(self.issuer)
        if (issuer_url.scheme != "https" or not issuer_url.hostname or issuer_url.username
                or issuer_url.password or issuer_url.query or issuer_url.fragment
                or not self.audience or not self.role_claim):
            raise RuntimeError("OIDC issuer, audience and role claim must be configured")
        self.client = jwks_client or BoundedJWKSClient(
            self.jwks_url, cache_jwk_set=True, lifespan=60 if production else 300,
            timeout=3, cooldown_duration=15,
        )

    def readiness(self) -> None:
        self.client.get_signing_keys()

    def authenticate(self, authorization: str | None) -> Identity | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not token or len(token) > 16_384:
            return None
        try:
            if self.production:
                header = jwt.get_unverified_header(token)
                key_id = header.get("kid")
                if (header.get("typ") not in ("at+jwt", "application/at+jwt")
                        or header.get("alg") != "RS256" or not isinstance(key_id, str)
                        or not 1 <= len(key_id) <= 128):
                    return None
            signing_key = self.client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token, signing_key,
                algorithms=["RS256"],
                audience=self.audience, issuer=self.issuer,
                leeway=5 if self.production else 30,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except PyJWKClientConnectionError:
            if self.production:
                raise
            return None
        except (jwt.PyJWTError, OSError, ValueError, TypeError, OverflowError):
            return None
        subject = claims.get("sub")
        role = claims.get(self.role_claim)
        if (not isinstance(subject, str) or not subject.strip() or len(subject) > 255
                or any(ord(c) < 32 or ord(c) == 127 for c in subject)):
            return None
        if role not in ("analyst", "manager", "auditor"):
            return None
        issued_at = claims.get("iat")
        if self.production:
            expires_at = claims.get("exp")
            if (type(issued_at) is not int or type(expires_at) is not int
                    or not 0 < expires_at - issued_at <= 300):
                return None
        return Identity(subject, role, issued_at if self.production else None)
