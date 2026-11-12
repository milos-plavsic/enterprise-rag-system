"""Optional OIDC RS256 JWT authentication against an operator-pinned issuer/JWKS.

This module validates signatures and claims. It is not a replacement for
IdP configuration, identity governance, TLS, or organisational role policy.
"""
from __future__ import annotations
import os
from urllib.parse import urlparse
import jwt
from jwt import PyJWKClient
from rag_service import Identity

class OIDCAuthenticator:
    def __init__(
        self,
        jwks_url: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        role_claim: str | None = None,
        jwks_client: object | None = None,
    ) -> None:
        self.jwks_url = jwks_url or os.getenv("RAG_OIDC_JWKS_URL", "")
        self.issuer = issuer or os.getenv("RAG_OIDC_ISSUER", "")
        self.audience = audience or os.getenv("RAG_OIDC_AUDIENCE", "")
        self.role_claim = role_claim or os.getenv("RAG_OIDC_ROLE_CLAIM", "enterprise_role")
        parsed = urlparse(self.jwks_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or not parsed.path):
            raise RuntimeError("OIDC JWKS must use an explicit HTTPS endpoint")
        if not self.issuer.startswith("https://") or not self.audience or not self.role_claim:
            raise RuntimeError("OIDC issuer, audience and role claim must be configured")
        self.client = jwks_client or PyJWKClient(
            self.jwks_url, cache_jwk_set=True, lifespan=300, timeout=5
        )

    def authenticate(self, authorization: str | None) -> Identity | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not token or len(token) > 16_384:
            return None
        try:
            signing_key = self.client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token, signing_key,
                algorithms=["RS256"],
                audience=self.audience, issuer=self.issuer,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, OSError, ValueError):
            return None
        subject = claims.get("sub")
        role = claims.get(self.role_claim)
        if not isinstance(subject, str) or not subject.strip():
            return None
        if role not in ("analyst", "manager", "auditor"):
            return None
        return Identity(subject,role)
