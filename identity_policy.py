"""Shared JWT verification and local entitlement timing contract."""

# An issuer ahead by this much can still issue a token the verifier accepts.
PRODUCTION_JWT_LEEWAY_SECONDS = 5
GRANT_CUTOFF_SECONDS = PRODUCTION_JWT_LEEWAY_SECONDS + 1
