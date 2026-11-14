"""Compatibility exports for v2 secure retrieval.

The legacy caller-supplied user_id interface is removed.
"""
from rag_service import (
    EnterpriseRAG, RBACEnforcer, TokenAuthenticator, Identity,
    InvalidDocument, InsufficientEvidence,
)
__all__ = [
    "EnterpriseRAG", "RBACEnforcer", "TokenAuthenticator", "Identity",
    "InvalidDocument", "InsufficientEvidence",
]
