"""Small auditable concept expansion baseline, not a neural similarity model."""
from collections import Counter

import numpy as np

from rag_service import tokens
from reference_answer import GENERIC

CONCEPTS = (
    ("expense", "expenses", "reimbursement", "reimbursements", "reimburse", "repayment"),
    ("approval", "approvals", "authorisation", "authorization", "signoff"),
    ("vacation", "holiday", "leave", "pto"),
    ("retention", "retaining", "archiving", "preservation"),
    ("credential", "credentials", "password", "passwords", "passphrase"),
)


def expand(question: str) -> str:
    present = set(tokens(question))
    extra = sorted({word for group in CONCEPTS if present.intersection(group) for word in group} - present)
    return " ".join((question, *extra))


def clean(question: str) -> str:
    return " ".join(word for word in tokens(question) if word not in GENERIC)


class LatentSemantic:
    """Offline truncated SVD, fitted exclusively to the caller's authorised corpus."""

    def __init__(self, documents: list[str]):
        counts = [Counter(tokens(clean(doc))) for doc in documents]
        terms = sorted({term for row in counts for term in row})[:4000]
        self.columns = {term: i for i, term in enumerate(terms)}
        # Avoid dense SVD costs for large corpora. This is a bounded reference comparator.
        if not terms or len(documents) > 128:
            self.basis = None
            return
        matrix = np.stack([self._vector(row) for row in counts])
        _, singular, right = np.linalg.svd(matrix, full_matrices=False)
        dimensions = min(16, max(1, int(np.sum(singular > 1e-10)) - 1))
        self.basis = right[:dimensions].T

    def _vector(self, counts: Counter) -> np.ndarray:
        vector = np.zeros(len(self.columns))
        for term, count in counts.items():
            if term in self.columns:
                vector[self.columns[term]] = 1 + np.log(count)
        norm = np.linalg.norm(vector)
        return vector / norm if norm else vector

    def encode(self, texts: list[str]) -> list:
        if self.basis is None:
            return [[0.0] for _ in texts]
        return [self._vector(Counter(tokens(clean(text)))) @ self.basis for text in texts]
