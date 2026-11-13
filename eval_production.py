"""Evaluate the production retrieval store against offline, held-out labels.

The input and database may contain confidential data. Nothing leaves this process.
Report only aggregates, never query text, subject IDs or source IDs.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from production_store import ProductionStore, ROLES, validate_subject
from rag_service import Identity


class EvidenceError(ValueError):
    pass


def evaluate(db: ProductionStore, manifest: dict[str, Any]) -> dict:
    cases = manifest["cases"]
    thresholds = manifest["thresholds"]
    required_roles = set(manifest["required_roles"])
    required_groups = set(manifest["required_categories"])
    if not required_roles or required_roles - ROLES or not required_groups:
        raise EvidenceError("specify deployment roles and categories")
    if any(type(thresholds[key]) not in (int, float) or not math.isfinite(thresholds[key])
           or not 0 < thresholds[key] <= 1 for key in ("min_recall", "min_abstention")):
        raise EvidenceError("set finite, positive acceptance thresholds")
    if type(thresholds["min_per_cohort"]) is not int or thresholds["min_per_cohort"] < 1:
        raise EvidenceError("min_per_cohort must be positive")
    minimum = thresholds["min_per_cohort"]
    for value in required_groups:
        if not isinstance(value, str) or not value or len(value) > 64:
            raise EvidenceError("invalid category")
    groups = defaultdict(lambda: {"answerable": 0, "abstain": 0, "recall_sum": 0.0, "correct_abstain": 0, "leaks": 0})
    unique = set()
    for case in cases:
        subject, role, category = case["subject"], case["role"], case["category"]
        validate_subject(subject)
        if role not in required_roles or category not in required_groups:
            raise EvidenceError("case not in declared cohort")
        query = case["query"]
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 2000:
            raise EvidenceError("invalid evaluation query")
        key = (subject, " ".join(query.casefold().split()))
        if key in unique:
            raise EvidenceError("duplicate subject/query case")
        unique.add(key)
        relevant, allowed = set(case["relevant_sources"]), set(case["allowed_sources"])
        if not relevant <= allowed:
            raise EvidenceError("relevant sources must be independently labelled as allowed")
        iat = case["issued_at"]
        if type(iat) is not int:
            raise EvidenceError("issued_at must be an integer")
        result = db.query(query, Identity(subject, role, iat))
        sources = {row["source"] for row in result["citations"]} | {row["source"] for row in result["evidence"]}
        stats = groups[role, category]
        stats["leaks"] += len(sources - allowed)
        if relevant:
            stats["answerable"] += 1
            stats["recall_sum"] += len(relevant & sources) / len(relevant)
        else:
            stats["abstain"] += 1
            stats["correct_abstain"] += result["status"] == "abstained"
    cohorts = []
    for role in sorted(required_roles):
        for category in sorted(required_groups):
            stats = groups[role, category]
            n_answer, n_abstain = stats["answerable"], stats["abstain"]
            recall = stats["recall_sum"] / n_answer if n_answer else None
            abstention = stats["correct_abstain"] / n_abstain if n_abstain else None
            cohorts.append({"role": role, "category": category, "answerable": n_answer, "unanswerable": n_abstain,
                            "recall_at_4": recall, "abstention": abstention, "leaks": stats["leaks"],
                            "passed": (n_answer >= minimum and n_abstain >= minimum and not stats["leaks"]
                                       and recall >= thresholds["min_recall"]
                                       and abstention >= thresholds["min_abstention"])})
    return {"cases": len(cases), "cohorts": cohorts, "passed": all(row["passed"] for row in cohorts)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate(ProductionStore(args.database), json.loads(args.manifest.read_text(encoding="utf-8")))
    except (KeyError, ValueError, TypeError, PermissionError, OSError):
        parser.exit(2, "Invalid evaluation inputs, policy or corpus. No results produced.\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
