"""Regression tests for the canonical GitHub branch-protection request shape."""
from __future__ import annotations

import json
from pathlib import Path


POLICY = Path(__file__).resolve().parents[1] / "security" / "main-branch-protection.json"


def test_required_status_checks_uses_exactly_one_github_schema_variant() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    status_checks = policy["required_status_checks"]

    has_contexts = "contexts" in status_checks
    has_checks = "checks" in status_checks

    assert has_contexts ^ has_checks, (
        "GitHub branch-protection PUT requires exactly one required-status-check "
        "variant: legacy 'contexts' or app-bound 'checks', never both."
    )


def test_app_bound_checks_are_used_for_required_status_checks() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    status_checks = policy["required_status_checks"]

    assert "checks" in status_checks
    assert "contexts" not in status_checks
    assert status_checks["checks"]

    for check in status_checks["checks"]:
        assert isinstance(check["context"], str) and check["context"]
        assert isinstance(check["app_id"], int)
