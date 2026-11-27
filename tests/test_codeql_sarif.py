"""Negative tests for query identity, suppression and historical positive control."""
import pytest

from scripts.verify_codeql_sarif import RULE, verify_clean, verify_positive_control


def document(*results, enabled=True):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{
            "id": RULE, "defaultConfiguration": {"enabled": enabled},
        }]}},
        "results": list(results),
    }]}


def finding(path, suppressed=False):
    return {"ruleId": RULE, "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": path},
    }}], "suppressions": [{"kind": "inSource"}] if suppressed else []}


def test_clean_and_positive_control():
    verify_clean(document())
    verify_positive_control(document(finding("original.py")))


@pytest.mark.parametrize("suppressed", [False, True])
def test_normal_finding_is_never_waived(suppressed):
    with pytest.raises(ValueError):
        verify_clean(document(finding("scripts/smoke_idp.py", suppressed)))


def test_disabled_or_missing_query_is_rejected():
    with pytest.raises(ValueError):
        verify_clean(document(enabled=False))
    missing = document()
    missing["runs"][0]["tool"]["driver"]["rules"] = []
    with pytest.raises(ValueError):
        verify_clean(missing)


@pytest.mark.parametrize("results", [
    [], [finding("remediated.py")], [finding("original.py", True)],
    [finding("original.py"), finding("remediated.py")],
])
def test_control_must_detect_only_original_insecure_fixture(results):
    with pytest.raises(ValueError):
        verify_positive_control(document(*results))
