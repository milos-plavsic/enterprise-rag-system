"""The investigation inventory must not act as a release exception."""
import json

import pytest

from scripts.openvex_inventory import investigation
from scripts.check_image_scan import main as release_gate

IMAGE = "sha256:" + "a" * 64
REPORT = "sha256:" + "b" * 64
STAMP = "2026-11-24T12:00:00+00:00"


def match(ident="CVE-2026-124709", name="libssl3", severity="High"):
    return {"vulnerability": {"id": ident, "severity": severity,
                              "fix": {"state": "unknown", "versions": []}},
            "artifact": {"name": name, "version": "3.5.9-r1", "type": "apk"}}


def report(*rows):
    return {"source": {"type": "image", "target": {"imageID": IMAGE}},
            "matches": list(rows)}


def test_grouped_image_bound_investigation():
    raw = report(match(), match(name="libcrypto3"), match(), match(severity="Low"))
    document = investigation(raw, IMAGE, REPORT, STAMP)
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["timestamp"] == STAMP
    assert len(document["statements"]) == 1
    statement = document["statements"][0]
    assert statement["status"] == "under_investigation"
    assert statement["products"] == [{"@id": "urn:sha256:" + "a" * 64}]
    assert "libcrypto3/3.5.9-r1/apk" in statement["status_notes"]
    assert "libssl3/3.5.9-r1/apk" in statement["status_notes"]
    assert REPORT in statement["status_notes"]
    assert "justification" not in statement


def test_clean_report_has_no_affirmative_claim():
    assert investigation(report(), IMAGE, REPORT, STAMP)["statements"] == []


@pytest.mark.parametrize("case", ["wrong_image", "wrong_type", "missing_matches",
                                  "invalid_severity", "missing_package"])
def test_invalid_evidence_rejected(case):
    raw = report(match())
    if case == "wrong_image":
        raw["source"]["target"]["imageID"] = REPORT
    elif case == "wrong_type":
        raw["source"]["type"] = "directory"
    elif case == "missing_matches":
        raw["matches"] = None
    elif case == "invalid_severity":
        raw["matches"][0]["vulnerability"]["severity"] = "typo"
    else:
        raw["matches"][0]["artifact"]["version"] = ""
    with pytest.raises((ValueError, KeyError)):
        investigation(raw, IMAGE, REPORT, STAMP)


def test_unknown_severity_requires_investigation():
    raw = report(match(severity="Unknown"))
    assert investigation(raw, IMAGE, REPORT, STAMP)["statements"][0]["status"] == "under_investigation"


def test_inventory_does_not_waive_release_gate(tmp_path):
    raw = report(match())
    inventory = investigation(raw, IMAGE, REPORT, STAMP)
    assert inventory["statements"][0]["status"] == "under_investigation"
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert release_gate(path) == 1
