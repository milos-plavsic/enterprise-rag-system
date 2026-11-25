"""OpenVEX investigation evidence must be deterministic and non-waiving."""
import copy
import json

import pytest

from scripts.openvex_inventory import investigation
from scripts.check_image_scan import main as release_gate

CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
SCANNER_MANIFEST = "sha256:" + "f" * 64
REPORT = "sha256:" + "c" * 64
GENERATOR = "sha256:" + "d" * 64
STAMP = "2026-11-25T10:00:00Z"
PRODUCT = "https://github.com/milos-plavsic/enterprise-rag-system/container-images/sha256/" + "b" * 64


def match(ident="CVE-2026-124709", name="libssl3", severity="High"):
    return {
        "vulnerability": {"id": ident, "severity": severity, "fix": {"state": "unknown", "versions": []}},
        "artifact": {"name": name, "version": "3.5.9-r1", "type": "apk"},
    }


def report(*rows):
    return {
        "source": {"type": "image", "target": {"imageID": CONFIG, "manifestDigest": SCANNER_MANIFEST}},
        "matches": list(rows),
    }


def identity():
    return {
        "manifest_digest": MANIFEST,
        "scanner_manifest_digest": SCANNER_MANIFEST,
        "config_digest": CONFIG,
        "product_id": PRODUCT,
        "scanner": {"name": "grype", "version": "0.110.0", "timestamp": STAMP},
    }


def test_grouped_manifest_bound_investigation_is_deterministic():
    raw = report(match(), match(name="libcrypto3"), match(), match(severity="Low"))
    first = investigation(raw, identity(), REPORT, GENERATOR)
    second = investigation(copy.deepcopy(raw), copy.deepcopy(identity()), REPORT, GENERATOR)
    assert first == second
    assert first["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert first["author"] == "https://github.com/milos-plavsic"
    assert first["role"] == "Document Creator"
    assert first["timestamp"] == STAMP
    assert first["version"] == 1
    assert GENERATOR in first["tooling"]
    assert len(first["statements"]) == 1
    statement = first["statements"][0]
    assert statement["timestamp"] == STAMP
    assert statement["status"] == "under_investigation"
    assert statement["products"] == [{"@id": PRODUCT, "hashes": {"sha-256": "b" * 64}}]
    assert "libcrypto3/3.5.9-r1/apk" in statement["status_notes"]
    assert "libssl3/3.5.9-r1/apk" in statement["status_notes"]
    assert REPORT in statement["status_notes"]
    assert "justification" not in statement


def test_generator_or_report_change_changes_document_id():
    raw = report(match())
    base = investigation(raw, identity(), REPORT, GENERATOR)["@id"]
    assert investigation(raw, identity(), "sha256:" + "e" * 64, GENERATOR)["@id"] != base
    assert investigation(raw, identity(), REPORT, "sha256:" + "f" * 64)["@id"] != base


def test_clean_report_has_no_affirmative_claim():
    assert investigation(report(), identity(), REPORT, GENERATOR)["statements"] == []


@pytest.mark.parametrize("case", ["wrong_manifest", "wrong_config", "missing_matches", "invalid_severity", "missing_package"])
def test_invalid_evidence_rejected(case):
    raw, receipt = report(match()), identity()
    if case == "wrong_manifest":
        raw["source"]["target"]["manifestDigest"] = "sha256:" + "e" * 64
    elif case == "wrong_config":
        raw["source"]["target"]["imageID"] = "sha256:" + "e" * 64
    elif case == "missing_matches":
        raw["matches"] = None
    elif case == "invalid_severity":
        raw["matches"][0]["vulnerability"]["severity"] = "typo"
    else:
        raw["matches"][0]["artifact"]["version"] = ""
    with pytest.raises((ValueError, KeyError)):
        investigation(raw, receipt, REPORT, GENERATOR)


def test_unknown_severity_requires_investigation():
    raw = report(match(severity="Unknown"))
    assert investigation(raw, identity(), REPORT, GENERATOR)["statements"][0]["status"] == "under_investigation"


def test_inventory_does_not_waive_release_gate(tmp_path):
    raw = report(match())
    document = investigation(raw, identity(), REPORT, GENERATOR)
    assert document["statements"][0]["status"] == "under_investigation"
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert release_gate(path) == 1


@pytest.mark.parametrize("severity", ["High", "Critical", "Unknown"])
def test_gate_blocks_unresolved_severity(tmp_path, severity):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report(match(severity=severity))), encoding="utf-8")
    assert release_gate(path) == 1


def test_gate_rejects_unrecognized_severity(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report(match(severity="typo"))), encoding="utf-8")
    with pytest.raises(ValueError, match="unrecognized scanner severity"):
        release_gate(path)
