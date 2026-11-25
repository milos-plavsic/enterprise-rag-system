import pytest

from scripts.compare_image_scans import compare

IMAGE = "sha256:" + "a" * 64\nMANIFEST = "sha256:" + "b" * 64\n\ndef identity():\n    return {"config_digest": IMAGE, "manifest_digest": MANIFEST}


def grype():
    return {"source": {"type": "image", "target": {"imageID": IMAGE, "manifestDigest": MANIFEST}}, "matches": [
        {"vulnerability": {"id": "CVE-2026-124709", "severity": "High"},
         "artifact": {"name": "libssl3", "version": "3.5.9-r1"}}
    ]}


def trivy(ident="CVE-2026-124709", name="libssl3", version="3.5.9-r1", severity="LOW"):
    return {"ArtifactType": "container_image", "Metadata": {"ImageID": IMAGE}, "Results": [
        {"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": [
            {"VulnerabilityID": ident, "PkgName": name, "InstalledVersion": version, "Severity": severity}
        ]}
    ]}


def test_disagreement_is_retained_not_waived():
    report = compare(grype(), trivy(), identity())
    assert report["findings"][0]["scanner_severities"] == {"grype": ["high"], "trivy": ["low"]}
    assert not report["trivy_blocking"]


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "UNKNOWN"])
def test_secondary_high_finding_blocks(severity):
    assert len(compare(grype(), trivy(severity=severity), identity())["trivy_blocking"]) == 1


def test_exact_existing_disposition_only():
    report = trivy("CVE-2026-119586", "sqlite-libs", "3.54.1-r0", "HIGH")
    assert not compare(grype(), report, identity())["trivy_blocking"]
    report["Results"][0]["Type"] = "debian"
    assert compare(grype(), report, identity())["trivy_blocking"]


def test_wrong_image_rejected():
    report = trivy()
    report["Metadata"]["ImageID"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        compare(grype(), report, identity())


def test_empty_results_rejected():
    report = trivy()
    report["Results"] = []
    with pytest.raises(ValueError, match="missing scanner results"):
        compare(grype(), report, identity())


def test_invalid_severity_rejected():
    with pytest.raises(ValueError, match="unrecognized scanner severity"):
        compare(grype(), trivy(severity="typo"), identity())
