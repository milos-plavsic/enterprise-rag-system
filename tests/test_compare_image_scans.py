import pytest

from scripts.compare_image_scans import compare

CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
SCANNER_MANIFEST = "sha256:" + "f" * 64


def identity():
    return {
        "config_digest": CONFIG,
        "manifest_digest": MANIFEST,
        "scanner_manifest_digest": SCANNER_MANIFEST,
    }


def grype(severity="High"):
    return {
        "source": {
            "type": "image",
            "target": {"imageID": CONFIG, "manifestDigest": SCANNER_MANIFEST},
        },
        "matches": [{
            "vulnerability": {"id": "CVE-2026-124709", "severity": severity},
            "artifact": {"name": "libssl3", "version": "3.5.9-r1"},
        }],
    }


def trivy(ident="CVE-2026-124709", name="libssl3",
          version="3.5.9-r1", severity="LOW"):
    return {
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": CONFIG},
        "Results": [{
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [{
                "VulnerabilityID": ident,
                "PkgName": name,
                "InstalledVersion": version,
                "Severity": severity,
            }],
        }],
    }


def test_disagreement_is_retained_not_waived():
    report = compare(grype(), trivy(), identity())
    assert report["findings"][0]["scanner_severities"] == {
        "grype": ["high"], "trivy": ["low"]
    }
    assert report["blocking_observations"] == [{
        "scanner": "grype",
        "id": "CVE-2026-124709",
        "package": "libssl3",
        "version": "3.5.9-r1",
        "severity": "high",
    }]


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL", "UNKNOWN"])
def test_secondary_blocking_finding_is_preserved(severity):
    report = compare(grype("Low"), trivy(severity=severity), identity())
    assert report["blocking_observations"][0]["scanner"] == "trivy"
    assert report["blocking_observations"][0]["severity"] == severity.lower()


def test_sqlite_observation_is_not_waived_by_comparator():
    report = compare(
        grype("Low"),
        trivy("CVE-2026-119586", "sqlite-libs", "3.54.1-r0", "HIGH"),
        identity(),
    )
    assert report["blocking_observations"] == [{
        "scanner": "trivy",
        "id": "CVE-2026-119586",
        "package": "sqlite-libs",
        "version": "3.54.1-r0",
        "severity": "high",
    }]


@pytest.mark.parametrize("scanner", ["grype", "trivy"])
def test_wrong_config_identity_rejected(scanner):
    g, t = grype(), trivy()
    if scanner == "grype":
        g["source"]["target"]["imageID"] = "sha256:" + "c" * 64
    else:
        t["Metadata"]["ImageID"] = "sha256:" + "c" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        compare(g, t, identity())


def test_wrong_grype_manifest_rejected():
    g = grype()
    g["source"]["target"]["manifestDigest"] = "sha256:" + "c" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        compare(g, trivy(), identity())


def test_empty_results_rejected():
    report = trivy()
    report["Results"] = []
    with pytest.raises(ValueError, match="missing scanner results"):
        compare(grype(), report, identity())


@pytest.mark.parametrize("scanner", ["grype", "trivy"])
def test_invalid_severity_rejected(scanner):
    g, t = grype(), trivy()
    if scanner == "grype":
        g["matches"][0]["vulnerability"]["severity"] = "typo"
    else:
        t["Results"][0]["Vulnerabilities"][0]["Severity"] = "typo"
    with pytest.raises(ValueError, match="unrecognized scanner severity"):
        compare(g, t, identity())
