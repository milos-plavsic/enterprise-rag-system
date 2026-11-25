import copy
import hashlib
import json

import pytest

from scripts.evaluate_release_findings import evaluate, release_vex

CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64


def identity():
    return {
        "config_digest": CONFIG,
        "manifest_digest": MANIFEST,
        "product_id": "https://github.com/milos-plavsic/enterprise-rag-system/container-images/sha256/" + "b" * 64,
    }


def evidence():
    return {
        "schema": 1,
        "source_tree_sha256": "sha256:" + "c" * 64,
        "packages": {"libcrypto3": "3.5.9-r1", "libssl3": "3.5.9-r1"},
        "invariants": {
            "no_quic_stack": True,
            "no_dane_api": True,
            "no_cms_pkcs7_api": True,
            "no_crl_check_configuration": True,
            "no_direct_pem_stack_api": True,
            "python_tls_ca_loader_only": True,
            "sqlite_cli_absent": True,
            "sqlite_runtime_patched": True,
        },
    }


def policy():
    return {
        "schema": 1,
        "author": "https://github.com/milos-plavsic",
        "role": "Product Security Maintainer",
        "issued_at": "2026-11-25T10:00:00Z",
        "component": {
            "packages": ["libcrypto3", "libssl3"],
            "version": "3.5.9-r1",
            "type": "apk",
        },
        "dispositions": {
            "CVE-2026-124709": {
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "required_invariants": ["no_quic_stack"],
                "impact_statement": "No QUIC execute path.",
            }
        },
    }


def grype(*rows):
    return {
        "source": {"type": "image", "target": {"imageID": CONFIG, "manifestDigest": MANIFEST}},
        "matches": list(rows),
    }


def gmatch(ident="CVE-2026-124709", package="libssl3", version="3.5.9-r1", severity="High"):
    return {
        "vulnerability": {"id": ident, "severity": severity},
        "artifact": {"name": package, "version": version, "type": "apk"},
    }


def trivy(*rows):
    return {
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": CONFIG},
        "Results": [{"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": list(rows)}],
    }


def tmatch(ident="CVE-2026-124709", package="libcrypto3", version="3.5.9-r1", severity="HIGH"):
    return {
        "VulnerabilityID": ident,
        "PkgName": package,
        "InstalledVersion": version,
        "Severity": severity,
    }


def test_exact_evidence_resolves_both_scanners():
    result = evaluate(grype(gmatch()), trivy(tmatch()), evidence(), policy(), identity())
    assert not result["unresolved"]
    assert {row["scanner"] for row in result["resolved"]} == {"grype", "trivy"}


def test_sqlite_disposition_requires_runtime_invariants():
    result = evaluate(
        grype(gmatch("CVE-2026-119586", "sqlite-libs", "3.54.1-r0")),
        trivy(tmatch("CVE-2026-119586", "sqlite-libs", "3.54.1-r0")),
        evidence(), policy(), identity(),
    )
    assert not result["unresolved"]
    broken = evidence()
    broken["invariants"]["sqlite_cli_absent"] = False
    result = evaluate(
        grype(gmatch("CVE-2026-119586", "sqlite-libs", "3.54.1-r0")),
        trivy(tmatch("CVE-2026-119586", "sqlite-libs", "3.54.1-r0")),
        broken, policy(), identity(),
    )
    assert len(result["unresolved"]) == 2


@pytest.mark.parametrize("change", ["cve", "version", "package", "type"])
def test_scope_drift_fails_closed(change):
    row = gmatch()
    if change == "cve":
        row["vulnerability"]["id"] = "CVE-2099-9999"
    elif change == "version":
        row["artifact"]["version"] = "3.5.10-r0"
    elif change == "package":
        row["artifact"]["name"] = "other"
    else:
        row["artifact"]["type"] = "deb"
    result = evaluate(grype(row), trivy(), evidence(), policy(), identity())
    assert result["unresolved"]


def test_required_invariant_failure_rejects_disposition():
    broken = evidence()
    broken["invariants"]["no_quic_stack"] = False
    with pytest.raises(ValueError, match="does not satisfy"):
        evaluate(grype(gmatch()), trivy(tmatch()), broken, policy(), identity())


def test_scanner_identity_drift_rejected():
    g = grype(gmatch())
    g["source"]["target"]["manifestDigest"] = "sha256:" + "d" * 64
    with pytest.raises(ValueError, match="manifest mismatch"):
        evaluate(g, trivy(tmatch()), evidence(), policy(), identity())


def test_release_vex_is_manifest_bound_and_stable():
    p, e, i = policy(), evidence(), identity()
    raw = json.dumps(p, sort_keys=True).encode()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    first = release_vex(p, e, i, digest)
    second = release_vex(copy.deepcopy(p), copy.deepcopy(e), copy.deepcopy(i), digest)
    assert first == second
    assert first["author"] == "https://github.com/milos-plavsic"
    assert first["statements"][0]["status"] == "not_affected"
    assert first["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
    assert first["statements"][0]["products"][0]["hashes"]["sha-256"] == "b" * 64
    assert first["statements"][0]["products"][0]["subcomponents"][0]["@id"].startswith("pkg:apk/alpine/")
