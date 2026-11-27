import copy
import hashlib
import json

import pytest

from scripts.evaluate_release_findings import evaluate, release_vex

CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
SCANNER_MANIFEST = "sha256:" + "f" * 64
GENERATOR = "sha256:" + "e" * 64


def identity():
    return {
        "config_digest": CONFIG,
        "archive_sha256": "sha256:" + "1" * 64,
        "local_image_id": "sha256:" + "4" * 64,
        "source_commit": "2" * 40,
        "source_tree_sha256": "sha256:" + "c" * 64,
        "collector_sha256": "sha256:" + "3" * 64,
        "policy_sha256": "sha256:" + hashlib.sha256(json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "image_reference": "rag-candidate:" + "2" * 40,
        "manifest_digest": MANIFEST,
        "scanner_manifest_digest": SCANNER_MANIFEST,
        "product_id": (
            "https://github.com/milos-plavsic/enterprise-rag-system/"
            "container-images/sha256/" + "b" * 64
        ),
    }


def evidence():
    return {
        "schema": 1,
        "source_tree_sha256": "sha256:" + "c" * 64,
        "image_binding": {key: identity()[key] for key in (
            "config_digest", "manifest_digest", "archive_sha256", "local_image_id", "source_commit",
            "source_tree_sha256", "collector_sha256", "policy_sha256",
        )},
        "packages": {"libcrypto3": "3.5.9-r1", "libssl3": "3.5.9-r1"},
        "invariants": {
            "no_quic_stack": True,
            "no_dane_api": True,
            "no_cms_pkcs7_api": True,
            "no_crl_check_configuration": True,
            "no_direct_pem_stack_api": True,
            "no_suite_b_certificate_flag": True,
            "python_tls_ca_loader_only": True,
            "sqlite_cli_absent": True,
            "sqlite_runtime_patched": True,
        },
    }


def disposition(required):
    return {
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "required_invariants": required,
        "impact_statement": "Reviewed vulnerable execution path is absent.",
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
            "CVE-2026-84785": disposition(["no_quic_stack"]),
            "CVE-2026-107494": disposition(["no_quic_stack"]),
            "CVE-2026-121482": disposition(
                ["no_cms_pkcs7_api", "no_crl_check_configuration"]
            ),
            "CVE-2026-84786": disposition(["no_dane_api"]),
            "CVE-2026-107493": disposition(
                ["no_direct_pem_stack_api", "python_tls_ca_loader_only"]
            ),
            "CVE-2026-124709": disposition(["no_quic_stack"]),
            "CVE-2026-35190": disposition(["no_suite_b_certificate_flag"]),
        },
    }


def grype(*rows):
    return {
        "source": {
            "type": "image",
            "target": {"imageID": CONFIG, "manifestDigest": SCANNER_MANIFEST},
        },
        "matches": list(rows),
    }


def gmatch(ident="CVE-2026-124709", package="libssl3",
           version="3.5.9-r1", severity="High", package_type="apk"):
    return {
        "vulnerability": {"id": ident, "severity": severity},
        "artifact": {
            "name": package,
            "version": version,
            "type": package_type,
        },
    }


def trivy(*rows):
    return {
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": CONFIG},
        "Results": [{
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": list(rows),
        }],
    }


def tmatch(ident="CVE-2026-124709", package="libcrypto3",
           version="3.5.9-r1", severity="HIGH"):
    return {
        "VulnerabilityID": ident,
        "PkgName": package,
        "InstalledVersion": version,
        "Severity": severity,
    }


def test_exact_evidence_resolves_both_scanners():
    result = evaluate(
        grype(gmatch()), trivy(tmatch()), evidence(), policy(), identity()
    )
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


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_disposition_set_cannot_be_extended_or_reduced_in_json_only(mutation):
    scoped = policy()
    if mutation == "missing":
        scoped["dispositions"].pop("CVE-2026-124709")
    else:
        scoped["dispositions"]["CVE-2099-9999"] = disposition(["no_quic_stack"])
    with pytest.raises(ValueError, match="explicit reviewed CVE scope"):
        evaluate(grype(gmatch()), trivy(tmatch()), evidence(), scoped, identity())


def test_required_invariant_failure_rejects_disposition():
    broken = evidence()
    broken["invariants"]["no_quic_stack"] = False
    with pytest.raises(ValueError, match="does not satisfy"):
        evaluate(grype(gmatch()), trivy(tmatch()), broken, policy(), identity())


def test_scanner_identity_drift_rejected():
    report = grype(gmatch())
    report["source"]["target"]["manifestDigest"] = "sha256:" + "d" * 64
    with pytest.raises(ValueError, match="manifest mismatch"):
        evaluate(report, trivy(tmatch()), evidence(), policy(), identity())


def test_runtime_source_digest_is_mandatory():
    broken = evidence()
    broken["source_tree_sha256"] = "not-a-digest"
    with pytest.raises(ValueError, match="source digest"):
        evaluate(grype(gmatch()), trivy(tmatch()), broken, policy(), identity())


def test_release_vex_is_manifest_bound_and_stable():
    current_policy = policy()
    current_evidence = evidence()
    current_identity = identity()
    raw = json.dumps(current_policy, sort_keys=True).encode()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()

    first = release_vex(
        current_policy, current_evidence, current_identity, digest, GENERATOR
    )
    second = release_vex(
        copy.deepcopy(current_policy),
        copy.deepcopy(current_evidence),
        copy.deepcopy(current_identity),
        digest,
        GENERATOR,
    )
    assert first == second
    assert first["author"] == "https://github.com/milos-plavsic"
    assert len(first["statements"]) == 7
    assert all(row["status"] == "not_affected" for row in first["statements"])
    assert all(
        row["justification"] == "vulnerable_code_not_in_execute_path"
        for row in first["statements"]
    )
    product = first["statements"][0]["products"][0]
    assert product["hashes"]["sha-256"] == "b" * 64
    assert all(
        component["@id"].startswith("pkg:apk/alpine/")
        for component in product["subcomponents"]
    )


def test_release_vex_generator_change_changes_document_id():
    current_policy = policy()
    current_evidence = evidence()
    current_identity = identity()
    digest = "sha256:" + "f" * 64
    first = release_vex(
        current_policy, current_evidence, current_identity,
        digest, "sha256:" + "1" * 64,
    )
    second = release_vex(
        current_policy, current_evidence, current_identity,
        digest, "sha256:" + "2" * 64,
    )
    assert first["@id"] != second["@id"]
    assert first["tooling"] != second["tooling"]


@pytest.mark.parametrize("invariant", [
    "no_quic_stack",
    "no_dane_api",
    "no_cms_pkcs7_api",
    "no_crl_check_configuration",
    "no_direct_pem_stack_api",
    "no_suite_b_certificate_flag",
    "python_tls_ca_loader_only",
])
def test_every_approved_openssl_invariant_fails_closed_when_false(invariant):
    broken = evidence()
    broken["invariants"][invariant] = False
    with pytest.raises(ValueError, match="runtime evidence does not satisfy"):
        evaluate(grype(gmatch()), trivy(tmatch()), broken, policy(), identity())


def test_canonical_manifest_remains_distinct_from_scanner_reconstruction():
    decisions = evaluate(grype(gmatch()), trivy(tmatch()), evidence(), policy(), identity())
    assert decisions["image_manifest_digest"] == MANIFEST
    assert decisions["scanner_manifest_digest"] == SCANNER_MANIFEST
    vex = release_vex(policy(), evidence(), identity(), GENERATOR, GENERATOR)
    assert vex["statements"][0]["products"][0]["hashes"]["sha-256"] == MANIFEST[7:]


@pytest.mark.parametrize("field", [
    "config_digest", "manifest_digest", "archive_sha256", "local_image_id", "source_commit",
    "source_tree_sha256", "collector_sha256", "policy_sha256",
])
def test_valid_but_mismatched_runtime_binding_rejected(field):
    stale = evidence()
    stale["image_binding"][field] = ("9" * 40 if field == "source_commit" else "sha256:" + "9" * 64)
    with pytest.raises(ValueError, match="binding mismatch"):
        evaluate(grype(gmatch()), trivy(), stale, policy(), identity())


def test_changed_policy_invariant_mapping_is_rejected():
    modified = policy()
    modified["dispositions"]["CVE-2026-121482"]["required_invariants"] = ["no_crl_check_configuration"]
    with pytest.raises(ValueError, match="invariant mapping"):
        evaluate(grype(gmatch()), trivy(), evidence(), modified, identity())


def test_valid_but_unrelated_source_digest_is_rejected():
    stale = evidence()
    stale["source_tree_sha256"] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="source digest mismatch"):
        evaluate(grype(gmatch()), trivy(), stale, policy(), identity())


def test_changed_policy_content_is_rejected():
    modified = policy()
    modified["dispositions"]["CVE-2026-121482"]["impact_statement"] = "Different reasoning"
    with pytest.raises(ValueError, match="policy digest mismatch"):
        evaluate(grype(gmatch()), trivy(), evidence(), modified, identity())
