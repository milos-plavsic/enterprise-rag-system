"""Apply exact, evidence-backed product dispositions to both image scanners.

This is the only production release exception engine. A finding is resolved only
when its scanner identity, component version, CVE and every required runtime
invariant match a source-controlled disposition. Everything else fails closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

BLOCKING = {"high", "critical", "unknown"}
SEVERITIES = {"negligible", "low", "medium", "high", "critical", "unknown"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EXPECTED_OPENSSL_CVES = frozenset({
    "CVE-2026-124709", "CVE-2026-107494", "CVE-2026-121482",
    "CVE-2026-84786", "CVE-2026-107493",
})


def severity(value: object) -> str:
    if not isinstance(value, str) or value.lower() not in SEVERITIES:
        raise ValueError("unrecognized scanner severity")
    return value.lower()


def _policy(policy: dict, evidence: dict) -> tuple[dict, set[str]]:
    if policy.get("schema") != 1 or evidence.get("schema") != 1:
        raise ValueError("unsupported evidence or policy schema")
    component = policy.get("component")
    if not isinstance(component, dict):
        raise ValueError("component policy missing")
    packages = component.get("packages")
    if not isinstance(packages, list) or not packages or any(not isinstance(p, str) for p in packages):
        raise ValueError("component packages missing")
    if component.get("version") != "3.5.9-r1" or component.get("type") != "apk":
        raise ValueError("unexpected OpenSSL disposition scope")
    runtime_packages = evidence.get("packages")
    if not isinstance(runtime_packages, dict) or any(runtime_packages.get(p) != component["version"] for p in packages):
        raise ValueError("runtime package evidence does not match policy")
    invariants = evidence.get("invariants")
    if not isinstance(invariants, dict):
        raise ValueError("runtime invariants missing")
    dispositions = policy.get("dispositions")
    if not isinstance(dispositions, dict) or not dispositions:
        raise ValueError("dispositions missing")
    if set(dispositions) != EXPECTED_OPENSSL_CVES:
        raise ValueError("OpenSSL disposition set must match the independently reviewed CVEs")
    source_digest = evidence.get("source_tree_sha256")
    if not isinstance(source_digest, str) or not DIGEST.fullmatch(source_digest):
        raise ValueError("runtime source digest missing")
    for cve, disposition in dispositions.items():
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            raise ValueError("invalid disposition CVE")
        if disposition.get("status") != "not_affected":
            raise ValueError("only reviewed not_affected dispositions are accepted")
        if disposition.get("justification") != "vulnerable_code_not_in_execute_path":
            raise ValueError("unexpected VEX justification")
        required = disposition.get("required_invariants")
        if not isinstance(required, list) or not required:
            raise ValueError("disposition lacks runtime invariants")
        if any(invariants.get(name) is not True for name in required):
            raise ValueError(f"runtime evidence does not satisfy {cve}")
        impact = disposition.get("impact_statement")
        if not isinstance(impact, str) or not impact.strip():
            raise ValueError("disposition lacks impact statement")
    return dispositions, set(packages)


def _grype_rows(report: dict) -> list[dict]:
    if report.get("source", {}).get("type") != "image":
        raise ValueError("Grype source is not an image")
    matches = report.get("matches")
    if not isinstance(matches, list):
        raise ValueError("Grype matches missing")
    rows = []
    for match in matches:
        vuln, pkg = match["vulnerability"], match["artifact"]
        sev = severity(vuln["severity"])
        if sev in BLOCKING:
            rows.append({
                "scanner": "grype", "id": vuln["id"], "severity": sev,
                "package": pkg["name"], "version": pkg["version"], "type": pkg["type"],
            })
    return rows


def _trivy_rows(report: dict) -> list[dict]:
    if report.get("ArtifactType") != "container_image":
        raise ValueError("Trivy source is not a container image")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy results missing")
    rows = []
    for result in results:
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid Trivy vulnerabilities")
        package_type = "apk" if result.get("Class") == "os-pkgs" and result.get("Type") == "alpine" else str(result.get("Type"))
        for vuln in vulnerabilities:
            sev = severity(vuln["Severity"])
            if sev in BLOCKING:
                rows.append({
                    "scanner": "trivy", "id": vuln["VulnerabilityID"], "severity": sev,
                    "package": vuln["PkgName"], "version": vuln["InstalledVersion"], "type": package_type,
                })
    return rows


def evaluate(grype: dict, trivy: dict, evidence: dict, policy: dict, identity: dict) -> dict:
    dispositions, packages = _policy(policy, evidence)
    config = identity.get("config_digest")
    manifest = identity.get("manifest_digest")
    if not isinstance(config, str) or not DIGEST.fullmatch(config):
        raise ValueError("invalid config digest")
    if not isinstance(manifest, str) or not DIGEST.fullmatch(manifest):
        raise ValueError("invalid manifest digest")
    if grype.get("source", {}).get("target", {}).get("imageID") != config:
        raise ValueError("Grype identity mismatch")
    if grype.get("source", {}).get("target", {}).get("manifestDigest") != manifest:
        raise ValueError("Grype manifest mismatch")
    if trivy.get("Metadata", {}).get("ImageID") != config:
        raise ValueError("Trivy identity mismatch")

    sqlite_ok = (
        evidence.get("invariants", {}).get("sqlite_cli_absent") is True
        and evidence.get("invariants", {}).get("sqlite_runtime_patched") is True
    )
    resolved, unresolved = [], []
    for row in _grype_rows(grype) + _trivy_rows(trivy):
        exact_sqlite = (
            row["id"], row["package"], row["version"], row["type"]
        ) == ("CVE-2026-119586", "sqlite-libs", "3.54.1-r0", "apk")
        exact_openssl = (
            row["id"] in dispositions
            and row["package"] in packages
            and row["version"] == policy["component"]["version"]
            and row["type"] == policy["component"]["type"]
        )
        if exact_sqlite and sqlite_ok:
            resolved.append({**row, "disposition": "not_affected", "evidence": "sqlite_cli_absent"})
        elif exact_openssl:
            required = dispositions[row["id"]]["required_invariants"]
            resolved.append({**row, "disposition": "not_affected", "evidence": required})
        else:
            unresolved.append(row)

    return {
        "schema": 1,
        "image_manifest_digest": manifest,
        "image_config_digest": config,
        "resolved": sorted(resolved, key=lambda x: (x["scanner"], x["id"], x["package"])),
        "unresolved": sorted(unresolved, key=lambda x: (x["scanner"], x["id"], x["package"])),
    }


def release_vex(policy: dict, evidence: dict, identity: dict, policy_sha256: str, generator_sha256: str) -> dict:
    if not DIGEST.fullmatch(policy_sha256):
        raise ValueError("invalid policy digest")
    dispositions, packages = _policy(policy, evidence)
    manifest = identity["manifest_digest"]
    product = {
        "@id": identity["product_id"],
        "hashes": {"sha-256": manifest.split(":", 1)[1]},
        "subcomponents": [
            {
                "@id": f"pkg:apk/alpine/{package}@{policy['component']['version']}?arch=x86_64",
                "identifiers": {
                    "purl": f"pkg:apk/alpine/{package}@{policy['component']['version']}?arch=x86_64"
                },
            }
            for package in sorted(packages)
        ],
    }
    stable = "|".join([
        manifest,
        policy_sha256,
        evidence["source_tree_sha256"],
    ]).encode()
    doc_hash = hashlib.sha256(stable).hexdigest()
    timestamp = policy.get("issued_at")
    author = policy.get("author")
    role = policy.get("role")
    if not all(isinstance(value, str) and value.strip() for value in (timestamp, author, role)):
        raise ValueError("VEX issuer metadata missing")
    statements = []
    for cve, disposition in sorted(dispositions.items()):
        required = disposition["required_invariants"]
        statements.append({
            "vulnerability": {
                "@id": "https://www.cve.org/CVERecord?id=" + cve,
                "name": cve,
            },
            "timestamp": timestamp,
            "products": [product],
            "status": "not_affected",
            "justification": disposition["justification"],
            "impact_statement": disposition["impact_statement"],
            "status_notes": (
                "Exact Alpine OpenSSL 3.5.9-r1 disposition. Required runtime invariants: "
                + ", ".join(required)
                + f". Policy {policy_sha256}; application source {evidence['source_tree_sha256']}."
            ),
        })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/milos-plavsic/enterprise-rag-system/security/vex/release/{doc_hash}",
        "author": author,
        "role": role,
        "timestamp": timestamp,
        "version": 1,
        "tooling": "enterprise-rag-system/scripts/evaluate_release_findings.py " + generator_sha256,
        "statements": statements,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grype", type=Path)
    parser.add_argument("trivy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("identity", type=Path)
    parser.add_argument("decisions", type=Path)
    parser.add_argument("vex", type=Path)
    args = parser.parse_args()
    grype = json.loads(args.grype.read_bytes())
    trivy = json.loads(args.trivy.read_bytes())
    evidence = json.loads(args.evidence.read_bytes())
    policy_raw = args.policy.read_bytes()
    policy = json.loads(policy_raw)
    identity = json.loads(args.identity.read_bytes())
    decisions = evaluate(grype, trivy, evidence, policy, identity)
    args.decisions.write_text(json.dumps(decisions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    generator_sha256 = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()\n    vex = release_vex(\n        policy, evidence, identity,\n        "sha256:" + hashlib.sha256(policy_raw).hexdigest(),\n        generator_sha256,\n    )
    args.vex.write_text(json.dumps(vex, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for row in decisions["unresolved"]:
        print(json.dumps(row, sort_keys=True))
    return int(bool(decisions["unresolved"]))


if __name__ == "__main__":
    raise SystemExit(main())
