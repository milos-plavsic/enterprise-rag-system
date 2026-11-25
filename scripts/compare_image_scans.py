"""Compare scanner evidence without letting either scanner waive the other."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SEVERITIES = {"negligible", "low", "medium", "high", "critical", "unknown"}
BLOCKING = {"high", "critical", "unknown"}


def check_severity(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("unrecognized scanner severity")
    severity = value.lower()
    if severity not in SEVERITIES:
        raise ValueError("unrecognized scanner severity")
    return severity


def compare(grype: dict, trivy: dict, identity: dict) -> dict:
    config = identity.get("config_digest")
    manifest = identity.get("manifest_digest")
    if not isinstance(config, str) or not DIGEST.fullmatch(config):
        raise ValueError("invalid config identity")
    if not isinstance(manifest, str) or not DIGEST.fullmatch(manifest):
        raise ValueError("invalid manifest identity")

    source = grype.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("Grype source is not an image")
    target = source.get("target")
    if (not isinstance(target, dict) or target.get("imageID") != config
            or target.get("manifestDigest") != identity.get("scanner_manifest_digest")):
        raise ValueError("Grype image identity mismatch")

    if trivy.get("ArtifactType") != "container_image":
        raise ValueError("Trivy source is not a container image")
    metadata = trivy.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("ImageID") != config:
        raise ValueError("Trivy image identity mismatch")

    gmatches = grype.get("matches")
    results = trivy.get("Results")
    if not isinstance(gmatches, list) or not isinstance(results, list) or not results:
        raise ValueError("missing scanner results")

    findings: dict[tuple[str, str, str], dict[str, set[str]]] = {}
    blocking_observations: list[dict] = []

    def add(source_name: str, ident: object, package: object, version: object, severity_value: object) -> None:
        if any(not isinstance(value, str) or not value.strip()
               for value in (ident, package, version)):
            raise ValueError("missing scanner finding identity")
        severity = check_severity(severity_value)
        findings.setdefault((ident, package, version), {}).setdefault(source_name, set()).add(severity)
        if severity in BLOCKING:
            blocking_observations.append({
                "scanner": source_name,
                "id": ident,
                "package": package,
                "version": version,
                "severity": severity,
            })

    for row in gmatches:
        vulnerability, package = row["vulnerability"], row["artifact"]
        add("grype", vulnerability["id"], package["name"], package["version"],
            vulnerability["severity"])

    for result in results:
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid Trivy findings")
        for row in vulnerabilities:
            add("trivy", row["VulnerabilityID"], row["PkgName"],
                row["InstalledVersion"], row["Severity"])

    return {
        "schema": 1,
        "image_manifest_digest": manifest,
        "scanner_manifest_digest": identity["scanner_manifest_digest"],
        "image_config_digest": config,
        "findings": [
            {
                "id": ident,
                "package": package,
                "version": version,
                "scanner_severities": {
                    scanner: sorted(values)
                    for scanner, values in sorted(sources.items())
                },
            }
            for (ident, package, version), sources in sorted(findings.items())
        ],
        "blocking_observations": sorted(
            blocking_observations,
            key=lambda row: (row["scanner"], row["id"], row["package"], row["version"]),
        ),
        "note": (
            "Evidence only. Release policy is enforced by evaluate_release_findings.py; "
            "a scanner disagreement or absence in one scanner is never an exception."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grype", type=Path)
    parser.add_argument("trivy", type=Path)
    parser.add_argument("identity", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = compare(
        json.loads(args.grype.read_bytes()),
        json.loads(args.trivy.read_bytes()),
        json.loads(args.identity.read_bytes()),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
