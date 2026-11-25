"""Compare scanner evidence without letting either scanner waive the other."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

SEVERITIES = {"negligible", "low", "medium", "high", "critical", "unknown"}
BLOCKING = {"high", "critical", "unknown"}


def check_severity(value: str) -> str:
    severity = value.lower()
    if severity not in SEVERITIES:
        raise ValueError("unrecognized scanner severity")
    return severity


def compare(grype: dict, trivy: dict, image: str) -> dict:
    if not DIGEST.fullmatch(image):
        raise ValueError("invalid image identity")
    if grype["source"]["type"] != "image" or grype["source"]["target"]["imageID"] != image:
        raise ValueError("Grype image identity mismatch")
    if trivy["ArtifactType"] != "container_image" or trivy["Metadata"]["ImageID"] != image:
        raise ValueError("Trivy image identity mismatch")
    gmatches, results = grype["matches"], trivy["Results"]
    if not isinstance(gmatches, list) or not isinstance(results, list) or not results:
        raise ValueError("missing scanner results")

    findings: dict[tuple[str, str, str], dict[str, set[str]]] = {}

    def add(source: str, ident: str, package: str, version: str, severity: str) -> None:
        if any(not isinstance(x, str) or not x.strip() for x in (ident, package, version)):
            raise ValueError("missing scanner finding identity")
        findings.setdefault((ident, package, version), {}).setdefault(source, set()).add(check_severity(severity))

    for row in gmatches:
        vuln, pkg = row["vulnerability"], row["artifact"]
        add("grype", vuln["id"], pkg["name"], pkg["version"], vuln["severity"])
    trivy_blocking = []
    for result in results:
        rows = result.get("Vulnerabilities")
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise ValueError("invalid Trivy findings")
        for row in rows:
            ident, name, version = row["VulnerabilityID"], row["PkgName"], row["InstalledVersion"]
            severity = check_severity(row["Severity"])
            add("trivy", ident, name, version, severity)
            # Same narrow product-specific disposition as the original gate;
            # require Alpine OS-package context, not a coincidental name match.
            cli_only = (ident, name, version, result.get("Class"), result.get("Type")) == (
                "CVE-2026-119586", "sqlite-libs", "3.54.1-r0", "os-pkgs", "alpine")
            if severity in BLOCKING and not cli_only:
                trivy_blocking.append({"id": ident, "package": name, "version": version, "severity": severity})

    return {
        "image_manifest_digest": manifest,\n        "image_config_digest": config,
        "findings": [
            {"id": ident, "package": pkg, "version": version,
             "scanner_severities": {k: sorted(v) for k, v in sorted(sources.items())}}
            for (ident, pkg, version), sources in sorted(findings.items())
        ],
        "trivy_blocking": sorted(trivy_blocking, key=lambda x: (x["id"], x["package"], x["version"])),
        "note": "This file is evidence only. Release policy is enforced by evaluate_release_findings.py; scanner discrepancies are not exceptions.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grype", type=Path)
    parser.add_argument("trivy", type=Path)
    parser.add_argument("image")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = compare(json.loads(args.grype.read_bytes()), json.loads(args.trivy.read_bytes()),\n                     json.loads(args.identity.read_bytes()))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for row in report["trivy_blocking"]:
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
