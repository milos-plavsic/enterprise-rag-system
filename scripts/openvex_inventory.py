"""Generate deterministic, non-waiving OpenVEX v0.2.0 investigation evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
AUTHOR = "https://github.com/milos-plavsic"
ROLE = "Document Creator"
TOOL = "enterprise-rag-system/scripts/openvex_inventory.py"


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def investigation(report: dict, identity: dict, raw_sha256: str, generator_sha256: str) -> dict:
    raw_sha256 = _digest(raw_sha256, "report digest")
    generator_sha256 = _digest(generator_sha256, "generator digest")
    manifest = _digest(identity.get("manifest_digest"), "manifest digest")
    product_id = identity.get("product_id")
    if (not isinstance(product_id, str)
            or not product_id.startswith("https://github.com/")
            or not product_id.endswith("/" + manifest.split(":", 1)[1])):
        raise ValueError("invalid product identifier")
    scanner = identity.get("scanner")
    if not isinstance(scanner, dict) or scanner.get("name") != "grype":
        raise ValueError("invalid scanner identity")
    timestamp = scanner.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("invalid scanner timestamp")

    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("scanner source is not an image")
    target = source.get("target")
    if (not isinstance(target, dict)
            or target.get("manifestDigest") != identity.get("scanner_manifest_digest")):
        raise ValueError("scanner manifest does not match identity receipt")
    if target.get("imageID") != identity.get("config_digest"):
        raise ValueError("scanner config does not match identity receipt")

    matches = report.get("matches")
    if not isinstance(matches, list):
        raise ValueError("scanner matches missing")
    groups: dict[str, set[tuple[str, str, str]]] = {}
    for row in matches:
        vulnerability, package = row["vulnerability"], row["artifact"]
        severity = vulnerability["severity"].lower()
        if severity not in {"negligible", "low", "medium", "high", "critical", "unknown"}:
            raise ValueError("unrecognized scanner severity")
        if severity not in {"high", "critical", "unknown"}:
            continue
        ident = vulnerability["id"]
        if not isinstance(ident, str) or not ident.strip():
            raise ValueError("missing vulnerability identifier")
        package_id = tuple(package[key] for key in ("name", "version", "type"))
        if any(not isinstance(value, str) or not value.strip() for value in package_id):
            raise ValueError("missing package identity")
        groups.setdefault(ident, set()).add(package_id)

    report_hex = raw_sha256.split(":", 1)[1]
    generator_hex = generator_sha256.split(":", 1)[1]
    document_id = (
        "https://github.com/milos-plavsic/enterprise-rag-system/security/vex/"
        f"{manifest.split(':', 1)[1]}/{report_hex}/{generator_hex}"
    )
    product = {
        "@id": product_id,
        "hashes": {"sha-256": manifest.split(":", 1)[1]},
    }
    statements = []
    for ident, packages in sorted(groups.items()):
        evidence = "; ".join("/".join(package) for package in sorted(packages))
        vulnerability = {"name": ident}
        if CVE.fullmatch(ident):
            vulnerability["@id"] = "https://www.cve.org/CVERecord?id=" + ident
        statements.append({
            "vulnerability": vulnerability,
            "timestamp": timestamp,
            "products": [product],
            "status": "under_investigation",
            "status_notes": (
                f"Scanner matches: {evidence}. Raw Grype report {raw_sha256}. "
                "No release exception or exploitability conclusion is implied."
            ),
        })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": document_id,
        "author": AUTHOR,
        "role": ROLE,
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"{TOOL} sha256:{generator_hex}",
        "statements": statements,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("identity", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    generator = Path(__file__).read_bytes()
    document = investigation(
        json.loads(raw),
        json.loads(args.identity.read_bytes()),
        "sha256:" + hashlib.sha256(raw).hexdigest(),
        "sha256:" + hashlib.sha256(generator).hexdigest(),
    )
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
