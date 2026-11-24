"""Create non-waiving OpenVEX investigation evidence from a Grype image report.

The image identity is the local OCI config digest, not a registry manifest digest.
No generated statement can authorize packaging. Review and approval are separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


def investigation(report: dict, image_id: str, raw_sha256: str, timestamp: str) -> dict:
    if not DIGEST.fullmatch(image_id) or not DIGEST.fullmatch(raw_sha256):
        raise ValueError("expected SHA-256 image and report identities")
    source = report["source"]
    if source["type"] != "image" or source["target"]["imageID"] != image_id:
        raise ValueError("scanner image identity mismatch")
    matches = report["matches"]
    if not isinstance(matches, list):
        raise ValueError("scanner matches missing")
    groups: dict[str, set[tuple[str, str, str]]] = {}
    for row in matches:
        v, p = row["vulnerability"], row["artifact"]
        severity = v["severity"].lower()
        if severity not in {"negligible", "low", "medium", "high", "critical", "unknown"}:
            raise ValueError("unrecognized scanner severity")
        if severity not in {"high", "critical", "unknown"}:
            continue
        ident = v["id"]
        if not isinstance(ident, str) or not ident.strip():
            raise ValueError("missing vulnerability identifier")
        package = tuple(p[k] for k in ("name", "version", "type"))
        if any(not isinstance(x, str) or not x.strip() for x in package):
            raise ValueError("missing package identity")
        groups.setdefault(ident, set()).add(package)
    product = "urn:sha256:" + image_id.split(":")[1]
    statements = []
    for ident, packages in sorted(groups.items()):
        evidence = "; ".join("/".join(p) for p in sorted(packages))
        vulnerability = {"name": ident}
        if CVE.fullmatch(ident):
            vulnerability["@id"] = "https://www.cve.org/CVERecord?id=" + ident
        statements.append({
            "vulnerability": vulnerability,
            "products": [{"@id": product}],
            "status": "under_investigation",
            "status_notes": "Scanner matches: " + evidence +
                ". Raw Grype report " + raw_sha256 +
                ". No release exception or exploitability conclusion is implied.",
        })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:sha256:" + raw_sha256.split(":")[1],
        "author": "enterprise-rag-system automated scan inventory (unreviewed)",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("image_id")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    document = investigation(json.loads(raw), args.image_id,
                             "sha256:" + hashlib.sha256(raw).hexdigest(),
                             datetime.now(timezone.utc).isoformat())
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
