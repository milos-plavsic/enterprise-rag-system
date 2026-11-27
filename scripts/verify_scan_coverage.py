"""Validate scanner coverage, database freshness, and independently emitted inventories."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
TRIVY = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
MAX_AGE = timedelta(hours=48)
BLOCKING = {"high", "critical", "unknown"}


def timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("scanner timestamp must be timezone aware")
    return dt.astimezone(timezone.utc)


def fresh(value: str, now: datetime, label: str) -> None:
    age = now - timestamp(value)
    if age < -timedelta(minutes=5) or age > MAX_AGE:
        raise ValueError(f"{label} is stale or future-dated")


def package(kind: str, name: str, version: str) -> tuple:
    if kind not in {"apk", "python"} or not name or not version:
        raise ValueError("incomplete package inventory identity")
    normalized = re.sub(r"[-_.]+", "-", name).lower() if kind == "python" else name
    return kind, normalized, version


def purl_kind(purl: str) -> str | None:
    if purl.startswith("pkg:apk/"):
        return "apk"
    if purl.startswith("pkg:pypi/"):
        return "python"
    return None


def verify(grype: dict, trivy: dict, db: dict, spdx: dict, cdx: dict,
           identity: dict, report_hash: str, now: datetime) -> dict:
    descriptor = grype["descriptor"]
    if descriptor["name"] != "grype" or descriptor["version"] != "0.110.0":
        raise ValueError("unreviewed Grype version")
    fresh(descriptor["timestamp"], now, "Grype scan")
    config = descriptor["configuration"]
    if (config["only-fixed"] or config["only-notfixed"] or config["exclude"]
            or config["vex-documents"] or config["vex-add"] or not config["show-suppressed"]):
        raise ValueError("unexpected Grype filtering or suppression configuration")
    # Grype's built-in Linux kernel header exclusions apply only to rpm/deb;
    # this Alpine/Python candidate cannot use them to hide an apk finding.
    if any(rule.get("package", {}).get("type") not in {"rpm", "deb"}
           for rule in config["ignore"]):
        raise ValueError("unexpected Grype ignore rule")
    for match in grype.get("ignoredMatches", []):
        if match["vulnerability"]["severity"].lower() in BLOCKING:
            raise ValueError("blocking Grype match was ignored")
    status = descriptor["db"]["status"]
    if status["valid"] is not True or config["db"]["validate-age"] is not True or config["db"]["validate-by-hash-on-start"] is not True:
        raise ValueError("Grype database validation disabled or invalid")
    fresh(status["built"], now, "Grype database")
    url = urlsplit(status["from"])
    checksum = parse_qs(url.query).get("checksum", [])
    if url.scheme != "https" or url.hostname != "grype.anchore.io" or len(checksum) != 1 or not DIGEST.fullmatch(checksum[0]):
        raise ValueError("Grype database checksum evidence missing")
    for provider in ("alpine", "github", "nvd"):
        fresh(descriptor["db"]["providers"][provider]["captured"], now, f"Grype {provider} feed")
    if grype["distro"]["name"] != "alpine":
        raise ValueError("Grype did not identify Alpine OS")

    if trivy["SchemaVersion"] != 2 or trivy["Trivy"]["Version"] != "0.76.2":
        raise ValueError("unreviewed Trivy report format/version")
    fresh(trivy["CreatedAt"], now, "Trivy scan")
    if (trivy["Metadata"]["OS"]["Family"] != "alpine"
            or trivy["Metadata"]["ImageID"] != identity["config_digest"]
            or trivy["Metadata"]["DiffIDs"] != identity["rootfs_diff_ids"]):
        raise ValueError("Trivy did not scan the expected complete image")
    if (db["schema"] != 1 or db["scanner_image"] != TRIVY
            or db["report_sha256"] != report_hash or db["archive_sha256"] != identity["archive_sha256"]
            or not DIGEST.fullmatch(db["database_sha256"]) or not DIGEST.fullmatch(db["metadata_sha256"])):
        raise ValueError("Trivy database receipt is not bound to this scan")
    metadata = db["metadata"]
    if metadata["Version"] != 2:
        raise ValueError("unexpected Trivy database schema")
    fresh(metadata["UpdatedAt"], now, "Trivy database")
    fresh(metadata["DownloadedAt"], now, "Trivy database acquisition")
    if timestamp(metadata["NextUpdate"]) <= timestamp(metadata["UpdatedAt"]):
        raise ValueError("invalid Trivy database update interval")
    if now > timestamp(metadata["NextUpdate"]) + timedelta(hours=24):
        raise ValueError("Trivy database missed its update deadline")

    expected_classes = {("os-pkgs", "alpine"): "apk", ("lang-pkgs", "python-pkg"): "python"}
    inventory = set()
    seen_classes = set()
    for result in trivy["Results"]:
        key = (result["Class"], result["Type"])
        if key not in expected_classes or key in seen_classes:
            raise ValueError("unexpected or duplicate Trivy inventory target")
        seen_classes.add(key)
        rows = result.get("Packages")
        if not isinstance(rows, list) or not rows:
            raise ValueError("Trivy package inventory missing")
        kind = expected_classes[key]
        current = {package(kind, row["Name"], row["Version"]) for row in rows}
        inventory.update(current)
        for match in result.get("Vulnerabilities", []) or []:
            if package(kind, match["PkgName"], match["InstalledVersion"]) not in current:
                raise ValueError("Trivy finding not in scanned inventory")
    if seen_classes != set(expected_classes):
        raise ValueError("required OS/Python scan targets missing")

    spdx_inventory = set()
    for row in spdx["packages"]:
        for ref in row.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                kind = purl_kind(ref["referenceLocator"])
                if kind:
                    spdx_inventory.add(package(kind, row["name"], row["versionInfo"]))
    cdx_inventory = set()
    for row in cdx["components"]:
        kind = purl_kind(row.get("purl", ""))
        if kind:
            cdx_inventory.add(package(kind, row["name"], row["version"]))
    if not inventory or inventory != spdx_inventory or inventory != cdx_inventory:
        raise ValueError("Trivy OS/Python inventory differs from independent SPDX/CycloneDX SBOM")
    if not {"libssl3", "libcrypto3", "sqlite-libs"} <= {name for kind, name, _ in inventory if kind == "apk"}:
        raise ValueError("critical OS component inventory missing")
    for match in grype["matches"]:
        row = match["artifact"]
        if row["type"] in {"apk", "python"} and package(row["type"], row["name"], row["version"]) not in inventory:
            raise ValueError("Grype finding absent from independently inventoried packages")
    return {"schema": 1, "image_config_digest": identity["config_digest"],
            "image_manifest_digest": identity["manifest_digest"],
            "grype_db_checksum": checksum[0], "grype_db_built": status["built"],
            "trivy_db_sha256": db["database_sha256"], "trivy_db_updated": metadata["UpdatedAt"],
            "apk_packages": sum(row[0] == "apk" for row in inventory),
            "python_packages": sum(row[0] == "python" for row in inventory),
            "inventory_match": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("grype", "trivy", "db", "spdx", "cdx", "identity", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    documents = [json.loads(getattr(args, name).read_bytes()) for name in ("grype", "trivy", "db", "spdx", "cdx", "identity")]
    report_hash = "sha256:" + hashlib.sha256(args.trivy.read_bytes()).hexdigest()
    result = verify(*documents, report_hash, datetime.now(timezone.utc))
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
