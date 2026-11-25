"""Verify that Buildx and Grype describe the same immutable local image.

The deployable manifest digest and config digest are distinct OCI identities.
This tool validates Grype's embedded manifest bytes, links them to the Buildx
config digest, and emits a small identity receipt consumed by VEX/SBOM policy.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPOSITORY = "milos-plavsic/enterprise-rag-system"


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def identity(build: dict, report: dict, expected_ref: str) -> dict:
    config = _digest(build.get("containerimage.config.digest"), "Buildx config digest")
    build_manifest = _digest(build.get("containerimage.digest"), "Buildx manifest digest")
    descriptor = build.get("containerimage.descriptor")
    if not isinstance(descriptor, dict) or _digest(descriptor.get("digest"), "Buildx descriptor digest") != build_manifest:
        raise ValueError("Buildx descriptor does not match its manifest digest")
    if descriptor.get("annotations", {}).get("config.digest") != config:
        raise ValueError("Buildx descriptor does not match its config digest")

    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("Grype source is not an image")
    target = source.get("target")
    if not isinstance(target, dict) or target.get("userInput") != expected_ref:
        raise ValueError("Grype scanned an unexpected image reference")
    grype_config = _digest(target.get("imageID"), "Grype config digest")
    manifest_digest = _digest(target.get("manifestDigest"), "Grype manifest digest")
    if grype_config != config:
        raise ValueError("Buildx and Grype config digests differ")

    encoded = target.get("manifest")
    if not isinstance(encoded, str):
        raise ValueError("Grype manifest bytes missing")
    try:
        manifest_bytes = base64.b64decode(encoded, validate=True)
        manifest = json.loads(manifest_bytes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Grype manifest payload") from exc
    actual_manifest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    if actual_manifest != manifest_digest:
        raise ValueError("Grype manifest digest does not match embedded manifest bytes")
    if manifest.get("config", {}).get("digest") != config:
        raise ValueError("Grype manifest does not reference the scanned config digest")

    scanner = report.get("descriptor")
    if not isinstance(scanner, dict) or scanner.get("name") != "grype" or not isinstance(scanner.get("version"), str):
        raise ValueError("Grype descriptor missing")
    timestamp = scanner.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("Grype timestamp missing")

    manifest_hex = manifest_digest.split(":", 1)[1]
    return {
        "schema": 1,
        "source_repository": f"https://github.com/{REPOSITORY}",
        "image_reference": expected_ref,
        "product_id": f"https://github.com/{REPOSITORY}/container-images/sha256/{manifest_hex}",
        "manifest_digest": manifest_digest,
        "config_digest": config,
        "buildx_manifest_digest": build_manifest,
        "buildx_media_type": descriptor.get("mediaType"),
        "scanner_media_type": target.get("mediaType"),
        "scanner": {"name": "grype", "version": scanner["version"], "timestamp": timestamp},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_metadata", type=Path)
    parser.add_argument("grype_report", type=Path)
    parser.add_argument("image_reference")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    receipt = identity(
        json.loads(args.build_metadata.read_bytes()),
        json.loads(args.grype_report.read_bytes()),
        args.image_reference,
    )
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
