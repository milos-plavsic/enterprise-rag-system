"""Verify Buildx, a Docker archive and Grype describe one immutable image.

The Docker archive is the portable artifact boundary. Its config bytes are
hashed directly; Grype's embedded manifest bytes are hashed independently and
must reference that exact config digest. Buildx metadata is cross-checked when
the exporter exposes digest fields, but is never assumed to do so.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = "milos-plavsic/enterprise-rag-system"
MAX_MANIFEST_BYTES = 1_048_576
MAX_CONFIG_BYTES = 16_777_216


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _optional_digest(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _digest(value, field)


def _read_member(archive: tarfile.TarFile, name: str, maximum: int) -> bytes:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe Docker archive member path")
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise ValueError(f"Docker archive member missing: {name}") from exc
    if not member.isfile() or member.size < 1 or member.size > maximum:
        raise ValueError(f"invalid Docker archive member: {name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"cannot read Docker archive member: {name}")
    data = stream.read(maximum + 1)
    if len(data) != member.size or len(data) > maximum:
        raise ValueError(f"invalid Docker archive member size: {name}")
    return data


def archive_identity(path: Path, expected_ref: str) -> dict:
    archive_hash = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            archive_hash.update(block)

    try:
        archive = tarfile.open(path, mode="r:")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("invalid Docker image archive") from exc
    with archive:
        manifest_raw = _read_member(archive, "manifest.json", MAX_MANIFEST_BYTES)
        try:
            entries = json.loads(manifest_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid Docker archive manifest") from exc
        if not isinstance(entries, list):
            raise ValueError("invalid Docker archive manifest")
        matches = [
            entry for entry in entries
            if isinstance(entry, dict)
            and expected_ref in (entry.get("RepoTags") or [])
        ]
        if len(matches) != 1:
            raise ValueError("Docker archive does not contain exactly the expected image")
        config_name = matches[0].get("Config")
        if not isinstance(config_name, str):
            raise ValueError("Docker archive config missing")
        config_raw = _read_member(archive, config_name, MAX_CONFIG_BYTES)

    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    basename = PurePosixPath(config_name).name
    if basename.endswith(".json"):
        basename = basename[:-5]
    if HEX.fullmatch(basename) and config_digest != "sha256:" + basename:
        raise ValueError("Docker archive config filename and bytes disagree")
    try:
        config = json.loads(config_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid Docker image config JSON") from exc
    if not isinstance(config, dict) or "rootfs" not in config:
        raise ValueError("Docker image config incomplete")

    return {
        "archive_sha256": "sha256:" + archive_hash.hexdigest(),
        "config_digest": config_digest,
        "config_member": config_name,
    }


def identity(build: dict, report: dict, expected_ref: str, archive_receipt: dict) -> dict:
    config = _digest(archive_receipt.get("config_digest"), "archive config digest")
    archive_sha256 = _digest(archive_receipt.get("archive_sha256"), "archive digest")

    build_config = _optional_digest(
        build.get("containerimage.config.digest"), "Buildx config digest")
    if build_config is not None and build_config != config:
        raise ValueError("Buildx and archive config digests differ")

    build_manifest = _optional_digest(
        build.get("containerimage.digest"), "Buildx manifest digest")
    descriptor = build.get("containerimage.descriptor")
    if descriptor is not None:
        if not isinstance(descriptor, dict):
            raise ValueError("invalid Buildx descriptor")
        descriptor_digest = _optional_digest(
            descriptor.get("digest"), "Buildx descriptor digest")
        if (descriptor_digest is not None and build_manifest is not None
                and descriptor_digest != build_manifest):
            raise ValueError("Buildx descriptor and manifest digests differ")
        annotations = descriptor.get("annotations")
        if annotations is not None and not isinstance(annotations, dict):
            raise ValueError("invalid Buildx descriptor annotations")
        annotated_config = (annotations or {}).get("config.digest")
        if annotated_config is not None and _digest(
                annotated_config, "Buildx annotated config digest") != config:
            raise ValueError("Buildx descriptor and archive config digests differ")

    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("Grype source is not an image")
    target = source.get("target")
    if not isinstance(target, dict) or target.get("userInput") != expected_ref:
        raise ValueError("Grype scanned an unexpected image reference")
    grype_config = _digest(target.get("imageID"), "Grype config digest")
    manifest_digest = _digest(target.get("manifestDigest"), "Grype manifest digest")
    if grype_config != config:
        raise ValueError("Docker archive and Grype config digests differ")

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
        raise ValueError("Grype manifest does not reference the archive config digest")

    scanner = report.get("descriptor")
    if (not isinstance(scanner, dict) or scanner.get("name") != "grype"
            or not isinstance(scanner.get("version"), str)):
        raise ValueError("Grype descriptor missing")
    timestamp = scanner.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("Grype timestamp missing")

    manifest_hex = manifest_digest.split(":", 1)[1]
    return {
        "schema": 1,
        "source_repository": f"https://github.com/{REPOSITORY}",
        "image_reference": expected_ref,
        "product_id": (
            f"https://github.com/{REPOSITORY}/container-images/sha256/{manifest_hex}"
        ),
        "archive_sha256": archive_sha256,
        "manifest_digest": manifest_digest,
        "config_digest": config,
        "buildx_manifest_digest": build_manifest,
        "buildx_config_digest": build_config,
        "buildx_media_type": (
            descriptor.get("mediaType") if isinstance(descriptor, dict) else None
        ),
        "scanner_media_type": target.get("mediaType"),
        "scanner": {
            "name": "grype",
            "version": scanner["version"],
            "timestamp": timestamp,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_metadata", type=Path)
    parser.add_argument("grype_report", type=Path)
    parser.add_argument("image_reference")
    parser.add_argument("image_archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    archive_receipt = archive_identity(args.image_archive, args.image_reference)
    receipt = identity(
        json.loads(args.build_metadata.read_bytes()),
        json.loads(args.grype_report.read_bytes()),
        args.image_reference,
        archive_receipt,
    )
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
