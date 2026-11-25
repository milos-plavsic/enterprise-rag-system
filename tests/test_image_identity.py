import base64
import hashlib
import io
import json
import tarfile

import pytest

from scripts.image_identity import archive_identity, identity

REF = "rag-candidate:test"
CONFIG_BYTES = json.dumps(
    {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}},
    separators=(",", ":"),
).encode()
CONFIG = "sha256:" + hashlib.sha256(CONFIG_BYTES).hexdigest()
BUILD_MANIFEST = "sha256:" + "b" * 64


def build():
    return {
        "containerimage.config.digest": CONFIG,
        "containerimage.digest": BUILD_MANIFEST,
        "containerimage.descriptor": {
            "digest": BUILD_MANIFEST,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "annotations": {"config.digest": CONFIG},
        },
    }


def report():
    raw = json.dumps(
        {"schemaVersion": 2, "config": {"digest": CONFIG}, "layers": []},
        separators=(",", ":"),
    ).encode()
    manifest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return {
        "source": {
            "type": "image",
            "target": {
                "userInput": REF,
                "imageID": CONFIG,
                "manifestDigest": manifest,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "manifest": base64.b64encode(raw).decode(),
            },
        },
        "descriptor": {
            "name": "grype",
            "version": "0.110.0",
            "timestamp": "2026-11-25T10:00:00Z",
        },
    }


def write_member(archive, name, payload):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


def docker_archive(tmp_path, *, ref=REF, config_bytes=CONFIG_BYTES):
    path = tmp_path / "image.tar"
    config_hex = hashlib.sha256(config_bytes).hexdigest()
    config_name = config_hex + ".json"
    manifest = json.dumps(
        [{"Config": config_name, "RepoTags": [ref], "Layers": []}],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as archive:
        write_member(archive, "manifest.json", manifest)
        write_member(archive, config_name, config_bytes)
    return path


def test_archive_hashes_config_bytes_and_selects_exact_tag(tmp_path):
    path = docker_archive(tmp_path)
    receipt = archive_identity(path, REF)
    assert receipt["config_digest"] == CONFIG
    assert receipt["config_member"] == CONFIG.split(":", 1)[1] + ".json"
    assert receipt["archive_sha256"].startswith("sha256:")


def test_links_archive_config_to_validated_scanner_manifest(tmp_path):
    archive = archive_identity(docker_archive(tmp_path), REF)
    receipt = identity(build(), report(), REF, archive)
    assert receipt["config_digest"] == CONFIG
    assert receipt["buildx_config_digest"] == CONFIG
    assert receipt["buildx_manifest_digest"] == BUILD_MANIFEST
    assert receipt["manifest_digest"] == report()["source"]["target"]["manifestDigest"]
    assert receipt["product_id"].endswith(receipt["manifest_digest"].split(":", 1)[1])
    assert receipt["archive_sha256"] == archive["archive_sha256"]


@pytest.mark.parametrize("case", ["config", "manifest_bytes", "reference", "descriptor"])
def test_identity_mismatch_fails_closed(tmp_path, case):
    metadata, scan = build(), report()
    archive = archive_identity(docker_archive(tmp_path), REF)
    if case == "config":
        metadata["containerimage.config.digest"] = "sha256:" + "c" * 64
        metadata["containerimage.descriptor"]["annotations"]["config.digest"] = metadata[
            "containerimage.config.digest"
        ]
    elif case == "manifest_bytes":
        scan["source"]["target"]["manifest"] = base64.b64encode(b"{}").decode()
    elif case == "reference":
        scan["source"]["target"]["userInput"] = "other:image"
    else:
        scan["descriptor"]["name"] = "not-grype"
    with pytest.raises(ValueError):
        identity(metadata, scan, REF, archive)


def test_missing_buildx_digest_fields_are_allowed_when_archive_and_grype_agree(tmp_path):
    archive = archive_identity(docker_archive(tmp_path), REF)
    receipt = identity({}, report(), REF, archive)
    assert receipt["config_digest"] == CONFIG
    assert receipt["buildx_config_digest"] is None
    assert receipt["buildx_manifest_digest"] is None


def test_archive_tag_mismatch_rejected(tmp_path):
    path = docker_archive(tmp_path, ref="other:image")
    with pytest.raises(ValueError, match="expected image"):
        archive_identity(path, REF)


def test_archive_config_filename_and_bytes_must_agree(tmp_path):
    path = tmp_path / "image.tar"
    wrong_name = "d" * 64 + ".json"
    manifest = json.dumps(
        [{"Config": wrong_name, "RepoTags": [REF], "Layers": []}],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as archive:
        write_member(archive, "manifest.json", manifest)
        write_member(archive, wrong_name, CONFIG_BYTES)
    with pytest.raises(ValueError, match="filename and bytes disagree"):
        archive_identity(path, REF)


def test_unsafe_archive_member_rejected(tmp_path):
    path = tmp_path / "image.tar"
    manifest = json.dumps(
        [{"Config": "../config.json", "RepoTags": [REF], "Layers": []}],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as archive:
        write_member(archive, "manifest.json", manifest)
        write_member(archive, "config.json", CONFIG_BYTES)
    with pytest.raises(ValueError, match="unsafe"):
        archive_identity(path, REF)
