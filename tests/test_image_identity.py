import base64
import hashlib
import io
import json
import tarfile

import pytest

from scripts.image_identity import archive_identity, identity, verify_daemon_image

REF = "rag-candidate:test"
CONFIG_BYTES = json.dumps(
    {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}},
    separators=(",", ":"),
).encode()
CONFIG = "sha256:" + hashlib.sha256(CONFIG_BYTES).hexdigest()
OCI_MANIFEST_BYTES = json.dumps(
    {"schemaVersion": 2, "config": {"digest": CONFIG, "size": len(CONFIG_BYTES)}, "layers": []},
    separators=(",", ":"),
).encode()
BUILD_MANIFEST = "sha256:" + hashlib.sha256(OCI_MANIFEST_BYTES).hexdigest()


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
    index = json.dumps({
        "schemaVersion": 2,
        "manifests": [{"digest": BUILD_MANIFEST, "size": len(OCI_MANIFEST_BYTES)}],
    }, separators=(",", ":")).encode()
    with tarfile.open(path, "w") as archive:
        write_member(archive, "manifest.json", manifest)
        write_member(archive, config_name, config_bytes)
        write_member(archive, "index.json", index)
        write_member(archive, "blobs/sha256/" + BUILD_MANIFEST[7:], OCI_MANIFEST_BYTES)
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
    assert receipt["buildx_exporter_reported_digest"] == BUILD_MANIFEST
    assert receipt["buildx_exporter_digest_kind"] == "archived-manifest"
    assert receipt["manifest_digest"] == BUILD_MANIFEST
    assert receipt["scanner_manifest_digest"] == report()["source"]["target"]["manifestDigest"]
    assert receipt["scanner_manifest_digest"] != receipt["manifest_digest"]
    assert receipt["verified_layer_count"] == 0
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


def test_missing_buildx_exporter_identity_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="lacks any image digest"):
        identity({}, report(), REF, archive_identity(docker_archive(tmp_path), REF))


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

def test_buildx_load_reports_config_digest_not_manifest(tmp_path):
    metadata = build()
    metadata["containerimage.digest"] = CONFIG
    metadata.pop("containerimage.descriptor")
    archive = archive_identity(docker_archive(tmp_path), REF)
    receipt = identity(metadata, report(), REF, archive)
    assert receipt["buildx_exporter_digest_kind"] == "config"
    assert receipt["buildx_exporter_reported_digest"] == CONFIG
    assert receipt["manifest_digest"] == BUILD_MANIFEST
    del metadata["containerimage.config.digest"]
    assert identity(metadata, report(), REF, archive)["buildx_exporter_digest_kind"] == "config"


def test_unknown_buildx_exporter_digest_is_rejected(tmp_path):
    metadata = build()
    metadata["containerimage.digest"] = "sha256:" + "a" * 64
    metadata["containerimage.descriptor"]["digest"] = metadata["containerimage.digest"]
    with pytest.raises(ValueError, match="neither config nor archive manifest"):
        identity(metadata, report(), REF, archive_identity(docker_archive(tmp_path), REF))


def test_untrusted_buildx_media_type_fails(tmp_path):
    metadata = build()
    metadata["containerimage.descriptor"]["mediaType"] = "application/x-untrusted"
    with pytest.raises(ValueError, match="media type"):
        identity(metadata, report(), REF, archive_identity(docker_archive(tmp_path), REF))


@pytest.mark.parametrize("field", ["layers", "user", "architecture"])
def test_daemon_image_binding_rejects_drift(field):
    receipt = {"rootfs_diff_ids": ["sha256:" + "a" * 64],
               "runtime_config": {"User": "10001:10001"}}
    image = {"Id": "sha256:" + "d" * 64, "Os": "linux", "Architecture": "amd64",
             "RootFS": {"Layers": receipt["rootfs_diff_ids"][:]}, "Config": {"User": "10001:10001"}}
    assert verify_daemon_image([image], receipt) == image["Id"]
    if field == "layers":
        image["RootFS"]["Layers"] = ["sha256:" + "e" * 64]
    elif field == "user":
        image["Config"]["User"] = "0"
    else:
        image["Architecture"] = "arm64"
    with pytest.raises(ValueError):
        verify_daemon_image([image], receipt)

def test_manifest_descriptor_must_match_verified_archive_bytes(tmp_path):
    metadata = build()
    metadata["containerimage.digest"] = CONFIG
    metadata["containerimage.descriptor"]["digest"] = CONFIG
    with pytest.raises(ValueError, match="manifest descriptor"):
        identity(metadata, report(), REF, archive_identity(docker_archive(tmp_path), REF))
