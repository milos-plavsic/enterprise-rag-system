"""Tamper tests for the portable OCI image boundary and its rootfs bytes."""

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from scripts.image_identity import archive_identity

TAG = "rag-candidate:review"
GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
PLAIN = "application/vnd.oci.image.layer.v1.tar"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def as_json(data):
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def tar_layer():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        content = b"verified archive payload\n"
        member = tarfile.TarInfo("app/proof.txt")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def member(archive, name, content):
    item = tarfile.TarInfo(name)
    item.size = len(content)
    archive.addfile(item, io.BytesIO(content))


def candidate(tmp_path, mutation=None, compression="gzip"):
    plain = tar_layer()
    compressed = gzip.compress(plain, mtime=0) if compression == "gzip" else plain
    layer_name = "blobs/sha256/" + digest(compressed).split(":")[1]
    layer_bytes = compressed
    if mutation == "modified_layer_blob":
        layer_bytes = compressed[:-1] + bytes([compressed[-1] ^ 0xFF])
    if mutation == "trailing_gzip":
        layer_bytes = compressed + b"untrusted-extra-bytes"
        layer_name = "blobs/sha256/" + digest(layer_bytes).split(":")[1]
    if mutation == "truncated_gzip":
        layer_bytes = compressed[:-3]
        layer_name = "blobs/sha256/" + digest(layer_bytes).split(":")[1]

    diff_id = digest(plain)
    if mutation == "incorrect_diff_id":
        diff_id = "sha256:" + "f" * 64
    config = as_json({
        "architecture": "arm64" if mutation == "wrong_config_arch" else "amd64",
        "os": "windows" if mutation == "wrong_config_os" else "linux",
        "rootfs": {"type": "layers", "diff_ids": [] if mutation == "missing_diff_id" else [diff_id]},
    })
    config_name = digest(config)[7:] + ".json"

    layer_descriptor = {
        "mediaType": PLAIN if compression == "plain" else GZIP,
        "digest": digest(layer_bytes) if mutation in {"trailing_gzip", "truncated_gzip"} else digest(compressed),
        "size": len(layer_bytes) + (1 if mutation == "incorrect_layer_size" else 0),
    }
    if mutation == "unsupported_compression":
        layer_descriptor["mediaType"] = "application/vnd.oci.image.layer.v1.tar+zstd"
    image_manifest = as_json({
        "schemaVersion": 1 if mutation == "wrong_manifest_schema" else 2,
        "mediaType": ("application/x-malformed" if mutation == "wrong_manifest_media_type"
                      else "application/vnd.oci.image.manifest.v1+json"),
        "config": {
            "mediaType": ("application/x-malformed" if mutation == "wrong_config_media_type"
                          else "application/vnd.oci.image.config.v1+json"),
            "digest": digest(config),
            "size": len(config) + (1 if mutation == "incorrect_config_size" else 0),
        },
        "layers": [layer_descriptor],
    })
    manifest_digest = digest(image_manifest)
    index = as_json({
        "schemaVersion": 2,
        "manifests": [
            {"digest": manifest_digest, "size": len(image_manifest),
             "mediaType": ("application/x-malformed" if mutation == "wrong_index_media_type"
                           else "application/vnd.oci.image.manifest.v1+json"),
             "platform": {"os": "windows" if mutation == "wrong_index_os" else "linux",
                          "architecture": "amd64"}}
        ] * (2 if mutation == "multiple_index_descriptors" else 1),
    })
    archive_layer_name = (
        "blobs/sha256/../../bad"
        if mutation == "unsafe_layer_name"
        else layer_name
    )
    archive_manifest = as_json([{
        "Config": config_name,
        "Layers": [archive_layer_name],
        "RepoTags": [TAG],
    }])
    path = tmp_path / "candidate.tar"
    with tarfile.open(path, "w") as tar:
        member(tar, "manifest.json", archive_manifest)
        member(tar, config_name, config)
        member(tar, "index.json", index)
        member(tar, "blobs/sha256/" + manifest_digest[7:],
               b"{}" if mutation == "modified_manifest_blob" else image_manifest)
        if mutation != "missing_layer_blob":
            member(tar, layer_name, layer_bytes)
        if mutation == "duplicate_archive_member":
            member(tar, "manifest.json", archive_manifest)
    return path, manifest_digest


@pytest.mark.parametrize("compression", ["gzip", "plain"])
def test_real_rootfs_content_is_bound_to_oci_manifest(tmp_path, compression):
    path, expected_manifest = candidate(tmp_path, compression=compression)
    receipt = archive_identity(path, TAG)
    assert receipt["manifest_digest"] == expected_manifest
    assert receipt["verified_layer_count"] == 1
    assert receipt["archive_sha256"] == digest(path.read_bytes())


@pytest.mark.parametrize("mutation", [
    "modified_layer_blob",
    "trailing_gzip",
    "truncated_gzip",
    "incorrect_diff_id",
    "missing_diff_id",
    "incorrect_layer_size",
    "incorrect_config_size",
    "unsupported_compression",
    "missing_layer_blob",
    "multiple_index_descriptors",
    "unsafe_layer_name",
    "modified_manifest_blob",
    "duplicate_archive_member",
    "wrong_config_arch",
    "wrong_config_os",
    "wrong_manifest_schema",
    "wrong_manifest_media_type",
    "wrong_config_media_type",
    "wrong_index_media_type",
    "wrong_index_os",
])
def test_every_image_content_or_identity_tamper_fails_closed(tmp_path, mutation):
    path, _ = candidate(tmp_path, mutation=mutation)
    with pytest.raises(ValueError):
        archive_identity(path, TAG)


def test_archive_rejects_missing_oci_index(tmp_path):
    path, _ = candidate(tmp_path)
    with tarfile.open(path, "r") as original:
        members = [(item.name, original.extractfile(item).read())
                   for item in original.getmembers() if item.isfile()
                   and item.name != "index.json"]
    with tarfile.open(path, "w") as rewritten:
        for name, content in members:
            member(rewritten, name, content)
    with pytest.raises(ValueError, match="index"):
        archive_identity(path, TAG)
