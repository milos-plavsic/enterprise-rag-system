"""Verify the exact OCI manifest, compressed layers and rootfs diff IDs in Docker save."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import zlib

from pathlib import PurePosixPath

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_MANIFEST_BYTES = 1_048_576
MAX_LAYER_COUNT = 128
MAX_LAYER_BYTES = 1 << 30
MAX_EXPANDED_BYTES = 1 << 32
COMPRESSED = {
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}
UNCOMPRESSED = {
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.oci.image.layer.v1.tar",
}


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _read_member(archive: tarfile.TarFile, name: str, limit: int) -> bytes:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe OCI archive member")
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise ValueError(f"missing OCI archive member: {name}") from exc
    if not member.isfile() or not 0 < member.size <= limit:
        raise ValueError("invalid OCI archive member")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("unreadable OCI archive member")
    with stream:
        content = stream.read(limit + 1)
    if len(content) != member.size:
        raise ValueError("incomplete OCI archive member")
    return content


def verify_oci_archive(
    archive: tarfile.TarFile, entry: dict, config_raw: bytes
) -> tuple[str, int]:
    """Return the verified canonical OCI manifest digest and layer count.

    The scanner can synthesise a different manifest; never use that as the
    deployable image identity. All compressed blobs and uncompressed diff IDs
    are checked against the archive's own OCI manifest and image config.
    """
    index = json.loads(_read_member(archive, "index.json", MAX_MANIFEST_BYTES))
    descriptors = index.get("manifests")
    if (
        index.get("schemaVersion") != 2
        or not isinstance(descriptors, list)
        or len(descriptors) != 1
        or not isinstance(descriptors[0], dict)
    ):
        raise ValueError("OCI index must contain exactly one image descriptor")
    descriptor = descriptors[0]
    canonical_digest = _digest(descriptor.get("digest"), "OCI image manifest")
    manifest_raw = _read_member(
        archive, "blobs/sha256/" + canonical_digest.split(":", 1)[1],
        MAX_MANIFEST_BYTES,
    )
    if (
        descriptor.get("size") != len(manifest_raw)
        or "sha256:" + hashlib.sha256(manifest_raw).hexdigest() != canonical_digest
    ):
        raise ValueError("OCI index manifest descriptor does not match blob bytes")
    manifest = json.loads(manifest_raw)
    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    manifest_config = manifest.get("config")
    if (
        not isinstance(manifest_config, dict)
        or manifest_config.get("digest") != config_digest
        or manifest_config.get("size") != len(config_raw)
    ):
        raise ValueError("OCI image manifest does not reference archive config")
    config = json.loads(config_raw)
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
    layers = manifest.get("layers")
    archive_layers = entry.get("Layers")
    if (
        not isinstance(rootfs, dict)
        or rootfs.get("type") != "layers"
        or not isinstance(diff_ids, list)
        or not isinstance(layers, list)
        or not isinstance(archive_layers, list)
        or len(layers) != len(diff_ids)
        or len(layers) != len(archive_layers)
        or len(layers) > MAX_LAYER_COUNT
    ):
        raise ValueError("OCI image layer count does not match rootfs diff IDs")
    for idx, (layer, archive_name, diff_id) in enumerate(
        zip(layers, archive_layers, diff_ids)
    ):
        if not isinstance(layer, dict):
            raise ValueError("invalid OCI layer descriptor")
        layer_digest = _digest(layer.get("digest"), f"layer {idx} digest")
        path = "blobs/sha256/" + layer_digest.split(":", 1)[1]
        if archive_name != path or _digest(diff_id, "rootfs diff ID") != diff_id:
            raise ValueError("OCI layer and rootfs descriptor disagreement")
        media_type = layer.get("mediaType")
        if media_type not in COMPRESSED | UNCOMPRESSED:
            raise ValueError("unsupported OCI layer media type")
        try:
            member = archive.getmember(path)
        except KeyError as exc:
            raise ValueError("missing OCI image layer") from exc
        if (
            not member.isfile()
            or type(layer.get("size")) is not int
            or layer["size"] != member.size
            or not 0 < member.size <= MAX_LAYER_BYTES
        ):
            raise ValueError("OCI image layer size mismatch")
        content_hash = hashlib.sha256()
        expanded_hash = hashlib.sha256()
        expanded_size = 0
        decoder = (
            zlib.decompressobj(16 + zlib.MAX_WBITS)
            if media_type in COMPRESSED else None
        )
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("unreadable OCI image layer")
        with stream:
            while block := stream.read(1_048_576):
                content_hash.update(block)
                if decoder is None:
                    data = block
                else:
                    try:
                        data = decoder.decompress(
                            block, MAX_EXPANDED_BYTES - expanded_size + 1
                        )
                    except zlib.error as exc:
                        raise ValueError("invalid compressed OCI layer") from exc
                expanded_size += len(data)
                if expanded_size > MAX_EXPANDED_BYTES:
                    raise ValueError("expanded OCI layer exceeds safety limit")
                expanded_hash.update(data)
        if decoder is not None:
            try:
                trailer = decoder.flush()
            except zlib.error as exc:
                raise ValueError("invalid OCI layer gzip trailer") from exc
            expanded_size += len(trailer)
            if (
                expanded_size > MAX_EXPANDED_BYTES
                or not decoder.eof
                or decoder.unused_data
                or decoder.unconsumed_tail
            ):
                raise ValueError("incomplete or ambiguous OCI gzip member")
            expanded_hash.update(trailer)
        if "sha256:" + content_hash.hexdigest() != layer_digest:
            raise ValueError("OCI image compressed layer digest mismatch")
        if "sha256:" + expanded_hash.hexdigest() != diff_id:
            raise ValueError("OCI rootfs uncompressed diff ID mismatch")
    return canonical_digest, len(layers)
