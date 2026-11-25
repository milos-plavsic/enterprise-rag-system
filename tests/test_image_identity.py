import base64
import hashlib
import json

import pytest

from scripts.image_identity import identity

CONFIG = "sha256:" + "a" * 64
BUILD_MANIFEST = "sha256:" + "b" * 64
REF = "rag-candidate:test"


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
        "descriptor": {"name": "grype", "version": "0.110.0", "timestamp": "2026-11-25T10:00:00Z"},
    }


def test_links_build_config_to_validated_scanner_manifest():
    receipt = identity(build(), report(), REF)
    assert receipt["config_digest"] == CONFIG
    assert receipt["buildx_manifest_digest"] == BUILD_MANIFEST
    assert receipt["manifest_digest"] == report()["source"]["target"]["manifestDigest"]
    assert receipt["product_id"].endswith(receipt["manifest_digest"].split(":", 1)[1])


@pytest.mark.parametrize("case", ["config", "manifest_bytes", "reference", "descriptor"])
def test_identity_mismatch_fails_closed(case):
    b, g = build(), report()
    if case == "config":
        b["containerimage.config.digest"] = "sha256:" + "c" * 64
        b["containerimage.descriptor"]["annotations"]["config.digest"] = b["containerimage.config.digest"]
    elif case == "manifest_bytes":
        g["source"]["target"]["manifest"] = base64.b64encode(b"{}").decode()
    elif case == "reference":
        g["source"]["target"]["userInput"] = "other:image"
    else:
        g["descriptor"]["name"] = "not-grype"
    with pytest.raises(ValueError):
        identity(b, g, REF)
