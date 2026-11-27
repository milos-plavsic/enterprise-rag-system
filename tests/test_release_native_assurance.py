"""Adversarial fixtures for the exact-image native release binding."""
from __future__ import annotations

import copy

import pytest

from scripts.native_archive_inventory import digest
from scripts.verify_release_native_assurance import verify


def fixture():
    fs = {"usr/lib/libssl.so.3": ["file", "a" * 64, 420, 0, 0],
          "usr/local/lib/python3.12/startup.pth": ["file", "b" * 64, 420, 0, 0]}
    elf = {"usr/lib/libssl.so.3": {"sha256": "a" * 64, "needed": ["libcrypto.so.3"],
                                   "soname": "libssl.so.3"}}
    sources = {"usr/local/lib/python3.12/ssl.py": "c" * 64}
    base = {"schema": 1, "elf_count": len(elf),
            "elf_inventory_sha256": digest({k: v["sha256"] for k, v in elf.items()}),
            "python_source_count": len(sources), "python_inventory_sha256": digest(sources),
            "application_source_sha256": "sha256:" + "d" * 64,
            "direct_consumers": ["usr/lib/libssl.so.3"],
            "effective_filesystem_entries": len(fs),
            "effective_filesystem_sha256": digest(fs)}
    manifest = "sha256:" + "e" * 64
    native = {"schema": 1, "accepted": True, "baseline_sha256": digest(base),
              "image_manifest_digest": manifest, "archive_sha256": "sha256:" + "f" * 64,
              "observed": {**{k: base[k] for k in base if k != "schema"},
                           "transitive_consumers": ["usr/lib/libssl.so.3"]},
              "effective_filesystem": fs, "elf": elf, "python_sources": sources}
    identity = {"source_commit": "0" * 40, "manifest_digest": manifest,
                "archive_sha256": native["archive_sha256"], "config_digest": "sha256:" + "1" * 64,
                "source_tree_sha256": base["application_source_sha256"]}
    decisions = {"schema": 1, "image_manifest_digest": manifest, "image_config_digest": identity["config_digest"],
                 "resolved": [{"scanner": "grype"}], "unresolved": []}
    vex = {"statements": [{"status": "not_affected", "products": [
        {"hashes": {"sha-256": "e" * 64}}]}]}
    return native, base, identity, decisions, vex


def test_complete_exact_release_binding():
    args = fixture()
    receipt = verify(*args)
    assert receipt["accepted"] is True
    assert receipt["effective_filesystem_entries"] == 2
    assert receipt["resolved_count"] == 1


@pytest.mark.parametrize("mutation", [
    "false_acceptance", "tampered_baseline", "stale_image", "different_archive",
    "modified_pth", "modified_native_binary", "modified_source", "changed_consumer",
    "different_application", "stale_decisions", "unresolved", "bad_vex", "missing_inventory",
])
def test_tampering_fails_closed(mutation):
    native, base, identity, decisions, vex = copy.deepcopy(fixture())
    if mutation == "false_acceptance":
        native["accepted"] = False
    elif mutation == "tampered_baseline":
        base["effective_filesystem_entries"] = 9
    elif mutation == "stale_image":
        native["image_manifest_digest"] = "sha256:" + "9" * 64
    elif mutation == "different_archive":
        native["archive_sha256"] = "sha256:" + "9" * 64
    elif mutation == "modified_pth":
        native["effective_filesystem"]["usr/local/lib/python3.12/startup.pth"][1] = "9" * 64
    elif mutation == "modified_native_binary":
        native["elf"]["usr/lib/libssl.so.3"]["sha256"] = "9" * 64
    elif mutation == "modified_source":
        native["python_sources"]["usr/local/lib/python3.12/ssl.py"] = "9" * 64
    elif mutation == "changed_consumer":
        native["elf"]["usr/lib/libssl.so.3"]["needed"] = []
    elif mutation == "different_application":
        identity["source_tree_sha256"] = "sha256:" + "9" * 64
    elif mutation == "stale_decisions":
        decisions["image_config_digest"] = "sha256:" + "9" * 64
    elif mutation == "unresolved":
        decisions["unresolved"] = [{"id": "CVE-test"}]
    elif mutation == "bad_vex":
        vex["statements"][0]["products"][0]["hashes"]["sha-256"] = "9" * 64
    else:
        native.pop("effective_filesystem")
    with pytest.raises(ValueError, match="native release assurance"):
        verify(native, base, identity, decisions, vex)
