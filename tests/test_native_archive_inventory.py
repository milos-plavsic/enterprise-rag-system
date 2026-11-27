import io
import json
import tarfile

import pytest
from scripts.native_archive_inventory import consumer_paths, digest, verify_baseline, safe_name, inventory


def fixture():
    elf = {"ssl": {"sha256": "a", "needed": ["libcrypto.so.3"], "soname": "libssl.so.3"},
           "extension": {"sha256": "b", "needed": ["libssl.so.3"], "soname": "extension.so"},
           "indirect": {"sha256": "c", "needed": ["extension.so"], "soname": None}}
    source = {"a.py": "x"}
    identity = {"source_tree_sha256": "y"}
    baseline = {"elf_count": 3, "elf_inventory_sha256": digest({"ssl": "a", "extension": "b", "indirect": "c"}),
                "python_source_count": 1, "python_inventory_sha256": digest(source),
                "application_source_sha256": "y", "direct_consumers": ["extension", "ssl"]}
    filesystem = {"a.py": ["file", "x", 420, 0, 0]}
    baseline["effective_filesystem_entries"] = 1
    baseline["effective_filesystem_sha256"] = digest(filesystem)
    return elf, source, identity, baseline, filesystem


def test_transitive_consumers():
    elf, source, identity, baseline, filesystem = fixture()
    assert consumer_paths(elf) == (["extension", "ssl"], ["extension", "indirect", "ssl"])
    assert verify_baseline(elf, source, identity, baseline, filesystem)["elf_count"] == 3


@pytest.mark.parametrize("change", ["elf", "dependency", "application", "new_consumer"])
def test_drift_blocks(change):
    elf, source, identity, baseline, filesystem = fixture()
    if change == "elf":
        elf["ssl"]["sha256"] = "changed"
    elif change == "dependency":
        source["a.py"] = "changed"
    elif change == "application":
        identity["source_tree_sha256"] = "changed"
    else:
        elf["new"] = {"sha256": "d", "needed": ["extension.so"], "soname": None}
    with pytest.raises(ValueError, match="baseline drift"):
        verify_baseline(elf, source, identity, baseline, filesystem)


@pytest.mark.parametrize("path", ["../outside", "/etc/shadow", "a/../../b"])
def test_unsafe_paths(path):
    with pytest.raises(ValueError):
        safe_name(path)

@pytest.mark.parametrize("path,entry", [
    ("python.pth", ["file", "exec startup", 420, 0, 0]),
    ("lib/libssl.so.3", ["symlink", "/tmp/untrusted.so", 511, 0, 0]),
    ("etc/ssl/openssl.cnf", ["file", "modified", 420, 0, 0]),
    ("usr/local/bin/uvicorn", ["file", "bootstrap", 493, 0, 0]),
])
def test_unreviewed_runtime_material_fails(path, entry):
    elf, source, identity, baseline, fs = fixture()
    fs[path] = entry
    with pytest.raises(ValueError, match="effective_filesystem"):
        verify_baseline(elf, source, identity, baseline, fs)


def test_permission_change_fails():
    elf, source, identity, baseline, fs = fixture()
    fs["a.py"][2] = 493
    with pytest.raises(ValueError, match="effective_filesystem"):
        verify_baseline(elf, source, identity, baseline, fs)

@pytest.mark.parametrize("name", [
    "usr/local/lib/python3.12/site-packages/pkg/__pycache__/module.pyc",
    "usr/local/lib/python3.12/site-packages/pkg/module.pyo",
])
def test_compiled_install_bytecode_fails_even_if_other_sources_match(name):
    elf, sources, identity, baseline, fs = fixture()
    fs[name] = ["file", "unreviewed native bytecode", 420, 0, 0]
    with pytest.raises(ValueError, match="bytecode"):
        verify_baseline(elf, sources, identity, baseline, fs)


def test_apk_log_is_rejected():
    elf, sources, identity, baseline, fs = fixture()
    fs["var/log/apk.log"] = ["file", "arbitrary install log", 420, 0, 0]
    with pytest.raises(ValueError, match="APK installation log"):
        verify_baseline(elf, sources, identity, baseline, fs)

def test_injected_site_package_cache_symlink_fails():
    elf, sources, identity, baseline, fs = fixture()
    fs["usr/local/lib/python3.12/site-packages/pkg/__pycache__"] = [
        "symlink", "/usr/lib/hidden", 511, 0, 0]
    with pytest.raises(ValueError, match="cache directories"):
        verify_baseline(elf, sources, identity, baseline, fs)

def make_test_archive(tmp_path, layer_members):
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode="w", format=tarfile.PAX_FORMAT) as layer:
        for item in layer_members:
            blob = b"safe"
            item.size = len(blob)
            layer.addfile(item, io.BytesIO(blob))
    layer_bytes = layer_stream.getvalue()
    outer_path = tmp_path / "image.tar"
    manifest = json.dumps([{"Layers": ["layer.tar"]}]).encode()
    with tarfile.open(outer_path, mode="w") as outer:
        for name, data in (("manifest.json", manifest), ("layer.tar", layer_bytes)):
            record = tarfile.TarInfo(name)
            record.size = len(data)
            outer.addfile(record, io.BytesIO(data))
    return outer_path


def test_extended_attributes_are_rejected(tmp_path):
    item = tarfile.TarInfo("usr/bin/tool")
    item.pax_headers = {"SCHILY.xattr.security.capability": "unexpected"}
    with pytest.raises(ValueError, match="extended attributes"):
        inventory(make_test_archive(tmp_path, [item]))


def test_duplicate_layer_paths_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="duplicate OCI layer"):
        inventory(make_test_archive(tmp_path, [
            tarfile.TarInfo("usr/bin/tool"), tarfile.TarInfo("usr/bin/tool")]))
