import pytest
from scripts.native_archive_inventory import consumer_paths, digest, verify_baseline, safe_name


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
