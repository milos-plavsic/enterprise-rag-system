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
    return elf, source, identity, baseline


def test_transitive_consumers():
    elf, source, identity, baseline = fixture()
    assert consumer_paths(elf) == (["extension", "ssl"], ["extension", "indirect", "ssl"])
    assert verify_baseline(elf, source, identity, baseline)["elf_count"] == 3


@pytest.mark.parametrize("change", ["elf", "dependency", "application", "new_consumer"])
def test_drift_blocks(change):
    elf, source, identity, baseline = fixture()
    if change == "elf":
        elf["ssl"]["sha256"] = "changed"
    elif change == "dependency":
        source["a.py"] = "changed"
    elif change == "application":
        identity["source_tree_sha256"] = "changed"
    else:
        elf["new"] = {"sha256": "d", "needed": ["extension.so"], "soname": None}
    with pytest.raises(ValueError, match="baseline drift"):
        verify_baseline(elf, source, identity, baseline)


@pytest.mark.parametrize("path", ["../outside", "/etc/shadow", "a/../../b"])
def test_unsafe_paths(path):
    with pytest.raises(ValueError):
        safe_name(path)
