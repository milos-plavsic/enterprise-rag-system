"""Ordinary offline recovery drills against fictional catalogs."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from disaster_recovery import recover
from document_source import sync
from production_runtime import deployment_lock
from production_store import ProductionStore
from reference.corpus import write


def authority(tmp_path, source=None, *, history=None, unmanaged=()):
    digest = hashlib.sha256((source / "manifest.json").read_bytes()).hexdigest() if source else None
    file = tmp_path / "approved.json"
    raw = json.dumps({"source_manifest_sha256": digest, "source_history": history or {},
                      "unmanaged": list(unmanaged)}).encode()
    file.write_bytes(raw)
    return file, hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("failure", ["missing", "corrupt"])
def test_recovers_failed_catalog_with_current_acl_withdrawals_and_tombstones(tmp_path, failure):
    live = ProductionStore(tmp_path / "live.sqlite3")
    live.initialize()
    source = tmp_path / "source"
    write(source, 1)
    sync(live, source)
    keep = live.publish("Keep", ("analyst",), b"Keep work", ["Keep work"])["source_id"]
    purge = live.publish("Remove", ("analyst",), b"Remove work", ["Remove work"])["source_id"]
    live.set_principal("avery", "analyst")
    snapshot = tmp_path / "backup.sqlite3"
    live.backup(snapshot)
    ProductionStore(snapshot).clear_principals_for_restore()
    original = snapshot.read_bytes()
    write(source, 3)
    approved, digest = authority(tmp_path, source, history={
        **{entry["key"]: entry["version"] for entry in json.loads((source / "manifest.json").read_bytes())["documents"]},
        "travel-expenses": 2,
    }, unmanaged=[{"id": keep, "sha256": hashlib.sha256(b"Keep work").hexdigest(), "owner": None,
                   "roles": ["auditor"]}])
    live.path.unlink()
    if failure == "corrupt":
        live.path.write_bytes(b"damaged test catalog")
    preserved = recover(live, snapshot, approved, digest, source=source)
    assert snapshot.read_bytes() == original
    assert preserved.is_dir()
    assert (preserved / live.path.name).exists() == (failure == "corrupt")
    if failure == "corrupt":
        assert (preserved / live.path.name).read_bytes() == b"damaged test catalog"
    live.readiness()
    with live.connect() as db:
        assert db.execute("SELECT release FROM source_release").fetchone() == (3,)
        assert db.execute("SELECT version FROM source_history WHERE source_key='travel-expenses'").fetchone() == (2,)
        assert db.execute("SELECT 1 FROM documents WHERE source_key='travel-expenses' OR id=?", (purge,)).fetchone() is None
        assert db.execute("SELECT role FROM document_roles WHERE document_id=?", (keep,)).fetchall() == [("auditor",)]
        assert not db.execute("SELECT 1 FROM principals").fetchone()
        assert db.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_recovery_fails_closed_and_preserves_the_snapshot(tmp_path):
    live = ProductionStore(tmp_path / "live.sqlite3")
    live.initialize()
    source = tmp_path / "source"
    write(source, 1)
    sync(live, source)
    snapshot = tmp_path / "backup.sqlite3"
    live.backup(snapshot)
    history = {item["key"]: item["version"] for item in json.loads((source / "manifest.json").read_bytes())["documents"]}
    history["withdrawn-after-snapshot"] = 4
    approved, digest = authority(tmp_path, history=history)
    with pytest.raises(RuntimeError, match="active catalog is readable"):
        recover(live, snapshot, approved, digest)
    live.path.unlink()
    with pytest.raises(RuntimeError, match="must be quarantined"):
        recover(live, snapshot, approved, digest)
    ProductionStore(snapshot).clear_principals_for_restore()
    with deployment_lock(live.path), pytest.raises(RuntimeError, match="one API process"):
        recover(live, snapshot, approved, digest)
    with pytest.raises(ValueError, match="record digest mismatch"):
        recover(live, snapshot, approved, "0" * 64)
    with pytest.raises(ValueError, match="directory is required"):
        recover(live, snapshot, approved, digest, source=source)
    assert not live.path.exists()
    assert snapshot.exists()
    recover(live, snapshot, approved, digest)
    with live.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM documents").fetchone() == (0,)
        assert dict(db.execute("SELECT source_key,version FROM source_history")) == history


def test_recovery_replays_equal_release_against_approved_source(tmp_path):
    live = ProductionStore(tmp_path / "live.sqlite3")
    live.initialize()
    source = tmp_path / "source"
    write(source, 1)
    sync(live, source)
    with live.connect(write=True) as db:
        db.execute("UPDATE chunks SET content='Unreconciled passage'")
    snapshot = tmp_path / "backup.sqlite3"
    live.backup(snapshot)
    ProductionStore(snapshot).clear_principals_for_restore()
    history = {item["key"]: item["version"] for item in json.loads((source / "manifest.json").read_bytes())["documents"]}
    approved, digest = authority(tmp_path, source, history=history)
    live.path.unlink()
    write(source, 2)
    with pytest.raises(ValueError, match="manifest digest mismatch"):
        recover(live, snapshot, approved, digest, source=source)
    assert not live.path.exists()
    write(source, 1)
    recover(live, snapshot, approved, digest, source=source)
    with live.connect() as db:
        assert not db.execute("SELECT 1 FROM chunks WHERE content='Unreconciled passage'").fetchone()
        assert db.execute("SELECT COUNT(*) FROM documents").fetchone() == (8,)


def test_migration_moves_legacy_grant_cutoff_once(tmp_path):
    from identity_policy import GRANT_CUTOFF_SECONDS
    from rag_service import Identity

    path = tmp_path / "legacy.sqlite3"
    store = ProductionStore(path)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=2")
        db.execute("INSERT INTO principals VALUES ('avery','analyst',101)")
    store.migrate()
    store.migrate()
    assert not store.entitled(Identity("avery", "analyst", 100 + GRANT_CUTOFF_SECONDS - 1))
    assert store.entitled(Identity("avery", "analyst", 100 + GRANT_CUTOFF_SECONDS))
