"""Synthetic assertions for the version, citation and optional answer boundaries."""
from __future__ import annotations

import json
import sqlite3
import time

import pytest

from document_source import sync
from production_store import ProductionStore, SOURCES
from rag_service import Identity
from reference.corpus import write
from reference_answer import choose
from reference_benchmark import run


@pytest.fixture
def lab(tmp_path):
    db = ProductionStore(tmp_path / "lab.sqlite3")
    db.initialize()
    source = tmp_path / "source"
    write(source, 1)
    assert sync(db, source)["documents"] == 8
    db.set_principal("avery", "analyst")
    db.set_principal("robin", "auditor")
    iat = int(time.time()) + 2
    return db, source, Identity("avery", "analyst", iat), Identity("robin", "auditor", iat)


def test_version_lifecycle_and_live_citations(lab):
    db, source, avery, robin = lab
    first = db.query("reimbursement approval", avery)["evidence"][0]
    assert first["version"] == 1 and "250 credits" in first["text"]
    args = first["source"], first["page"], first["ordinal"]
    assert db.citation(avery, *args)["id"] == first["id"]
    assert db.citation(robin, *args) is None
    write(source, 2)
    sync(db, source)
    second = db.query("reimbursement approval", avery)["evidence"][0]
    assert second["version"] == 2 and "150 credits" in second["text"]
    assert db.citation(avery, *args) is None and db.revalidate(avery, [first]) == []
    assert db.citation(avery, second["source"], 1, 1)["id"] == second["id"]
    assert db.set_document_roles(second["source"], ("auditor",)) is False
    write(source, 3)
    sync(db, source)
    assert db.citation(avery, second["source"], 1, 1) is None
    db.set_principal("avery", None)
    with pytest.raises(PermissionError):
        db.citation(avery, *args)


def test_source_release_is_atomic_and_rejects_rollback(lab):
    db, source, avery, _ = lab
    write(source, 2)
    p = source / "manifest.json"
    manifest = json.loads(p.read_bytes())
    manifest["documents"][1]["version"] = 0
    p.unlink()
    p.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        sync(db, source)
    assert db.query("reimbursement approval", avery)["evidence"][0]["version"] == 1
    write(source, 2)
    sync(db, source)
    write(source, 1)
    with pytest.raises(ValueError, match="release must increase"):
        sync(db, source)
    write(source, 3)
    sync(db, source)
    manifest = json.loads(p.read_bytes())
    write(source, 1)
    stale = json.loads(p.read_bytes())["documents"][0]
    manifest["release"] = 4
    manifest["documents"].append(stale)
    p.unlink()
    p.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="higher version"):
        sync(db, source)


def test_acl_only_change_preserves_citation_identity_but_revokes_access(lab):
    db, source, avery, robin = lab
    first = db.query("reimbursement approval", avery)["evidence"][0]
    write(source, 2)
    p = source / "manifest.json"
    manifest = json.loads(p.read_bytes())
    manifest["documents"][0].update(file="travel-expenses-v1.txt", version=1,
                                    effective_at="2026-01-01T00:00:00Z", sha256=first["sha256"], roles=["auditor"])
    p.unlink()
    p.write_text(json.dumps(manifest))
    sync(db, source)
    assert db.citation(avery, first["source"], 1, 1) is None
    assert db.citation(robin, first["source"], 1, 1)["id"] == first["id"]


def test_migrates_previous_schema_preserving_existing_grants_and_documents(tmp_path):
    path = tmp_path / "old.sqlite3"
    previous = SOURCES.replace(",\n    source_key TEXT UNIQUE, version INTEGER, effective_at INTEGER", "")
    previous = "\n".join(line for line in previous.splitlines() if "CREATE TABLE source_" not in line)
    with sqlite3.connect(path) as db:
        db.executescript(previous + "\nPRAGMA user_version=1;")
        db.execute("INSERT INTO principals VALUES ('avery','analyst',1)")
        db.execute("INSERT INTO documents VALUES ('old',NULL,'hash',1,1,'Old title')")
        db.execute("INSERT INTO document_roles VALUES ('old','analyst')")
        db.execute("INSERT INTO chunks VALUES ('old',1,1,'Juniper source passage')")
    store = ProductionStore(path)
    with pytest.raises(RuntimeError, match="schema"):
        store.readiness()
    store.migrate()
    store.migrate()
    store.readiness()
    assert store.query("Juniper", Identity("avery", "analyst", 2))["evidence"][0]["title"] == "Old title"


def test_local_selector_only_emits_literal_authorised_quotes(lab):
    db, _, avery, _ = lab
    evidence = db.query("expense approval", avery)["evidence"]
    chosen = choose("Which expense requires approval?", evidence, lambda _query, choices: [0] if choices else [])
    assert len(chosen) == 1
    row, quote = chosen[0]
    assert quote in row["text"] and "250 credits" in quote
    assert "credentials" not in quote
    assert choose("Who manages Neptune?", evidence, lambda *_: [0]) == []
    assert choose("expense approval", evidence, lambda *_: []) == []


def test_reference_comparison_has_no_observed_permission_leaks():
    report = run(concurrency=2, requests=8)
    assert set(report["modes"]) == {"lexical", "concept", "semantic"}
    assert all(row["all"]["leaks"] == 0 for row in report["modes"].values())
    assert report["modes"]["lexical"]["all"]["abstained"] == report["modes"]["lexical"]["all"]["unanswerable"]
    assert report["modes"]["concept"]["all"]["hits"] >= report["modes"]["lexical"]["all"]["hits"]


def test_restore_refuses_a_stale_source_release(lab, tmp_path):
    from production_admin import activate_restore

    db, source, avery, _ = lab
    snapshot = tmp_path / "stale.sqlite3"
    db.backup(snapshot)
    write(source, 3)
    sync(db, source)
    staged = ProductionStore(snapshot)
    staged.clear_principals_for_restore()
    with pytest.raises(RuntimeError, match="current source release"):
        activate_restore(db, snapshot)
    sync(staged, source)
    activate_restore(db, snapshot)
    with pytest.raises(PermissionError):
        db.query("reimbursement approval", avery)
