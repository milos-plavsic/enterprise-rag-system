"""Offline catalog recovery with an independently obtained current authority record."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from document_source import sync
from production_runtime import deployment_lock
from production_store import ProductionStore, ROLES, validate_subject
from rag_service import MAX_DOCUMENTS

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-f]{32}")
_SIDECARS = ("-wal", "-shm", "-journal")


def require_quarantine(db: sqlite3.Connection) -> None:
    if (db.execute("SELECT 1 FROM principals LIMIT 1").fetchone() or
            not db.execute("SELECT 1 FROM policy_history WHERE event='restore_quarantine' LIMIT 1").fetchone()):
        raise RuntimeError("stage must be quarantined with no active grants")


def _authority(path: Path, expected: str) -> dict:
    if not _DIGEST.fullmatch(expected):
        raise ValueError("supply the approved recovery record's SHA-256")
    with path.open("rb") as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("approved recovery record digest mismatch")
    record = json.loads(raw)
    if not isinstance(record, dict) or set(record) != {"source_manifest_sha256", "source_history", "unmanaged"}:
        raise ValueError("invalid recovery record")
    manifest, unmanaged = record["source_manifest_sha256"], record["unmanaged"]
    if (manifest is not None and (not isinstance(manifest, str) or not _DIGEST.fullmatch(manifest))
            or not isinstance(unmanaged, list) or len(unmanaged) > MAX_DOCUMENTS):
        raise ValueError("invalid recovery record entries")
    history = record["source_history"]
    if (not isinstance(history, dict) or (manifest is None and history) or any(
        not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", key) or type(version) is not int or not 1 <= version < 2**63
        for key, version in history.items()
    )):
        raise ValueError("invalid authoritative source history")
    seen = set()
    for item in unmanaged:
        if not isinstance(item, dict) or set(item) != {"id", "sha256", "owner", "roles"}:
            raise ValueError("invalid unmanaged document entry")
        source, digest, owner, roles = (item[k] for k in ("id", "sha256", "owner", "roles"))
        if (not isinstance(source, str) or not _ID.fullmatch(source) or source in seen
                or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
                or not isinstance(roles, list) or any(not isinstance(role, str) or role not in ROLES for role in roles)
                or len(roles) != len(set(roles)) or (owner is not None and roles)):
            raise ValueError("invalid unmanaged document identity or access rules")
        if owner is not None:
            validate_subject(owner)
        seen.add(source)
    return record


def _reconcile_unmanaged(store: ProductionStore, entries: list[dict], *, managed: bool) -> None:
    with store.connect(write=True) as db:
        existing = {source: (digest, owner) for source, digest, owner in db.execute(
            "SELECT id,digest,owner FROM documents WHERE source_key IS NULL")}
        for item in entries:
            source = item["id"]
            if existing.pop(source, None) != (item["sha256"], item["owner"]):
                raise RuntimeError("approved unmanaged document is missing or differs from backup")
            db.execute("DELETE FROM document_roles WHERE document_id=?", (source,))
            db.executemany("INSERT INTO document_roles VALUES (?,?)", [(source, role) for role in item["roles"]])
        db.executemany("DELETE FROM documents WHERE id=?", [(source,) for source in existing])
        if not managed:
            db.execute("DELETE FROM documents WHERE source_key IS NOT NULL")
        require_quarantine(db)


def _require_failed_catalog(active: ProductionStore) -> None:
    if not active.path.exists():
        return
    # Include the live WAL in the health decision. Never treat transient I/O or locks as corruption.
    try:
        with closing(sqlite3.connect(f"{active.path.as_uri()}?mode=ro", uri=True, timeout=2)) as db:
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                return
    except sqlite3.DatabaseError as exc:
        if (getattr(exc, "sqlite_errorcode", 0) & 255) in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
            return
        raise
    raise RuntimeError("active catalog is readable; use activate-restore")


def recover(active: ProductionStore, snapshot_path: Path, authority_path: Path, authority_sha256: str,
            *, source: Path | None = None, parser_socket: str | None = None) -> Path:
    """Recover using an approved current inventory while preserving original recovery inputs."""
    snapshot = ProductionStore(snapshot_path)
    if snapshot.path == active.path:
        raise ValueError("recovery snapshot cannot be the active catalog")
    with deployment_lock(active.path):
        _require_failed_catalog(active)
        record = _authority(authority_path, authority_sha256)
        manifest = record["source_manifest_sha256"]
        if (manifest is None) != (source is None):
            raise ValueError("a managed source directory is required exactly when approved by the recovery record")
        with snapshot.connect() as db:
            require_quarantine(db)
        # Work on a copy. A rejected or interrupted reconciliation cannot change the supplied snapshot.
        with tempfile.TemporaryDirectory(prefix=".recovery-stage-", dir=active.path.parent) as directory:
            stage = ProductionStore(Path(directory) / "catalog.sqlite3")
            snapshot.backup(stage.path)
            _reconcile_unmanaged(stage, record["unmanaged"], managed=manifest is not None)
            if manifest is not None:
                sync(stage, source, parser_socket=parser_socket, recovery_manifest_sha256=manifest)
            with stage.connect(write=True) as db:
                require_quarantine(db)
                if manifest is not None:
                    history = record["source_history"]
                    recovered = dict(db.execute("SELECT source_key,version FROM source_history"))
                    current = dict(db.execute("SELECT source_key,version FROM documents WHERE source_key IS NOT NULL"))
                    if (any(history.get(key, 0) < version for key, version in recovered.items())
                            or any(history.get(key) != version for key, version in current.items())):
                        raise RuntimeError("authoritative version history disagrees with the reconciled catalog")
                    db.executemany("INSERT INTO source_history VALUES (?,?) ON CONFLICT(source_key) "
                                   "DO UPDATE SET version=excluded.version", history.items())
                if (db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                        or db.execute("PRAGMA foreign_key_check").fetchone()):
                    raise RuntimeError("reconciled catalog integrity check failed")
            with closing(sqlite3.connect(stage.path)) as db:
                if db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                    raise RuntimeError("unable to enable WAL for recovered database")
            if any(stage.path.with_name(stage.path.name + suffix).exists() for suffix in _SIDECARS):
                raise RuntimeError("staged catalog still has journals")
            damaged = Path(tempfile.mkdtemp(prefix=".failed-catalog-", dir=active.path.parent))
            for suffix in (*_SIDECARS, ""):
                path = active.path.with_name(active.path.name + suffix)
                if os.path.lexists(path):
                    os.replace(path, damaged / path.name)
            ProductionStore(damaged / active.path.name)._sync_directory()
            active._sync_directory()
            os.replace(stage.path, active.path)
            active._sync_directory()
            return damaged
