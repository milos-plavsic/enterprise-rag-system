"""Atomic, versioned import of an operator-owned reference document directory."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from production_store import ProductionStore, ROLES
from rag_service import InvalidDocument, MAX_CHUNKS, MAX_DOCUMENTS, MAX_UPLOAD_BYTES, chunk_text, extract_pages

KEY = re.compile(r"[a-z][a-z0-9-]{0,62}")
MANIFEST_LIMIT = 131_072


def _bytes(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("source must be a regular file")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("source exceeds size limit")
    return payload


def _effective(text: str) -> int:
    date = datetime.fromisoformat(text)
    if date.tzinfo is None:
        raise ValueError("effective timestamp needs a timezone")
    return int(date.timestamp())


def _clock() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def sync(store: ProductionStore, root: Path, *, parser_socket: str | None = None,
         recovery_manifest_sha256: str | None = None) -> dict:
    """Publish one complete snapshot. Omissions withdraw managed documents only."""
    root = root.resolve(strict=True)
    raw = _bytes(root / "manifest.json", MANIFEST_LIMIT)
    if recovery_manifest_sha256 is not None and hashlib.sha256(raw).hexdigest() != recovery_manifest_sha256:
        raise ValueError("authoritative source manifest digest mismatch")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or set(manifest) != {"release", "documents"}:
        raise ValueError("invalid source manifest")
    release, entries = manifest["release"], manifest["documents"]
    if type(release) is not int or not 1 <= release < 2**63 or not isinstance(entries, list) or len(entries) > MAX_DOCUMENTS:
        raise ValueError("invalid release or document count")
    with store.connect() as db:
        previous = db.execute("SELECT release FROM source_release").fetchone()
        if previous and (release < previous[0] or release == previous[0] and recovery_manifest_sha256 is None):
            raise ValueError("source release must increase")
    prepared = {}
    total_chunks = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"key", "version", "title", "file", "roles", "effective_at", "sha256"}:
            raise ValueError("invalid document entry")
        key, version, title, name, roles = (entry[x] for x in ("key", "version", "title", "file", "roles"))
        if (not isinstance(key, str) or not KEY.fullmatch(key) or key in prepared or type(version) is not int
                or not 1 <= version < 2**63 or not isinstance(title, str) or not title.strip() or len(title) > 200
                or not isinstance(name, str) or Path(name).name != name or not isinstance(roles, list)
                or not roles or any(not isinstance(role, str) or role not in ROLES for role in roles)
                or len(set(roles)) != len(roles)):
            raise ValueError("invalid document metadata")
        effective_at = _effective(entry["effective_at"])
        if effective_at > _clock():
            raise ValueError("future effective versions must be published when effective")
        suffix = Path(name).suffix.casefold()
        if suffix not in {".txt", ".pdf"} or (suffix == ".pdf" and not parser_socket):
            raise ValueError("unsupported source format or missing isolated PDF worker")
        payload = _bytes(root / name, MAX_UPLOAD_BYTES)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError("document digest does not match the release manifest")
        pages = extract_pages(payload, suffix, parser_socket=parser_socket)
        rows = [(page, number, text) for page, content in enumerate(pages, 1)
                for number, text in enumerate(chunk_text(content), 1)]
        if not rows:
            raise InvalidDocument("source contains no indexable text")
        total_chunks += len(rows)
        if total_chunks > MAX_CHUNKS:
            raise InvalidDocument("source chunk quota exceeded")
        prepared[key] = (version, title, tuple(sorted(roles)), effective_at, digest, len(pages), rows)
    if _bytes(root / "manifest.json", MANIFEST_LIMIT) != raw:
        raise ValueError("manifest changed during import")
    return _apply(store, release, prepared, total_chunks, reconcile=recovery_manifest_sha256 is not None)


def _apply(store: ProductionStore, release: int, prepared: dict, total_chunks: int,
           *, reconcile: bool) -> dict:
    with store.connect(write=True) as db:
        previous = db.execute("SELECT release FROM source_release").fetchone()
        if previous and (release < previous[0] or release == previous[0] and not reconcile):
            raise ValueError("source release must increase")
        if (db.execute("SELECT COUNT(*) FROM documents WHERE source_key IS NULL").fetchone()[0] + len(prepared) > MAX_DOCUMENTS
                or db.execute("SELECT COUNT(*) FROM chunks JOIN documents ON id=document_id WHERE source_key IS NULL").fetchone()[0]
                + total_chunks > MAX_CHUNKS):
            raise InvalidDocument("combined corpus quota exceeded")
        active = {row[0]: row[1:] for row in db.execute(
            "SELECT source_key,id,version,title,effective_at,digest FROM documents WHERE source_key IS NOT NULL")}
        for key, (version, title, roles, effective_at, digest, page_count, rows) in prepared.items():
            latest = db.execute("SELECT version FROM source_history WHERE source_key=?", (key,)).fetchone()
            existing = active.get(key)
            if existing and existing[1:] == (version, title, effective_at, digest):
                source = existing[0]
                current_roles = tuple(row[0] for row in db.execute(
                    "SELECT role FROM document_roles WHERE document_id=? ORDER BY role", (source,)))
                if reconcile:
                    db.execute("DELETE FROM chunks WHERE document_id=?", (source,))
                    db.executemany("INSERT INTO chunks VALUES (?,?,?,?)", [(source, *row) for row in rows])
                    db.execute("UPDATE documents SET page_count=? WHERE id=?", (page_count, source))
                if current_roles != roles:
                    db.execute("DELETE FROM document_roles WHERE document_id=?", (source,))
                    _roles(db, source, roles)
                    store._document_event(db, "source_roles", source, role=",".join(roles))
                continue
            if latest and version <= latest[0]:
                raise ValueError("changed or reintroduced document requires a higher version")
            if existing:
                db.execute("DELETE FROM documents WHERE id=?", (existing[0],))
                store._document_event(db, "source_superseded", existing[0])
            source = uuid.uuid4().hex
            db.execute("""INSERT INTO documents(id, owner, digest, created, page_count, title, source_key, version, effective_at)
                        VALUES (?,NULL,?,?,?,?,?,?,?)""", (source, digest, _clock(), page_count, title, key, version, effective_at))
            db.executemany("INSERT INTO chunks VALUES (?,?,?,?)", [(source, *row) for row in rows])
            _roles(db, source, roles)
            db.execute("INSERT INTO source_history VALUES (?,?) ON CONFLICT(source_key) DO UPDATE SET version=excluded.version",
                       (key, version))
            store._document_event(db, "source_publish", source, role=",".join(roles))
        for key in active.keys() - prepared.keys():
            source = active[key][0]
            db.execute("DELETE FROM documents WHERE id=?", (source,))
            store._document_event(db, "source_withdraw", source)
        db.execute("INSERT INTO source_release VALUES (1,?) ON CONFLICT(slot) DO UPDATE SET release=excluded.release", (release,))
    return {"release": release, "documents": len(prepared), "chunks": total_chunks}


def _roles(db: sqlite3.Connection, source: str, roles: tuple[str, ...]) -> None:
    db.executemany("INSERT INTO document_roles VALUES (?,?)", [(source, role) for role in roles])
