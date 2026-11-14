"""Durable document and entitlement store for one enterprise security domain."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from rag_service import (
    Chunk, DocumentIndex, Identity, InvalidDocument, MAX_CHUNKS, MAX_DOCUMENTS,
    MAX_EXTRACTED_CHARS, chunk_text,
)

from pdf_worker import MAX_PAGES
from identity_policy import GRANT_CUTOFF_SECONDS, PRODUCTION_JWT_LEEWAY_SECONDS

ROLES = frozenset({"analyst", "manager", "auditor"})
SCHEMA_VERSION = 3
SOURCES = """
CREATE TABLE principals (subject TEXT PRIMARY KEY, role TEXT NOT NULL
    CHECK(role IN ('analyst','manager','auditor')), min_iat INTEGER NOT NULL);
CREATE TABLE documents (id TEXT PRIMARY KEY, owner TEXT, digest TEXT NOT NULL,
    created INTEGER NOT NULL, page_count INTEGER NOT NULL, title TEXT,
    source_key TEXT UNIQUE, version INTEGER, effective_at INTEGER);
CREATE TABLE document_roles (document_id TEXT NOT NULL REFERENCES documents ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('analyst','manager','auditor')),
    PRIMARY KEY(document_id,role));
CREATE TABLE chunks (document_id TEXT NOT NULL REFERENCES documents ON DELETE CASCADE,
    page INTEGER NOT NULL, ordinal INTEGER NOT NULL, content TEXT NOT NULL,
    PRIMARY KEY(document_id,page,ordinal));
CREATE INDEX documents_owner ON documents(owner);
CREATE INDEX document_roles_role ON document_roles(role,document_id);
CREATE TABLE source_release (slot INTEGER PRIMARY KEY CHECK(slot=1), release INTEGER NOT NULL);
CREATE TABLE source_history (source_key TEXT PRIMARY KEY, version INTEGER NOT NULL);
CREATE TABLE policy_history (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL,
    subject TEXT, role TEXT, changed INTEGER NOT NULL, document_id TEXT);
"""


def validate_subject(subject: str) -> None:
    if not isinstance(subject, str) or not 1 <= len(subject) <= 255 or not subject.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in subject
    ):
        raise ValueError("invalid subject")


class ProductionStore:
    """SQLite on one local durable disk. API startup never creates or seeds it."""

    def __init__(self, path: Path):
        self.path = path.resolve()

    @contextmanager
    def connect(self, *, write: bool = False, verify: bool = True) -> Iterator[sqlite3.Connection]:
        mode = "rw" if write else "ro"
        db = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True, timeout=2)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            if write:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("PRAGMA secure_delete=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if verify and db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise RuntimeError("unsupported production database schema")
            yield db
            db.commit()
        finally:
            db.close()

    def initialize(self) -> None:
        # A private staging file and no-replace publication avoid serving a partial schema.
        stage = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.init")
        fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(stage)) as db:
                db.executescript(f"BEGIN IMMEDIATE;\n{SOURCES}\nPRAGMA user_version={SCHEMA_VERSION};\nCOMMIT;")
                db.execute("PRAGMA journal_mode=WAL").fetchone()
            os.link(stage, self.path)
            self._sync_directory()
        finally:
            stage.unlink(missing_ok=True)

    def migrate(self) -> None:
        """Explicit, transactional upgrade from the previous production candidate."""
        with self.connect(write=True, verify=False) as db:
            old = db.execute("PRAGMA user_version").fetchone()[0]
            if old == SCHEMA_VERSION:
                return
            if old not in {1, 2}:
                raise RuntimeError("unsupported production database migration")
            if old == 1:
                db.execute("ALTER TABLE documents ADD COLUMN source_key TEXT")
                db.execute("ALTER TABLE documents ADD COLUMN version INTEGER")
                db.execute("ALTER TABLE documents ADD COLUMN effective_at INTEGER")
                db.execute("CREATE UNIQUE INDEX documents_source_key ON documents(source_key)")
                db.execute("CREATE TABLE source_release (slot INTEGER PRIMARY KEY CHECK(slot=1), release INTEGER NOT NULL)")
                db.execute("CREATE TABLE source_history (source_key TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            # Existing grants used the old +1 cutoff. Preserve the grants but close that window.
            db.execute("UPDATE principals SET min_iat=min_iat+?", (PRODUCTION_JWT_LEEWAY_SECONDS,))
            db.execute("PRAGMA user_version=3")

    def _sync_directory(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def readiness(self) -> None:
        # Verify the schema and that the live volume accepts a write reservation.
        with self.connect(write=True) as db:
            for table in ("principals", "documents", "document_roles", "chunks", "policy_history", "source_release", "source_history"):
                if not db.execute(
                    "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", (table,)
                ).fetchone():
                    raise RuntimeError("production database schema incomplete")

    def set_principal(self, subject: str, role: str | None) -> None:
        validate_subject(subject)
        if role is not None and role not in ROLES:
            raise ValueError("invalid role")
        with self.connect(write=True) as db:
            now = int(time.time())
            previous = db.execute("SELECT MAX(changed) FROM policy_history WHERE subject=? AND event IN ('grant','revoke')",
                                  (subject,)).fetchone()[0]
            if previous is not None:
                now = max(now, previous)
            if role is None:
                db.execute("DELETE FROM principals WHERE subject=?", (subject,))
            else:
                # A token minted before the change cannot regain access on re-enrolment.
                db.execute("INSERT INTO principals VALUES (?,?,?) ON CONFLICT(subject) DO UPDATE "
                           "SET role=excluded.role, min_iat=excluded.min_iat", (subject, role, now + GRANT_CUTOFF_SECONDS))
            db.execute("INSERT INTO policy_history(event,subject,role,changed) VALUES (?,?,?,?)",
                       ("revoke" if role is None else "grant", subject, role, now))

    @staticmethod
    def _entitled(db: sqlite3.Connection, identity: Identity) -> bool:
        if identity.issued_at is None:
            return False
        return db.execute("SELECT 1 FROM principals WHERE subject=? AND role=? AND min_iat<=?",
                          (identity.subject, identity.role, identity.issued_at)).fetchone() is not None

    def entitled(self, identity: Identity) -> bool:
        with self.connect() as db:
            return self._entitled(db, identity)

    def _insert(self, payload: bytes, pages: list[str], *, identity: Identity | None = None,
                title: str | None = None, roles: tuple[str, ...] = ()) -> dict:
        if not 1 <= len(pages) <= MAX_PAGES or sum(map(len, pages)) > MAX_EXTRACTED_CHARS:
            raise InvalidDocument("document text exceeds limits")
        rows = [(i, j, text) for i, page in enumerate(pages, 1)
                for j, text in enumerate(chunk_text(page), 1)]
        if not rows:
            raise InvalidDocument("no indexable text in document")
        source = uuid.uuid4().hex
        with self.connect(write=True) as db:
            if identity is not None and (identity.role != "manager" or not self._entitled(db, identity)):
                raise PermissionError("upload not allowed")
            if (db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] >= MAX_DOCUMENTS or
                    db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] + len(rows) > MAX_CHUNKS):
                raise InvalidDocument("document or chunk quota reached")
            db.execute("INSERT INTO documents(id,owner,digest,created,page_count,title) VALUES (?,?,?,?,?,?)", (source,
                       identity.subject if identity else None, hashlib.sha256(payload).hexdigest(),
                       int(time.time()), len(pages), title))
            db.executemany("INSERT INTO chunks VALUES (?,?,?,?)", [(source, *row) for row in rows])
            db.executemany("INSERT INTO document_roles VALUES (?,?)", [(source, role) for role in roles])
            self._document_event(db, "upload" if identity else "publish", source,
                                 identity.subject if identity else None, ",".join(roles) or None)
        return {"source_id": source, "indexed": True, "page_count": len(pages)}

    def set_document_roles(self, source: str, roles: tuple[str, ...]) -> bool:
        if set(roles) - ROLES:
            raise ValueError("invalid document roles")
        with self.connect(write=True) as db:
            if not db.execute("SELECT 1 FROM documents WHERE id=? AND owner IS NULL AND source_key IS NULL", (source,)).fetchone():
                return False
            db.execute("DELETE FROM document_roles WHERE document_id=?", (source,))
            db.executemany("INSERT INTO document_roles VALUES (?,?)", [(source, role) for role in sorted(set(roles))])
            self._document_event(db, "document_roles", source, role=",".join(sorted(set(roles))))
            return True

    @staticmethod
    def _document_event(db: sqlite3.Connection, event: str, source: str,
                        subject: str | None = None, role: str | None = None) -> None:
        db.execute("INSERT INTO policy_history(event,subject,role,changed,document_id) VALUES (?,?,?,?,?)",
                   (event, subject, role, int(time.time()), source))

    def upload(self, identity: Identity, payload: bytes, pages: list[str]) -> dict:
        return self._insert(payload, pages, identity=identity)

    def publish(self, title: str, roles: tuple[str, ...], payload: bytes, pages: list[str]) -> dict:
        if not title.strip() or len(title) > 200 or not roles or set(roles) - ROLES:
            raise ValueError("a bounded title and explicit valid roles are required")
        return self._insert(payload, pages, title=title, roles=tuple(sorted(set(roles))))

    def delete(self, source: str, identity: Identity | None = None) -> bool:
        with self.connect(write=True) as db:
            if identity is None:
                count = db.execute("DELETE FROM documents WHERE id=? AND source_key IS NULL", (source,)).rowcount
            else:
                if identity.role != "manager" or not self._entitled(db, identity):
                    raise PermissionError("delete not allowed")
                count = db.execute("DELETE FROM documents WHERE id=? AND owner=?",
                                   (source, identity.subject)).rowcount
            if count:
                self._document_event(db, "delete", source, identity.subject if identity else None)
            return count == 1

    def clear_principals_for_restore(self) -> None:
        """A stale snapshot must not silently resurrect revoked grants."""
        with self.connect(write=True) as db:
            db.execute("DELETE FROM principals")
            db.execute("INSERT INTO policy_history(event,changed) VALUES (?,?)", ("restore_quarantine", int(time.time())))

    def _allowed_chunk(self, db: sqlite3.Connection, identity: Identity, source: str, page: int, ordinal: int):
        return db.execute("""SELECT c.content, d.title, d.version, d.effective_at, d.digest
            FROM chunks c JOIN documents d ON d.id=c.document_id WHERE d.id=? AND c.page=? AND c.ordinal=?
            AND ((d.owner=? AND ?='manager') OR EXISTS (SELECT 1 FROM document_roles r
            WHERE r.document_id=d.id AND r.role=?))""",
            (source, page, ordinal, identity.subject, identity.role, identity.role)).fetchone()

    def _citation(self, db: sqlite3.Connection, identity: Identity, source: str, page: int, ordinal: int) -> dict | None:
        row = self._allowed_chunk(db, identity, source, page, ordinal)
        if row is None:
            return None
        text, title, version, effective_at, digest = row
        chunk = Chunk(source, page, ordinal, text, (identity.role,))
        return {"id": chunk.id, "source": source, "page": page, "ordinal": ordinal,
                "title": title, "version": version, "effective_at": effective_at,
                "sha256": digest, "text": text,
                "href": f"/v1/documents/{source}/passages/{page}/{ordinal}"}

    def citation(self, identity: Identity, source: str, page: int, ordinal: int) -> dict | None:
        with self.connect() as db:
            if not self._entitled(db, identity):
                raise PermissionError("access denied")
            return self._citation(db, identity, source, page, ordinal)

    def revalidate(self, identity: Identity, evidence: list[dict]) -> list[dict]:
        with self.connect() as db:
            if not self._entitled(db, identity):
                raise PermissionError("access denied")
            return [row for row in evidence if (current := self._citation(
                db, identity, row["source"], row["page"], row["ordinal"])) and current["id"] == row["id"]]

    def query(self, question: str, identity: Identity, *, ranking: str = "lexical", reference: bool = False) -> dict:
        if ranking not in {"lexical", "concept", "semantic"}:
            raise ValueError("unsupported reference ranking")
        with self.connect() as db:
            if not self._entitled(db, identity):
                raise PermissionError("access denied")
            # Neither text nor statistics from inaccessible documents enter the ranker.
            rows = db.execute("""SELECT d.id, c.page, c.ordinal, c.content FROM chunks c
                JOIN documents d ON d.id=c.document_id WHERE (d.owner=? AND ?='manager') OR EXISTS
                (SELECT 1 FROM document_roles r WHERE r.document_id=d.id AND r.role=?)
                ORDER BY d.id,c.page,c.ordinal""", (identity.subject, identity.role, identity.role)).fetchall()
        documents = [Chunk(source, page, ordinal, text, (identity.role,))
                     for source, page, ordinal, text in rows]
        if reference:
            from reference_ranking import clean
            question = clean(question)
        if ranking == "concept":
            from reference_ranking import expand
            question = expand(question)
        embedder = None
        if ranking == "semantic" and documents:
            from reference_ranking import LatentSemantic
            embedder = LatentSemantic([doc.text for doc in documents])
        index = DocumentIndex(documents, embedder, dense_min_score=0.63)
        results = index.search(question, identity.role, {row[0] for row in rows},
                               distinct_sources=True, ranking="hybrid" if embedder else "lexical")
        positions = {chunk.id: chunk.number for chunk in documents}
        with self.connect() as db:
            if not self._entitled(db, identity):
                raise PermissionError("access denied")
            evidence = [dict(current, rank_score=row["rank_score"]) for row in results if
                        (current := self._citation(db, identity, row["source"], row["page"], positions[row["id"]]))
                        and current["id"] == row["id"]]
        return evidence_response(evidence)

    def backup(self, destination: Path) -> None:
        # Snapshot WAL transactions via SQLite, never by copying the live main file.
        destination = destination.absolute()
        stage = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.backup")
        fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with self.connect() as source, closing(sqlite3.connect(stage)) as snapshot:
                source.backup(snapshot, pages=256)
                snapshot.execute("PRAGMA journal_mode=DELETE").fetchone()
                if snapshot.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise RuntimeError("snapshot failed integrity check")
            with stage.open("rb") as stream:
                os.fsync(stream.fileno())
            os.link(stage, destination)
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            stage.unlink(missing_ok=True)

    def inspect(self) -> str:
        with self.connect() as db:
            return json.dumps({"schema": SCHEMA_VERSION,
                               "documents": db.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
                               "principals": db.execute("SELECT COUNT(*) FROM principals").fetchone()[0]})


def evidence_response(evidence: list[dict]) -> dict:
    return {"status": "evidence_only" if evidence else "abstained",
            "answer": "Authorised passages retrieved." if evidence else "Insufficient authorised evidence.",
            "citations": [{k: v for k, v in row.items() if k not in {"text", "rank_score"}} for row in evidence],
            "evidence": evidence, "confidence": None}
