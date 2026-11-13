"""Explicit production settings, deployment lock and redacted audit events."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from production_store import ProductionStore

log = logging.getLogger("uvicorn.error")


def production_mode() -> bool:
    profile = os.getenv("RAG_PROFILE", "demo")
    if profile not in {"demo", "production"}:
        raise RuntimeError("invalid runtime profile")
    return profile == "production"


@dataclass(frozen=True)
class Settings:
    database: Path
    parser_socket: str
    audit_key: bytes

    @classmethod
    def load(cls) -> Settings:
        forbidden = ("RAG_API_TOKENS_JSON", "RAG_DATA_DIR", "RAG_EMBEDDING_MODEL", "RAG_LLM_MODEL",
                     "RAG_LLM_ENDPOINT", "RAG_ALLOW_REMOTE_LLM", "RAG_LLM_API_KEY")
        if any(os.getenv(key) for key in forbidden):
            raise RuntimeError("demo, embedding and generation settings are not supported in production")
        database = Path(os.environ["RAG_PRODUCTION_DB"])
        socket = Path(os.environ["RAG_PARSER_SOCKET"])
        if not database.is_absolute() or not socket.is_absolute():
            raise RuntimeError("database and socket paths must be absolute")
        audit_key = Path(os.environ["RAG_AUDIT_KEY_FILE"]).read_bytes().strip()
        if len(audit_key) < 32 or len(audit_key) > 256:
            raise RuntimeError("audit key must contain 32 to 256 bytes")
        return cls(database, str(socket), audit_key)


@contextmanager
def deployment_lock(database: Path) -> Iterator[None]:
    import fcntl

    path = database.resolve().with_suffix(database.suffix + ".lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("production supports exactly one API process per database") from exc
        yield
    finally:
        os.close(fd)


def store(settings: Settings) -> ProductionStore:
    return ProductionStore(settings.database)


def audit(settings: Settings, *, event: str, outcome: str, subject: str | None = None,
          request_id: str | None = None, sources: list[str] | None = None, elapsed_ms: int | None = None) -> None:
    record = {"schema": 1, "event": event, "outcome": outcome, "request_id": request_id, "elapsed_ms": elapsed_ms}
    if subject:
        record["actor"] = hmac.new(settings.audit_key, subject.encode(), hashlib.sha256).hexdigest()
    if sources is not None:
        record["sources"] = sources
    log.info("rag_audit %s", json.dumps(record, separators=(",", ":")))
