"""Operator-only offline commands. Never expose this CLI to API callers."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from disaster_recovery import recover, require_quarantine
from production_runtime import deployment_lock
from production_store import ProductionStore, ROLES
from rag_service import MAX_UPLOAD_BYTES, extract_pages


def activate_restore(active: ProductionStore, staged_path: Path) -> None:
    """Offline replacement after a quarantined snapshot is reconciled."""
    staged = ProductionStore(staged_path)
    if staged.path == active.path or staged.path.parent != active.path.parent:
        raise ValueError("restore requires a different staged file on the same volume")
    with deployment_lock(active.path):
        with active.connect() as live:
            live_release = live.execute("SELECT release FROM source_release WHERE slot=1").fetchone()
            live_history = dict(live.execute("SELECT source_key,version FROM source_history"))
            live_managed = {key: (version, digest, title, effective) for key, version, digest, title, effective in
                            live.execute("SELECT source_key,version,digest,title,effective_at FROM documents WHERE source_key IS NOT NULL")}
        with staged.connect(write=True) as db:
            staged_release = db.execute("SELECT release FROM source_release WHERE slot=1").fetchone()
            if live_release and (not staged_release or staged_release[0] < live_release[0]):
                raise RuntimeError("reconcile the staged snapshot with the current source release before activation")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise RuntimeError("invalid staged snapshot")
            require_quarantine(db)
            for key, version, digest, title, effective in db.execute(
                "SELECT source_key,version,digest,title,effective_at FROM documents WHERE source_key IS NOT NULL"
            ):
                high = live_history.get(key, 0)
                if version < high or (version == high and live_managed.get(key) != (version, digest, title, effective)):
                    raise RuntimeError("staged catalog would revive a superseded or withdrawn source version")
            db.executemany("INSERT INTO source_history VALUES (?,?) ON CONFLICT(source_key) "
                           "DO UPDATE SET version=MAX(version,excluded.version)", live_history.items())
        # SQLite may leave sidecars after the last read-only connection closes.
        # Have SQLite checkpoint and remove them itself, never unlink a WAL manually.
        for path in (active.path, staged.path):
            with closing(sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True, timeout=2)) as db:
                if db.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                    raise RuntimeError("unable to close old WAL journal")
            if any(path.with_name(path.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
                raise RuntimeError("database still has an open journal")
        # Re-enable WAL on the staged inode before atomic activation.
        with closing(sqlite3.connect(staged.path)) as db:
            if db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                raise RuntimeError("unable to enable WAL for restored database")
        os.replace(staged.path, active.path)
        active._sync_directory()


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--database", type=Path, default=os.getenv("RAG_PRODUCTION_DB"))
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("inspect")
    commands.add_parser("migrate")
    sync = commands.add_parser("sync-source")
    sync.add_argument("directory", type=Path)
    grant = commands.add_parser("grant")
    grant.add_argument("subject")
    grant.add_argument("role", choices=sorted(ROLES))
    revoke = commands.add_parser("revoke")
    revoke.add_argument("subject")
    publish = commands.add_parser("publish")
    publish.add_argument("file", type=Path)
    publish.add_argument("--title", required=True)
    publish.add_argument("--role", choices=sorted(ROLES), action="append", required=True)
    acl = commands.add_parser("document-roles")
    acl.add_argument("source")
    acl.add_argument("--role", choices=sorted(ROLES), action="append", default=[])
    commands.add_parser("quarantine-restored-grants")
    restore = commands.add_parser("activate-restore")
    restore.add_argument("staged", type=Path)
    disaster = commands.add_parser("recover-catalog")
    disaster.add_argument("snapshot", type=Path)
    disaster.add_argument("--authority", type=Path, required=True)
    disaster.add_argument("--authority-sha256", required=True)
    disaster.add_argument("--source", type=Path)
    remove = commands.add_parser("delete")
    remove.add_argument("source")
    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    args = cli.parse_args()
    if args.database is None:
        cli.error("set --database or RAG_PRODUCTION_DB")
    db = ProductionStore(args.database)
    if args.command == "init":
        db.initialize()
    elif args.command == "migrate":
        with deployment_lock(db.path):
            db.migrate()
    elif args.command == "sync-source":
        from document_source import sync
        print(json.dumps(sync(db, args.directory, parser_socket=os.getenv("RAG_PARSER_SOCKET"))))
    elif args.command == "inspect":
        print(db.inspect())
    elif args.command == "grant":
        db.set_principal(args.subject, args.role)
    elif args.command == "revoke":
        db.set_principal(args.subject, None)
    elif args.command == "publish":
        parser = os.getenv("RAG_PARSER_SOCKET")
        if args.file.suffix.casefold() == ".pdf" and not parser:
            cli.error("publishing PDFs requires the isolated parser socket")
        with args.file.open("rb") as stream:
            payload = stream.read(MAX_UPLOAD_BYTES + 1)
        pages = extract_pages(payload, args.file.suffix.casefold(), parser_socket=parser)
        print(json.dumps(db.publish(args.title, tuple(args.role), payload, pages)))
    elif args.command == "document-roles":
        if not db.set_document_roles(args.source, tuple(args.role)):
            cli.error("published document not found")
    elif args.command == "quarantine-restored-grants":
        db.clear_principals_for_restore()
    elif args.command == "activate-restore":
        activate_restore(db, args.staged)
    elif args.command == "recover-catalog":
        preserved = recover(db, args.snapshot, args.authority, args.authority_sha256,
                            source=args.source, parser_socket=os.getenv("RAG_PARSER_SOCKET"))
        print(json.dumps({"preserved_failed_catalog": str(preserved)}))
    elif args.command == "delete":
        if not db.delete(args.source):
            cli.error("document not found")
    elif args.command == "backup":
        db.backup(args.destination)


if __name__ == "__main__":
    main()
