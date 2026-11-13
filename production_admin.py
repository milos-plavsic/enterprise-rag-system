"""Operator-only offline commands. Never expose this CLI to API callers."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from production_store import ProductionStore, ROLES
from rag_service import MAX_UPLOAD_BYTES, extract_pages


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--database", type=Path, default=os.getenv("RAG_PRODUCTION_DB"))
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("inspect")
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
    elif args.command == "delete":
        if not db.delete(args.source):
            cli.error("document not found")
    elif args.command == "backup":
        db.backup(args.destination)


if __name__ == "__main__":
    main()
