"""Compute the expected runtime source identity from the immutable Git tree."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import PurePosixPath

ROOT_SOURCES = frozenset({
    "identity_policy.py", "disaster_recovery.py", "document_source.py",
    "reference_ranking.py", "reference_answer.py", "auth_oidc.py", "pdf_worker.py",
    "pdf_transport.py", "pdf_daemon.py", "production_admin.py", "production_store.py",
    "production_runtime.py", "query_intent.py", "rag_service.py",
})
SOURCE_SUFFIXES = {".py", ".js", ".html"}
POLICY_PATH = "security/openssl-3.5.9-r1-dispositions.json"
COLLECTOR_PATH = "scripts/openssl_reachability.py"


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_policy_digest(policy: dict) -> str:
    return sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode())


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], timeout=30)


def source_receipt(image_ref: str) -> dict:
    commit = git("rev-parse", "HEAD").decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or image_ref != f"rag-candidate:{commit}":
        raise ValueError("candidate reference does not identify checked-out Git commit")
    files = set(ROOT_SOURCES)
    for entry in git("ls-tree", "-r", "-z", commit, "--", "app").split(b"\0"):
        if not entry:
            continue
        header, raw_name = entry.split(b"\t", 1)
        name = raw_name.decode("utf-8")
        path = PurePosixPath(name)
        if path.suffix.casefold() in SOURCE_SUFFIXES and "__pycache__" not in path.parts:
            if header.split(b" ")[0] not in {b"100644", b"100755"}:
                raise ValueError("runtime source must be a regular Git file")
            files.add(name)
    if not any(name.startswith("app/") for name in files):
        raise ValueError("application source inventory missing")
    digest = hashlib.sha256()
    for name in sorted(files, key=PurePosixPath):
        digest.update(name.encode() + b"\0" + git("show", f"{commit}:{name}") + b"\0")
    policy = json.loads(git("show", f"{commit}:{POLICY_PATH}"))
    return {
        "source_commit": commit,
        "source_tree_sha256": "sha256:" + digest.hexdigest(),
        "collector_sha256": sha256(git("show", f"{commit}:{COLLECTOR_PATH}")),
        "policy_sha256": canonical_policy_digest(policy),
    }
