"""Production-profile contracts with local, synthetic material only."""
from __future__ import annotations

import errno
import io
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from reportlab.pdfgen.canvas import Canvas

from app import api
from auth_oidc import OIDCAuthenticator
from pdf_transport import parser_ready
from production_runtime import deployment_lock
from production_store import ProductionStore
from rag_service import Identity, extract_pages

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://id.example.test/issuer"
AUDIENCE = "rag-api"


class LocalKeys:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return self

    def get_signing_keys(self):
        return [self]


@pytest.fixture
def parser(tmp_path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
            pass
    except PermissionError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES) or os.getenv("CI"):
            raise
        pytest.skip("workspace does not allow AF_UNIX sockets; mandatory in CI")
    path = str(tmp_path / "parser.sock")
    with subprocess.Popen([sys.executable, str(ROOT / "pdf_daemon.py"), path]) as daemon:
        try:
            deadline = time.monotonic() + 5
            while not Path(path).exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            parser_ready(path)
            yield path
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)


@pytest.fixture
def production(tmp_path, monkeypatch):
    path = tmp_path / "production.sqlite3"
    db = ProductionStore(path)
    db.initialize()
    for subject, role in [("alice", "manager"), ("bob", "manager"), ("cora", "analyst")]:
        db.set_principal(subject, role)
    keyfile = tmp_path / "audit-key"
    keyfile.write_bytes(os.urandom(32).hex().encode())
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = LocalKeys(private.public_key())
    for name in ("RAG_API_TOKENS_JSON", "RAG_DATA_DIR", "RAG_EMBEDDING_MODEL", "RAG_LLM_MODEL",
                 "RAG_LLM_ENDPOINT", "RAG_ALLOW_REMOTE_LLM", "RAG_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {"RAG_PROFILE": "production", "RAG_PRODUCTION_DB": str(path),
                        "RAG_PARSER_SOCKET": str(tmp_path / "parser.sock"), "RAG_AUDIT_KEY_FILE": str(keyfile)}.items():
        monkeypatch.setenv(name, value)
    auth = OIDCAuthenticator(ISSUER + "/jwks", ISSUER, AUDIENCE, jwks_client=provider, production=True)
    monkeypatch.setattr(api, "authenticator", lambda: auth)
    monkeypatch.setattr(api, "parser_ready", lambda _path: None)
    api.rate_gate.recent.clear()

    def headers(subject="alice", role="manager", *, token_type="at+jwt", duration=180, issued_at=None):
        iat = int(time.time()) + 2 if issued_at is None else issued_at
        signed = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": subject,
                             "enterprise_role": role, "iat": iat, "exp": iat + duration},
                            private, algorithm="RS256", headers={"typ": token_type, "kid": "local"})
        return {"Authorization": f"Bearer {signed}"}

    with TestClient(api.app) as client:
        yield client, db, headers, provider


def ask(client, headers, term):
    return client.post("/v1/query", headers=headers, json={"query": term})


def test_production_owner_acl_and_delete(production):
    client, db, headers, _ = production
    assert client.get("/ready").status_code == 200
    assert ask(client, headers("unknown"), "Quartz").status_code == 403
    assert ask(client, headers(token_type="JWT"), "Quartz").status_code == 401
    assert ask(client, headers(duration=301), "Quartz").status_code == 401
    assert ask(client, headers("alice", "analyst"), "Quartz").status_code == 403
    doc = client.post("/v1/documents/upload", headers=headers(),
                      files={"file": ("sample.txt", b"Quartz publication schedule")})
    assert doc.status_code == 201, doc.text
    source = doc.json()["source_id"]
    db.publish("Security timetable", ("analyst",), b"Cedar", ["Cedar timetable"])
    assert ask(client, headers(), "Quartz").json()["citations"][0]["source"] == source
    assert ask(client, headers("bob"), "Quartz").json()["status"] == "abstained"
    assert ask(client, headers("cora", "analyst"), "Cedar").json()["status"] == "evidence_only"
    assert ask(client, headers(), "Cedar").json()["status"] == "abstained"
    assert client.delete(f"/v1/documents/{source}", headers=headers("bob")).status_code == 404
    assert client.delete(f"/v1/documents/{source}", headers=headers()).status_code == 204
    assert ask(client, headers(), "Quartz").json()["status"] == "abstained"


def test_revocation_survives_regrant_and_is_checked_on_next_request(production, monkeypatch):
    client, db, headers, _ = production
    iat = int(time.time()) + 2
    old = headers(issued_at=iat)
    assert ask(client, old, "Quartz").status_code == 200
    db.set_principal("alice", None)
    assert ask(client, old, "Quartz").status_code == 403
    with monkeypatch.context() as patch:
        patch.setattr("production_store.time.time", lambda: iat)
        db.set_principal("alice", "manager")
    assert ask(client, old, "Quartz").status_code == 403
    assert ask(client, headers(issued_at=iat + 1), "Quartz").status_code == 200


def test_snapshot_restores_content_and_permissions(production, tmp_path):
    _, db, _, _ = production
    alice = Identity("alice", "manager", int(time.time()) + 2)
    bob = Identity("bob", "manager", alice.issued_at)
    data = b"Atlas procedure"
    source = db.upload(alice, data, [data.decode()])["source_id"]
    snapshot = tmp_path / "restore.sqlite3"
    db.backup(snapshot)
    with pytest.raises(FileExistsError):
        db.backup(snapshot)
    db.delete(source, alice)
    restored = ProductionStore(snapshot)
    restored.readiness()
    assert restored.query("Atlas", alice)["citations"][0]["source"] == source
    assert restored.query("Atlas", bob)["status"] == "abstained"
    assert db.query("Atlas", alice)["status"] == "abstained"


def test_readiness_and_database_lock(production, monkeypatch):
    client, db, _, provider = production
    with pytest.raises(RuntimeError, match="one API process"), deployment_lock(db.path):
        pass
    def unavailable():
        raise OSError("private provider detail")
    monkeypatch.setattr(provider, "get_signing_keys", unavailable)
    assert client.get("/ready").json() == {"detail": "service is not ready"}
    assert client.get("/ready").status_code == 503
    assert client.get("/health").status_code == 200


def test_bounded_requests_and_redacted_audit(production, caplog):
    client, _, headers, _ = production
    oversized = client.post("/v1/query", content=b"x" * 32769,
                            headers={"Content-Type": "application/json", **headers()})
    assert oversized.status_code == 413, oversized.text
    with caplog.at_level("INFO", logger="uvicorn.error"):
        response = ask(client, headers(), "Confidential subject matter")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] in caplog.text
    assert "rag_audit" in caplog.text
    assert "Confidential" not in caplog.text and "alice" not in caplog.text


def test_pdf_socket_round_trip_and_benign_rejection(parser):
    buffer = io.BytesIO()
    canvas = Canvas(buffer)
    canvas.drawString(40, 700, "Local PDF worker test")
    canvas.save()
    assert "Local PDF worker test" in extract_pages(buffer.getvalue(), ".pdf", parser_socket=parser)[0]
    with pytest.raises(ValueError, match="PDF parsing failed"):
        extract_pages(b"%PDF-1.7\nnot a PDF", ".pdf", parser_socket=parser)
    parser_ready(parser)


def test_offline_evaluation_blocks_leaks_and_missing_cohorts(production):
    from eval_production import evaluate

    _, db, _, _ = production
    doc = db.publish("Cedar", ("analyst",), b"Cedar", ["Cedar reference manual"])["source_id"]
    case = {"subject": "cora", "issued_at": int(time.time()) + 2, "role": "analyst", "category": "reference"}
    hit = {**case, "query": "Cedar", "relevant_sources": [doc], "allowed_sources": [doc]}
    miss = {**case, "query": "Aardvark", "relevant_sources": [], "allowed_sources": []}
    manifest = {"required_roles": ["analyst"], "required_categories": ["reference"],
                "thresholds": {"min_per_cohort": 1, "min_recall": 1.0, "min_abstention": 1.0},
                "cases": [hit, miss]}
    assert evaluate(db, manifest)["passed"]
    leaked = evaluate(db, {**manifest, "cases": [miss, {**hit, "relevant_sources": [], "allowed_sources": []}]})
    assert not leaked["passed"] and leaked["cohorts"][0]["leaks"] == 1
    assert not evaluate(db, {**manifest, "required_roles": ["analyst", "auditor"]})["passed"]
    assert db.set_document_roles(doc, ("auditor",))
    assert not evaluate(db, manifest)["passed"]


def test_restore_quarantine_never_reinstates_old_grants(production, tmp_path):
    _, db, _, _ = production
    identity = Identity("alice", "manager", int(time.time()) + 2)
    snapshot = tmp_path / "quarantine.sqlite3"
    db.backup(snapshot)
    restored = ProductionStore(snapshot)
    assert restored.entitled(identity)
    restored.clear_principals_for_restore()
    assert not restored.entitled(identity)


def test_parser_subprocess_regular_document_and_timeout(monkeypatch):
    from pdf_transport import isolated_parse

    buffer = io.BytesIO()
    canvas = Canvas(buffer)
    canvas.drawString(40, 700, "Worker text extraction")
    canvas.save()
    assert b"Worker text extraction" in isolated_parse(buffer.getvalue())
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    with monkeypatch.context() as patch:
        patch.setattr("pdf_transport.subprocess.run", timeout)
        assert isolated_parse(buffer.getvalue()) == b""
    assert b"Worker text extraction" in isolated_parse(buffer.getvalue())


def test_restore_activation_requires_quarantine_and_stopped_service(production, tmp_path):
    from production_admin import activate_restore

    _, db, _, _ = production
    snapshot = tmp_path / "activate.sqlite3"
    db.backup(snapshot)
    with pytest.raises(RuntimeError, match="one API process"):
        activate_restore(db, snapshot)
    separate = ProductionStore(tmp_path / "separate.sqlite3")
    separate.initialize()
    with pytest.raises(RuntimeError, match="quarantined"):
        activate_restore(separate, snapshot)
    ProductionStore(snapshot).clear_principals_for_restore()
    assert not separate.entitled(Identity("alice", "manager", int(time.time()) + 2))
    activate_restore(separate, snapshot)
    assert not snapshot.exists()
    separate.readiness()
    assert not separate.entitled(Identity("alice", "manager", int(time.time()) + 2))
