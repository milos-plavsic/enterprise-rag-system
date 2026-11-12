from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.api import app, backend, authenticator, rate_gate
from rag_service import EnterpriseRAG, Identity, TokenAuthenticator

ROOT = Path(__file__).resolve().parents[1]
TOKENS = {
    "A"*48: {"subject":"alice","role":"analyst"},
    "M"*48: {"subject":"bob","role":"manager"},
    "U"*48: {"subject":"charlie","role":"auditor"},
}

@pytest.fixture
def environment(tmp_path, monkeypatch):
    result = subprocess.run(
        [sys.executable, str(ROOT / "synthetic_data.py")],
        cwd=tmp_path, capture_output=True, text=True, check=True
    )
    assert "successfully" in result.stdout
    monkeypatch.setenv("RAG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("RAG_API_TOKENS_JSON", json.dumps(TOKENS))
    monkeypatch.delenv("RAG_EMBEDDING_MODEL", raising=False)
    monkeypatch.delenv("RAG_LLM_MODEL", raising=False)
    backend.cache_clear()
    authenticator.cache_clear()
    rate_gate.recent.clear()
    yield tmp_path / "data"
    backend.cache_clear()
    rate_gate.recent.clear()

@pytest.fixture
def client(environment):
    return TestClient(app)

def auth(role: str) -> dict[str,str]:
    index={"analyst":"A","manager":"M","auditor":"U"}[role]
    return {"Authorization":"Bearer "+index*48}
