"""Model boundary tests run without network or hosted model credentials."""
from __future__ import annotations
import json
import pytest
import rag_service

class FakeResponse:
    def __init__(self, content): self.content=content
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def read(self, amount): return self.content[:amount]

class FakeOpener:
    def __init__(self, output): self.output=output; self.input=None
    def open(self, request, timeout):
        self.input=json.loads(request.data)
        content=json.dumps({"choices":[{"message":{"content":json.dumps(self.output)}}]}).encode()
        return FakeResponse(content)

def starting_evidence():
    return {
        "status":"evidence_only","answer":"evidence",
        "citations":[{"id":"allowed:p1:c1:abc","source":"allowed","page":1}],
        "evidence":[{"id":"allowed:p1:c1:abc","source":"allowed","page":1,"text":"Policy allows 20 PTO days."}],
        "confidence":None,
    }

def test_valid_generated_answer_is_explicitly_unverified(monkeypatch):
    fake=FakeOpener({"answer":"Employees receive 20 PTO days.","citations":["allowed:p1:c1:abc"]})
    monkeypatch.setenv("RAG_LLM_ENDPOINT","http://127.0.0.1:8877/v1")
    monkeypatch.setenv("RAG_LLM_MODEL","mock")
    monkeypatch.setattr(rag_service,"build_opener",lambda *args:fake)
    out=rag_service._model_answer("How much PTO?",starting_evidence())
    assert out["status"]=="generated_unverified"
    assert "NOT verified" in out["limitations"]
    assert fake.input["messages"][1]["role"]=="user"
    serialized=fake.input["messages"][1]["content"]
    assert "Policy allows" in serialized
    assert "secret" not in serialized

def test_model_cannot_cite_unretrieved_document(monkeypatch):
    fake=FakeOpener({"answer":"Secret salary is 9000","citations":["secret:p1:c1:x"]})
    monkeypatch.setenv("RAG_LLM_ENDPOINT","http://127.0.0.1:8877/v1")
    monkeypatch.setenv("RAG_LLM_MODEL","mock")
    monkeypatch.setattr(rag_service,"build_opener",lambda *args:fake)
    with pytest.raises(ValueError,match="invalid model output"):
        rag_service._model_answer("What is salary?",starting_evidence())

def test_external_model_egress_requires_opt_in(monkeypatch):
    monkeypatch.setenv("RAG_LLM_ENDPOINT","https://provider.example/v1")
    monkeypatch.setenv("RAG_LLM_MODEL","mock")
    monkeypatch.delenv("RAG_ALLOW_REMOTE_LLM",raising=False)
    with pytest.raises(RuntimeError,match="explicit"):
        rag_service._model_answer("What is PTO?",starting_evidence())

def test_model_abstention_has_no_unverified_citation(monkeypatch):
    fake=FakeOpener({"answer":"","citations":[]})
    monkeypatch.setenv("RAG_LLM_ENDPOINT","http://127.0.0.1:8877/v1")
    monkeypatch.setenv("RAG_LLM_MODEL","mock")
    monkeypatch.setattr(rag_service,"build_opener",lambda *args:fake)
    out=rag_service._model_answer("Missing fact?",starting_evidence())
    assert out["status"]=="abstained"
    assert out["citations"]==[]
