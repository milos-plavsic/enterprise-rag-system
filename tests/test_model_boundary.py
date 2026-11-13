"""Model boundary tests run without network or hosted model credentials."""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
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


@pytest.mark.parametrize("payload", [[], None, "not an object"])
def test_non_object_model_json_is_rejected(monkeypatch, payload):
    monkeypatch.setenv("RAG_LLM_ENDPOINT", "http://127.0.0.1:8877/v1")
    monkeypatch.setenv("RAG_LLM_MODEL", "mock")
    monkeypatch.setattr(rag_service, "build_opener", lambda *args: FakeOpener(payload))
    with pytest.raises(rag_service.ModelResponseError, match="schema"):
        rag_service._model_answer("How much PTO?", starting_evidence())


def test_api_to_loopback_provider_uses_only_authorised_evidence(client, monkeypatch):
    from conftest import auth

    received = []

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.path)
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = json.loads(body["messages"][1]["content"])
            received.append(context)
            answer = {"answer": "Synthetic provider answer.",
                      "citations": [context["passages"][0]["id"]]}
            output = json.dumps({"choices": [{"message": {"content": json.dumps(answer)}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            monkeypatch.setenv("RAG_LLM_MODEL", "mock")
            monkeypatch.setenv("RAG_LLM_ENDPOINT", f"http://127.0.0.1:{server.server_port}/v1")
            response = client.post("/v1/query", headers=auth("analyst"),
                                   json={"query": "financial report revenue"})
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert response.status_code == 200
    assert response.json()["status"] == "generated_unverified"
    assert received[0] == "/v1/chat/completions"
    passages = received[1]["passages"]
    assert passages and all(p["id"].startswith("financial_report.pdf:") for p in passages)
