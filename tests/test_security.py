from __future__ import annotations
import json
from pathlib import Path
import pytest
from rag_service import (
    Chunk, DocumentIndex, EnterpriseRAG, Identity, InvalidDocument,
    TokenAuthenticator, reciprocal_rank_fusion,
)
from conftest import auth, TOKENS

def test_health(client):
    assert client.get("/health").json() == {"status":"ok"}

def test_no_authentication(client):
    response = client.post("/v1/query", json={"query":"revenue EMEA"})
    assert response.status_code == 401

def test_unknown_bearer_cannot_assert_role(client):
    response = client.post("/v1/query",
        headers={"Authorization":"Bearer "+"F"*48},
        json={"query":"list employees","user_id":"bob"})
    assert response.status_code == 401

def test_role_not_selected_by_body(client):
    response = client.post("/v1/query", headers=auth("analyst"),
        json={"query":"employees","user_id":"bob"})
    assert response.status_code == 422

def test_sales_filter_is_correct(client):
    body=client.post("/v1/query", headers=auth("analyst"),
        json={"query":"What is total EMEA revenue?"}).json()
    assert body["status"]=="computed"
    assert "$75,000" in body["answer"]
    assert body["citations"][0]["filter"]=="EMEA"
    assert body["citations"][0]["rows"]==2

def test_all_regions_and_ambiguous_region(client):
    answer=client.post("/v1/query",headers=auth("analyst"),json={"query":"Total sales"}).json()
    assert "$225,000" in answer["answer"]
    ambiguous=client.post("/v1/query",headers=auth("analyst"),
        json={"query":"Compare sales EMEA and APAC"}).json()
    assert ambiguous["status"]=="abstained"

def test_employee_permission(client):
    denied=client.post("/v1/query",headers=auth("analyst"),json={"query":"List employees"})
    assert denied.status_code==403
    allowed=client.post("/v1/query",headers=auth("manager"),
        json={"query":"List employees"})
    assert allowed.status_code==200
    assert allowed.json()["status"]=="evidence_only"
    assert all(set(x)=={"name","department"} for x in allowed.json()["evidence"])

def test_auditor_role_and_source_isolation(client):
    denied=client.post("/v1/query",headers=auth("analyst"),
        json={"query":"recent error logs"})
    assert denied.status_code==403
    allowed=client.post("/v1/query",headers=auth("auditor"),
        json={"query":"recent error logs"}).json()
    assert allowed["citations"][0]["source"]=="logs.json"
    financial=client.post("/v1/query",headers=auth("auditor"),
        json={"query":"financial report revenue"}).json()
    assert all(x["source"]!="financial_report.pdf" for x in financial.get("citations",[]))

def test_real_pdf_content_used(environment):
    rag=EnterpriseRAG(environment)
    sources={x.source for x in rag._index.chunks}
    assert "financial_report.pdf" in sources
    assert any("Total Revenue:" in c.text for c in rag._index.chunks)

def test_permission_filter_keeps_original_vector_alignment():
    class FakeEmbedding:
        def encode(self, texts):
            def vec(t):
                low=t.casefold()
                if "security" in low or "breach" in low:
                    return [0,1,0]
                if "benefits" in low: return [0,0,1]
                return [1,0,0]
            return [vec(t) for t in texts]
    docs=[
        Chunk("finance",1,1,"revenue finance",("analyst",)),
        Chunk("security",1,1,"security breach",("auditor",)),
        Chunk("benefits",1,1,"benefits pension",("auditor",)),
    ]
    idx=DocumentIndex(docs,embedder=FakeEmbedding())
    got=idx.search("security breach","auditor",{"security","benefits"},k=2)
    assert got[0]["source"]=="security"
    assert all(r["source"]!="finance" for r in got)

def test_documents_have_stable_evidence_ids(environment):
    index=EnterpriseRAG(environment)._index
    for item in index.chunks:
        assert item.id.startswith(item.source+":p")
    docs=EnterpriseRAG(environment).search_documents("health insurance","manager")
    assert docs and docs[0]["source"]=="employee_handbook.pdf"

def test_upload_requires_manager(client):
    response=client.post("/v1/documents/upload",headers=auth("analyst"),
        files={"file":("notes.txt",b"Budget report example","text/plain")})
    assert response.status_code==403

def test_upload_path_cannot_escape_root(client,environment):
    response=client.post("/v1/documents/upload",headers=auth("manager"),
        files={"file":("../../../../tmp/attack.txt",b"UniquePolicyToken for approved managers","text/plain")})
    assert response.status_code==201
    body=response.json()
    assert body["source_id"].startswith("uploads/")
    assert ".." not in body["source_id"]
    assert (environment/body["source_id"]).exists()
    assert not (environment/"attack.txt").exists()
    q=client.post("/v1/query",headers=auth("manager"),
        json={"query":"UniquePolicyToken"}).json()
    assert any(row["source"]==body["source_id"] for row in q["evidence"])
    other=client.post("/v1/query",headers=auth("analyst"),
        json={"query":"UniquePolicyToken"}).json()
    assert all(row["source"]!=body["source_id"] for row in other["evidence"])

@pytest.mark.parametrize("filename,data",[
    ("bad.pdf",b"not a PDF"),
    ("bad.txt",b"\xff\xfe"),
    ("large.txt",b"x"*2_000_001),
])
def test_upload_rejects_invalid_documents(client,filename,data):
    response=client.post("/v1/documents/upload",headers=auth("manager"),
        files={"file":(filename,data,"application/octet-stream")})
    assert response.status_code==400

def test_absent_token_config_fails_closed(monkeypatch):
    monkeypatch.delenv("RAG_API_TOKENS_JSON",raising=False)
    with pytest.raises(RuntimeError):
        TokenAuthenticator()

def test_invalid_token_policy_fails_closed():
    with pytest.raises(RuntimeError):
        TokenAuthenticator('{"short":{"subject":"alice","role":"manager"}}')

def test_rrf_does_not_combine_incompatible_score_scales():
    scores=reciprocal_rank_fusion([[2,1],[1,2]])
    assert scores[1]==scores[2]

def test_no_source_leak_in_document_results(environment):
    rag=EnterpriseRAG(environment)
    for role in ["analyst","auditor","manager"]:
        rows=rag.search_documents("policy revenue handbook",role)
        for row in rows:
            assert row["source"] in rag.allowed(role)

def test_refused_request_does_not_claim_high_confidence(client):
    response=client.post("/v1/query",headers=auth("analyst"),
        json={"query":"employee names"})
    assert response.status_code==403

def test_long_query_validation(client):
    response=client.post("/v1/query",headers=auth("manager"),
        json={"query":"x"*2001})
    assert response.status_code==422
