import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest

from app import api
from conftest import auth
from rag_service import Chunk, EnterpriseRAG


@pytest.mark.parametrize("question", [
    "What is EMEA revenue excluding Acme Corp?",
    "Total South America revenue",
    "Revenue in EMEA and South America",
    "Revenue in EMEA, South America",
    "Total sales except EMEA",
    "EMEA and APAC revenue",
    "Total EMEA sales YTD",
    "Net revenue in EMEA",
    "Total EMEA revenue over $20,000",
    "EMEA revenue by product",
])
def test_unsupported_sales_constraints_abstain(client, question):
    response = client.post("/v1/query", headers=auth("analyst"), json={"query": question})
    assert response.status_code == 200
    assert response.json()["status"] == "abstained"
    assert response.json()["citations"] == []


@pytest.mark.parametrize(("question", "scope", "amount"), [
    ("Show me total revenue from the EMEA region", "EMEA", "$75,000"),
    ("What is total sales in North America?", "NA", "$120,000"),
    ("Total sales for Asia Pacific", "APAC", "$30,000"),
    ("Give me total sales across all regions", None, "$225,000"),
])
def test_supported_sales_forms_keep_scope(client, question, scope, amount):
    response = client.post("/v1/query", headers=auth("analyst"), json={"query": question})
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "computed"
    assert body["citations"][0]["filter"] == scope
    assert amount in body["answer"]


def test_log_terms_in_policy_query_do_not_select_live_logs(client):
    response = client.post("/v1/query", headers=auth("manager"),
                           json={"query": "What does the security policy say about audit logs?"})
    assert response.status_code == 200
    sources = {item["source"] for item in response.json()["citations"]}
    assert "security_policy.pdf" in sources
    assert "logs.json" not in sources


@pytest.mark.parametrize(("question", "levels"), [
    ("Show recent errors", ["ERROR", "ERROR"]),
    ("Show recent warnings", ["WARN"]),
    ("Show recent warning logs", ["WARN"]),
    ("Recent error logs matching service timeout", ["ERROR"]),
    ("Recent error and warning logs", ["ERROR", "WARN", "ERROR"]),
])
def test_log_levels_and_recency(client, question, levels):
    response = client.post("/v1/query", headers=auth("auditor"), json={"query": question})
    assert response.status_code == 200
    body = response.json()
    assert body["citations"] == [{"source": "logs.json", "count": len(levels)}]
    assert [row["level"] for row in body["evidence"]] == levels
    timestamps = [row["timestamp"] for row in body["evidence"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_log_limit_keeps_latest_records_and_projects_fields(client, environment):
    rows = [
        {"timestamp": f"2025-04-01T10:{i:02d}:00Z", "level": "WARN",
         "msg": f"Log message {i}", "extra": "not part of the documented output"}
        for i in range(25)
    ]
    (environment / "logs.json").write_text(json.dumps(rows[::2] + rows[1::2]), encoding="utf-8")
    response = client.post("/v1/query", headers=auth("auditor"),
                           json={"query": "Show recent warnings"})
    assert response.status_code == 200
    body = response.json()
    assert body["citations"] == [{"source": "logs.json", "count": 25}]
    assert [row["msg"] for row in body["evidence"]] == [f"Log message {i}" for i in range(24, 4, -1)]
    assert all(set(row) == {"timestamp", "level", "msg"} for row in body["evidence"])


@pytest.mark.parametrize("question", ["List employees in Finance", "How many employees?",
                                     "Show employee salaries"])
def test_directory_does_not_drop_unsupported_constraints(client, question):
    response = client.post("/v1/query", headers=auth("manager"), json={"query": question})
    assert response.status_code == 200
    assert response.json()["status"] == "abstained"
    assert response.json()["evidence"] == []


def test_source_level_cutoff_is_applied_after_deduplication():
    class Embedder:
        def encode(self, texts):
            return [[1, 0.1] if text == "second source" else [1, 0] for text in texts]

    from rag_service import DocumentIndex
    chunks = [Chunk("first", 1, i, "first source", ("manager",)) for i in range(6)]
    chunks.append(Chunk("second", 1, 0, "second source", ("manager",)))
    index = DocumentIndex(chunks, Embedder())
    found = index.search("lookup", "manager", {"first", "second"}, k=2, ranking="dense",
                         distinct_sources=True)
    assert [row["source"] for row in found] == ["first", "second"]


def test_empty_lexical_corpus_abstains():
    from rag_service import DocumentIndex
    index = DocumentIndex([Chunk("diagram", 1, 1, "•••", ("manager",))])
    assert index.search("diagram", "manager", {"diagram"}) == []


@pytest.mark.parametrize("ranking", ["dense", "hybrid"])
def test_weak_dense_only_match_is_not_returned(ranking):
    from rag_service import DocumentIndex

    class Embedder:
        def encode(self, texts):
            return [[1, 0] if text == "handbook" else [0.28, 0.96] for text in texts]

    chunks = [Chunk("policy", 1, 1, "Access policy", ("auditor",))]
    conservative = DocumentIndex(chunks, Embedder())
    assert conservative.search("handbook", "auditor", {"policy"}, ranking=ranking) == []
    permissive = DocumentIndex(chunks, Embedder(), dense_min_score=0.20)
    assert permissive.search("handbook", "auditor", {"policy"}, ranking=ranking)


@pytest.mark.parametrize("floor", [float("nan"), float("inf"), -0.01, 1.01])
def test_invalid_dense_score_floor_is_rejected(floor):
    from rag_service import DocumentIndex
    with pytest.raises(ValueError, match="cosine floor"):
        DocumentIndex([], dense_min_score=floor)


def test_backend_is_initialised_once_on_concurrent_first_calls(environment, monkeypatch):
    start = Barrier(2)
    entered = Event()
    release = Event()
    result = object()
    calls = []

    def create(_):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return result

    def get_backend():
        start.wait(timeout=5)
        return api.backend()

    monkeypatch.setattr(api, "EnterpriseRAG", create)
    with ThreadPoolExecutor(max_workers=2) as workers:
        requests = [workers.submit(get_backend) for _ in range(2)]
        try:
            assert entered.wait(5)
        finally:
            release.set()
        assert all(request.result(timeout=5) is result for request in requests)
    assert calls == [1]


def test_demo_ui_is_served(client):
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Permission-Aware Enterprise Retrieval" in page.text


def test_upload_transport_limit_applies_before_indexing(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_MULTIPART_BYTES", 100)

    def unexpected():
        pytest.fail("upload was sent to indexing")

    monkeypatch.setattr(api, "backend", unexpected)
    response = client.post("/v1/documents/upload", headers=auth("manager"),
                           files={"file": ("ordinary.txt", b"Small demo document", "text/plain")})
    assert response.status_code == 413
