import json
import math
from pathlib import Path
import pytest
from eval_retrieval import evaluate_retrieval
from rag_service import EnterpriseRAG

def test_authored_retrieval_golden_fixture(environment):
    path=Path(__file__).resolve().parents[1]/"fixtures"/"retrieval_gold.json"
    benchmark=json.loads(path.read_text())
    metrics=evaluate_retrieval(EnterpriseRAG(environment),benchmark)
    assert metrics["cases"]==8
    assert not metrics["permission_leaks"]
    assert metrics["correct_abstentions"]==metrics["abstention_cases"]
    assert metrics["recall_at_k"]==1.0


def test_source_metrics_use_the_same_cutoff_for_rank_and_denominator():
    class StubRag:
        def search_documents(self, query, role, k, *, distinct_sources, ranking):
            assert distinct_sources and ranking == "lexical" and k == 3
            return [{"source": source} for source in ("a", "b", "c")]

        def can_access_document(self, role, source):
            return source != "b"

    fixture = {"cases": [{"id": "q", "role": "analyst", "question": "test",
                          "expected_sources": ["a", "c", "d"]}]}
    result = evaluate_retrieval(StubRag(), fixture, k=3, ranking="lexical")
    assert result["precision_at_k"] == pytest.approx(2 / 3)
    assert result["recall_at_k"] == pytest.approx(2 / 3)
    assert result["mrr"] == 1
    assert result["ndcg_at_k"] == pytest.approx(1.5 / (1.5 + 1 / math.log2(3)))
    assert result["permission_leaks"] == [{"case": "q", "source": "b"}]


def test_authorised_upload_is_not_a_permission_leak(environment):
    rag = EnterpriseRAG(environment)
    source = rag.upload(b"UniqueCedarPolicy", ".txt", "manager")["source_id"]
    fixture = {"cases": [
        {"id": "allowed", "role": "manager", "question": "UniqueCedarPolicy",
         "expected_sources": [source]},
        {"id": "denied", "role": "analyst", "question": "UniqueCedarPolicy",
         "expected_sources": []},
    ]}
    result = evaluate_retrieval(rag, fixture, k=1)
    assert result["precision_at_k"] == result["recall_at_k"] == 1
    assert result["correct_abstentions"] == 1
    assert not result["permission_leaks"]
