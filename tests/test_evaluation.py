from __future__ import annotations
import json
from pathlib import Path
from eval_benchmark import run_benchmark
from rag_service import EnterpriseRAG, Identity

def test_benchmark_uses_explicit_expected_outcomes(environment):
    rag=EnterpriseRAG(environment)
    path=Path(__file__).resolve().parents[1]/"fixtures"/"evaluation.json"
    out=run_benchmark(rag,json.loads(path.read_text()))
    assert out["cases"]>=8
    assert out["accuracy"]==1.0
    assert out["failures"]==[]

def test_no_unverified_confidence(environment):
    rag=EnterpriseRAG(environment)
    result=rag.query("What is the security policy?",Identity("a","auditor"))
    assert result["confidence"] is None
    assert result["status"] in {"evidence_only","abstained"}


def test_benchmark_counts_failed_cases_not_failed_assertions():
    class StubRag:
        def query(self, question, identity):
            return {"status": "evidence_only", "answer": "none",
                    "evidence": [{"source": "forbidden"}]}

    case = {"id": "q", "role": "analyst", "question": "q", "expect": "computed",
            "must_contain": "$75,000", "forbid_source": "forbidden"}
    result = run_benchmark(StubRag(), {"cases": [case]})
    assert result["accuracy"] == result["passed"] == 0
    assert len(result["failures"]) == 1
    assert "evidence" in result["failures"][0]["reason"]
