import json
from pathlib import Path
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
