"""Labelled lexical/hybrid retrieval metrics on authored demo fixtures.

This is a regression benchmark, not an independently sampled relevance study.
"""
from __future__ import annotations
import json
import math
from pathlib import Path
from typing import Any
from rag_service import EnterpriseRAG

def evaluate_retrieval(rag: EnterpriseRAG, benchmark: dict[str, Any], k: int = 4) -> dict[str, Any]:
    cases=benchmark.get("cases")
    if not isinstance(cases,list) or not cases:
        raise ValueError("nonempty labelled retrieval cases required")
    ranks=[]
    recalls=[]
    precisions=[]
    ndcgs=[]
    abstention_checks=[]
    leaks=[]
    for case in cases:
        role=case["role"]
        expected=set(case["expected_sources"])
        results=rag.search_documents(case["question"],role)[:k]
        ranked=list(dict.fromkeys(row["source"] for row in results))
        for source in ranked:
            if source not in rag.allowed(role):
                leaks.append({"case":case["id"],"source":source})
        if not expected:
            abstention_checks.append(not ranked)
            continue
        relevant=[index for index,source in enumerate(ranked,start=1) if source in expected]
        recalls.append(len(relevant)/len(expected))
        precisions.append(len(relevant)/k)
        ranks.append(1/min(relevant) if relevant else 0.0)
        actual=sum(1/math.log2(rank+1) for rank in relevant)
        ideal=sum(1/math.log2(rank+1) for rank in range(1,min(k,len(expected))+1))
        ndcgs.append(actual/ideal)
    def mean(values): return sum(values)/len(values) if values else None
    return {
        "cases":len(cases),"labelled_answerable":len(recalls),
        "recall_at_k":mean(recalls),"precision_at_k":mean(precisions),
        "mrr":mean(ranks),"ndcg_at_k":mean(ndcgs),
        "correct_abstentions":sum(abstention_checks),
        "abstention_cases":len(abstention_checks),
        "permission_leaks":leaks,
        "scope":"authored synthetic role-scoped source labels only",
    }

if __name__=="__main__":
    cases=json.loads(Path("fixtures/retrieval_gold.json").read_text("utf-8"))
    print(json.dumps(evaluate_retrieval(EnterpriseRAG(),cases),indent=2))
