"""Labelled lexical/hybrid retrieval metrics on authored demo fixtures.

This is a regression benchmark, not an independently sampled relevance study.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
from time import perf_counter
from typing import Any
from rag_service import EnterpriseRAG

def evaluate_retrieval(
    rag: EnterpriseRAG, benchmark: dict[str, Any], k: int = 4, *, ranking: str = "hybrid",
) -> dict[str, Any]:
    if not 1 <= k <= 20:
        raise ValueError("k must be between 1 and 20")
    cases=benchmark.get("cases")
    if not isinstance(cases,list) or not cases:
        raise ValueError("nonempty labelled retrieval cases required")
    ranks=[]
    recalls=[]
    precisions=[]
    ndcgs=[]
    abstention_checks=[]
    leaks=[]
    timings=[]
    for case in cases:
        role=case["role"]
        expected=set(case["expected_sources"])
        started=perf_counter()
        results=rag.search_documents(case["question"],role,k,distinct_sources=True,ranking=ranking)
        timings.append((perf_counter()-started)*1000)
        ranked=[row["source"] for row in results]
        for source in ranked:
            if not rag.can_access_document(role, source):
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
        "ranking":ranking,"ranking_unit":"distinct source","k":k,
        "recall_at_k":mean(recalls),"precision_at_k":mean(precisions),
        "mrr":mean(ranks),"ndcg_at_k":mean(ndcgs),
        "correct_abstentions":sum(abstention_checks),
        "abstention_cases":len(abstention_checks),
        "permission_leaks":leaks,
        "mean_query_ms":mean(timings),
        "p95_query_ms":sorted(timings)[math.ceil(0.95*len(timings))-1],
        "scope":"retrieval only, with relevance defined by the supplied source labels",
    }

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=Path("fixtures/retrieval_gold.json"))
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--k", type=int, default=4)
    parser.add_argument("--ranking", choices=("lexical","dense","hybrid"), default="lexical")
    args=parser.parse_args()
    cases=json.loads(args.fixture.read_text("utf-8"))
    results=evaluate_retrieval(EnterpriseRAG(args.data_dir),cases,args.k,ranking=args.ranking)
    print(json.dumps(results,indent=2))
    raise SystemExit(1 if results["permission_leaks"] else 0)
