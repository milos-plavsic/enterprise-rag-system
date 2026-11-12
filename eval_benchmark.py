"""Offline, labelled functional evaluation baseline.

Cases check known-answer data selection and policy outcomes. They are not a
representative production RAG quality benchmark or calibrated model evaluation.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from rag_service import EnterpriseRAG, Identity

def run_benchmark(rag: EnterpriseRAG, document: dict[str, Any]) -> dict[str, Any]:
    cases = document.get("cases", [])
    if not cases:
        raise ValueError("nonempty labelled cases required")
    failures: list[dict[str, str]] = []
    for case in cases:
        try:
            result=rag.query(case["question"],Identity("evaluation",case["role"]))
            if case["expect"]=="denied":
                failures.append({"case":case["id"],"reason":"expected permission denial"})
                continue
            expected_status=case["expect"]
            if result["status"]!=expected_status:
                failures.append({"case":case["id"],"reason":"unexpected status"})
            fragment=case.get("must_contain")
            if fragment and fragment not in result["answer"]:
                failures.append({"case":case["id"],"reason":"expected answer fragment missing"})
            forbidden=case.get("forbid_source")
            if forbidden and any(x.get("source")==forbidden for x in result.get("citations",[])):
                failures.append({"case":case["id"],"reason":"unauthorised source in citations"})
        except PermissionError:
            if case["expect"]!="denied":
                failures.append({"case":case["id"],"reason":"unexpected permission denial"})
    return {
        "cases":len(cases),
        "passed":len(cases)-len(failures),
        "accuracy":(len(cases)-len(failures))/len(cases),
        "failures":failures,
        "scope":"authored synthetic functional cases; not independent semantic QA validation",
    }

if __name__=="__main__":
    rag=EnterpriseRAG()
    cases=json.loads(Path("fixtures/evaluation.json").read_text("utf-8"))
    print(json.dumps(run_benchmark(rag,cases),indent=2))
