"""Offline, labelled functional evaluation baseline.

Cases check known-answer data selection and policy outcomes. They are not a
representative production RAG quality benchmark or calibrated model evaluation.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from rag_service import EnterpriseRAG, Identity, InsufficientEvidence

def run_benchmark(rag: EnterpriseRAG, document: dict[str, Any]) -> dict[str, Any]:
    cases = document.get("cases", [])
    if not cases:
        raise ValueError("nonempty labelled cases required")
    failures: list[dict[str, str]] = []
    for case in cases:
        reasons = []
        try:
            result=rag.query(case["question"],Identity("evaluation",case["role"]))
        except InsufficientEvidence:
            result = {"status": "abstained", "answer": ""}
        except PermissionError:
            result = {"status": "denied", "answer": ""}
        if result["status"] != case["expect"]:
            reasons.append(f"expected {case['expect']}, got {result['status']}")
        fragment = case.get("must_contain")
        if fragment and fragment not in result["answer"]:
            reasons.append("expected answer fragment missing")
        sources = {row.get("source") for field in ("citations", "evidence")
                   for row in result.get(field, [])}
        forbidden = case.get("forbid_source")
        if forbidden and forbidden in sources:
            reasons.append("unauthorised source in citations or evidence")
        if reasons:
            failures.append({"case": case["id"], "reason": ", ".join(reasons)})
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
    results = run_benchmark(rag, cases)
    print(json.dumps(results, indent=2))
    raise SystemExit(1 if results["failures"] else 0)
