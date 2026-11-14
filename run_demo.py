"""Synthetic, offline functional evaluation; not a production correctness claim."""
from __future__ import annotations
import json
from pathlib import Path
from eval_benchmark import run_benchmark
from rag_service import EnterpriseRAG

if __name__=="__main__":
    doc=json.loads(Path("fixtures/evaluation.json").read_text("utf-8"))
    report=run_benchmark(EnterpriseRAG(),doc)
    print(json.dumps(report,indent=2))
    if report["failures"]:
        raise SystemExit(1)
