"""Reproducible fictional-corpus retrieval comparison and bounded workload probe."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import sqlite3
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from document_source import sync
from identity_policy import GRANT_CUTOFF_SECONDS
from production_store import ProductionStore
from rag_service import Identity
from reference.corpus import write

ROOT = Path(__file__).resolve().parent


def run(*, concurrency: int = 4, requests: int = 80) -> dict:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        db = ProductionStore(root / "catalog.sqlite3")
        db.initialize()
        write(root / "source", 2)
        source_stats = sync(db, root / "source")
        for role in ("analyst", "manager", "auditor"):
            db.set_principal(role, role)
        issued_at = int(time.time()) + GRANT_CUTOFF_SECONDS
        with db.connect() as connection:
            keys = dict(connection.execute("SELECT id,source_key FROM documents"))
        manifest = json.loads((root / "source/manifest.json").read_text())
        permissions = {row["key"]: row["roles"] for row in manifest["documents"]}
        held_out = json.loads((ROOT / "reference/held_out.json").read_text())
        output = {"scope": held_out["scope"], "corpus": source_stats, "modes": {}}
        for mode in ("lexical", "concept", "semantic"):
            stats = defaultdict(lambda: {"answerable": 0, "unanswerable": 0, "hits": 0, "abstained": 0, "leaks": 0})
            for role, category, question, expected in held_out["cases"]:
                result = db.query(question, Identity(role, role, issued_at), ranking=mode, reference=True)
                result_keys = {keys[row["source"]] for row in result["evidence"] + result["citations"]}
                for cohort in ("all", f"{role}/{category}"):
                    row = stats[cohort]
                    row["leaks"] += sum(role not in permissions[key] for key in result_keys)
                    if expected:
                        row["answerable"] += 1
                        row["hits"] += expected in result_keys
                    else:
                        row["unanswerable"] += 1
                        row["abstained"] += result["status"] == "abstained"
            output["modes"][mode] = dict(stats)
        identity = Identity("analyst", "analyst", issued_at)

        def query(_):
            start = time.perf_counter()
            result = db.query("expense approval", identity, reference=True)
            assert result["status"] == "evidence_only"
            return 1000 * (time.perf_counter() - start)

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            latency = sorted(pool.map(query, range(requests)))
        elapsed = time.perf_counter() - start
        output["workload"] = {"boundary": "in-process retrieval only; excludes network, IdP and model",
                              "requests": requests, "concurrency": concurrency,
                              "p50_ms": round(latency[(requests - 1) // 2], 2),
                              "p95_ms": round(latency[int(0.95 * (requests - 1))], 2),
                              "requests_per_second": round(requests / elapsed, 2),
                              "platform": platform.platform(), "python": platform.python_version(),
                              "sqlite": sqlite3.sqlite_version, "visible_cpus": os.cpu_count()}
        return output


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--concurrency", type=int, choices=range(1, 17), default=4)
    cli.add_argument("--requests", type=int, default=80)
    args = cli.parse_args()
    if not 1 <= args.requests <= 10_000:
        cli.error("requests must be 1–10000")
    report = run(concurrency=args.concurrency, requests=args.requests)
    print(json.dumps(report, indent=2))
    raise SystemExit(any(x["all"]["leaks"] for x in report["modes"].values()))
