"""Require enabled original rule and prove it detects the historical defect.

The normal analysis must contain no result for the original rule, even a
suppressed one. A separate, local database contains the exact historical
fixture and current fixture. Its only permitted findings are on the former.
Neither control source nor its SARIF is uploaded to GitHub code scanning.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

RULE = "py/insecure-protocol"


def original_results(document: dict) -> list[dict]:
    if document.get("version") != "2.1.0":
        raise ValueError("unsupported SARIF version")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("expected exactly one Python CodeQL run")
    run = runs[0]
    tool = run["tool"]
    driver = tool["driver"]
    if driver.get("name") not in {"CodeQL", "CodeQL command-line toolchain"}:
        raise ValueError("unexpected SARIF analysis tool")
    components = [driver, *tool.get("extensions", [])]
    rules = [rule for component in components for rule in component.get("rules", [])
             if rule.get("id") == RULE]
    if not rules or any(rule.get("defaultConfiguration", {}).get("enabled") is not True
                        for rule in rules):
        raise ValueError("original TLS rule not enabled in SARIF")
    for invocation in run.get("invocations", []):
        if invocation.get("executionSuccessful") is False:
            raise ValueError("CodeQL SARIF reports failed execution")
    results = run.get("results")
    if not isinstance(results, list):
        raise ValueError("missing CodeQL SARIF result inventory")
    selected = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
            raise ValueError("SARIF result without explicit rule identity")
        if result["ruleId"] == RULE:
            selected.append(result)
    return selected


def verify_clean(document: dict) -> None:
    if original_results(document):
        raise ValueError("original TLS rule has a finding, including suppressed results")


def verify_positive_control(document: dict) -> None:
    results = original_results(document)
    if not results:
        raise ValueError("historical insecure fixture did not trigger the original query")
    for result in results:
        if result.get("suppressions"):
            raise ValueError("historical positive control was suppressed")
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ValueError("positive control result lacks source location")
        for location in locations:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            if PurePosixPath(unquote(urlsplit(uri).path)).name != "original.py":
                raise ValueError("original TLS rule also flags the remediated fixture")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normal_sarif", type=Path)
    parser.add_argument("control_sarif", type=Path)
    args = parser.parse_args()
    verify_clean(json.loads(args.normal_sarif.read_bytes()))
    verify_positive_control(json.loads(args.control_sarif.read_bytes()))
    print("VERIFIED: enabled original rule has no normal finding and detects historical positive control only")


if __name__ == "__main__":
    main()
