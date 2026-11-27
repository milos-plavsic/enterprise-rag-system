"""Read-only, exact-PR acceptance verifier for an independently controlled runner.

Run only a separately reviewed and pinned copy of this program, never the
candidate's checkout. The approved head and base must come from that runner's
trusted review record, not a PR-provided value. This program does not publish
a GitHub check or claim that the independent producer has been provisioned.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from urllib.parse import urlencode

REPO = "milos-plavsic/enterprise-rag-system"
PREFIX = f"/repos/{REPO}/"
WORKFLOWS = {
    ".github/workflows/ci.yml": (286521581, {"tests (3.11)", "tests (3.12)", "tests (3.13)"}),
    ".github/workflows/security.yml": (416615574, {"static", "CodeQL (Python)", "CodeQL original TLS regression gate"}),
    ".github/workflows/production.yml": (417413644, {"image"}),
    ".github/workflows/reference.yml": (418250940, {"reference"}),
    ".github/workflows/base-evaluation.yml": (429327951, {
        "Evaluate alpine-current", "Evaluate debian-bookworm", "Evaluate debian-trixie",
        "Evaluate docker-hardened-dev", "Evaluate chainguard-dev"}),
}
ACTIONS_APP = 15368
CODEQL_APP = 57789


def require(condition, message):
    if not condition:
        raise ValueError(message)


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def api(path):
    require(path.startswith(PREFIX), "unexpected API path")
    result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET", path],
                            check=True, capture_output=True, text=True, timeout=40)
    return json.loads(result.stdout)


def page_all(get, path, key):
    # Reject pagination ambiguity rather than trusting a partial inventory.
    result = []
    page = 1
    while page <= 20:
        sep = "&" if "?" in path else "?"
        data = get(path + sep + urlencode({"per_page": 100, "page": page}))
        rows, total = data[key], data["total_count"]
        require(isinstance(rows, list) and type(total) is int and total >= 0, "malformed page")
        result.extend(rows)
        if len(result) == total:
            ids = [row["id"] for row in result]
            require(len(set(ids)) == len(ids), "duplicated result across pages")
            return result
        require(rows and len(result) < total, "incomplete or inconsistent pagination")
        page += 1
    raise ValueError("too many result pages")


def approved_pr(get, number, head, base):
    pull = get(PREFIX + f"pulls/{number}")
    require(pull["number"] == number and pull["state"] == "open" and not pull["draft"], "PR not ready")
    require(pull["head"]["sha"] == head and pull["base"]["sha"] == base
            and pull["base"]["ref"] == "main"
            and pull["base"]["repo"]["full_name"] == REPO, "PR differs from independent review")
    merge = pull["merge_commit_sha"]
    require(valid_sha(merge), "missing exact merge SHA")
    commit = get(PREFIX + f"git/commits/{merge}")
    require(commit["sha"] == merge and [p["sha"] for p in commit["parents"]] == [base, head],
            "unexpected merge ancestry")
    branch = get(PREFIX + "branches/main")
    require(branch["protected"] is True and branch["commit"]["sha"] == base, "main protection/base drift")
    return merge


def verify(get, number, head, base):
    require(type(number) is int and number > 0 and valid_sha(head) and valid_sha(base), "invalid trusted approval identity")
    merge = approved_pr(get, number, head, base)
    checks = page_all(get, PREFIX + f"commits/{head}/check-runs?filter=all", "check_runs")
    runs = page_all(get, PREFIX + f"actions/runs?head_sha={head}&event=pull_request", "workflow_runs")
    selected = {}
    for path, (workflow_id, names) in WORKFLOWS.items():
        possible = [row for row in runs if row.get("path") == path and row.get("workflow_id") == workflow_id]
        require(len(possible) == 1, f"missing or ambiguous workflow: {path}")
        run = possible[0]
        require(run["head_sha"] == head and run["event"] == "pull_request"
                and run["repository"]["full_name"] == REPO
                and run["status"] == "completed" and run["conclusion"] == "success",
                f"workflow not successful: {path}")
        require(any(p["number"] == number and p["head"]["sha"] == head and p["base"]["sha"] == base
                    for p in run["pull_requests"]), f"workflow PR association mismatch: {path}")
        attempt = run["run_attempt"]
        require(type(attempt) is int and attempt >= 1, "invalid workflow attempt")
        jobs = page_all(get, PREFIX + f"actions/runs/{run['id']}/attempts/{attempt}/jobs", "jobs")
        for name in names:
            matches = [job for job in jobs if job["name"] == name]
            require(len(matches) == 1, f"missing or duplicate job: {name}")
            job = matches[0]
            require(job["status"] == "completed" and job["conclusion"] == "success"
                    and job["run_id"] == run["id"], f"job did not execute successfully: {name}")
            # GitHub legitimately creates two checks with the same name at
            # the same head when both push and pull_request triggers run.
            # Select by the exact GitHub job URL in the approved PR run,
            # not by a globally unique check name. Duplicate matches for
            # the same job remain an unconditional rejection.
            candidates = [check for check in checks
                          if check["name"] == name and check.get("details_url") == job["html_url"]]
            require(len(candidates) == 1, f"missing or ambiguous exact job check: {name}")
            check = candidates[0]
            require(check["head_sha"] == head and check["app"]["id"] == ACTIONS_APP
                    and check["status"] == "completed" and check["conclusion"] == "success"
                    and check["details_url"] == job["html_url"], f"unexpected check identity: {name}")
            selected[name] = {"run_id": run["id"], "job_id": job["id"], "check_id": check["id"]}
    codeql = [row for row in checks if row["name"] == "CodeQL"]
    require(len(codeql) == 1 and codeql[0]["head_sha"] == head
            and codeql[0]["app"]["id"] == CODEQL_APP
            and codeql[0]["status"] == "completed" and codeql[0]["conclusion"] == "success",
            "missing or invalid CodeQL service check")
    require(approved_pr(get, number, head, base) == merge, "PR changed during verification")
    return {"repository": REPO, "pr": number, "head": head, "base": base, "merge": merge,
            "verified_jobs": selected, "codeql_check_id": codeql[0]["id"],
            "qualification": "Execution evidence only. Independent source and policy review required."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pr", type=int)
    parser.add_argument("--approved-head", required=True)
    parser.add_argument("--approved-base", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(api, args.pr, args.approved_head, args.approved_base), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
