#!/usr/bin/env python3
"""Verify the original CodeQL TLS finding across PR and default-branch gates.

PR gate:
  * prove main is already protected and the PR base is the current main tip;
  * prove CodeQL analysed the exact current PR merge commit;
  * prove the original TLS rule has no open finding on that merge ref.

Main gate:
  * prove the checked-out commit is the protected main tip;
  * prove CodeQL analysed that exact main commit;
  * prove alert #2 is formally fixed (never dismissed/waived);
  * prove no open CodeQL finding for the original rule remains on main.

All queries are read-only and fail closed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = "milos-plavsic/enterprise-rag-system"
PR_NUMBER = 10
ALERT_NUMBER = 2
MAIN_REF = "refs/heads/main"
MAX_ATTEMPTS = 18
DELAY_SECONDS = 5


class VerificationError(Exception):
    """Security evidence is unavailable, stale, inconsistent, or ambiguous."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise VerificationError("Unexpected GitHub API redirect")


def api_get(path: str, token: str) -> object:
    # Authenticate exclusively to the fixed GitHub HTTPS API origin.
    if not path.startswith("/repos/" + REPO + "/"):
        raise VerificationError("Unexpected GitHub API path")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "enterprise-rag-codeql-alert-verifier",
        },
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(), NoRedirect()
        )
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise VerificationError(f"GitHub returned HTTP {response.status}")
            raw = response.read(1_048_577)
    except urllib.error.HTTPError as exc:
        raise VerificationError(f"GitHub evidence query returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise VerificationError("GitHub evidence query unavailable") from exc
    if len(raw) > 1_048_576:
        raise VerificationError("GitHub evidence unexpectedly large")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("Malformed GitHub evidence") from exc


def _valid_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(c in "0123456789abcdef" for c in value)
    )


def execution_mode(repo: str, ref: str, event: str, sha: str) -> str:
    if repo != REPO or not _valid_sha(sha):
        raise VerificationError("Unexpected repository or invalid checked-out commit")
    if event == "pull_request" and ref == f"refs/pull/{PR_NUMBER}/merge":
        return "premerge"
    if event == "push" and ref == MAIN_REF:
        return "postmerge"
    raise VerificationError("Unexpected event/ref for CodeQL closure verification")


def require_identity(repo: str, ref: str, event: str, merge_sha: str) -> None:
    """Backwards-compatible strict PR-only identity check."""
    if execution_mode(repo, ref, event, merge_sha) != "premerge":
        raise VerificationError("Unexpected repository, event or PR merge ref")


def validate_original_alert(alert: object) -> str:
    if not isinstance(alert, dict) or alert.get("number") != ALERT_NUMBER:
        raise VerificationError("Wrong original CodeQL alert")
    if (alert.get("tool") or {}).get("name") != "CodeQL":
        raise VerificationError("Original alert is not CodeQL")
    if alert.get("state") == "dismissed" or alert.get("dismissed_at") is not None:
        raise VerificationError("Dismissal cannot stand in for remediation")
    if alert.get("state") not in {"open", "fixed"}:
        raise VerificationError("Unexpected original alert state")
    location = ((alert.get("most_recent_instance") or {}).get("location") or {})
    if location.get("path") != "scripts/smoke_idp.py":
        raise VerificationError("Original alert path no longer matches TLS fixture")
    rule_id = (alert.get("rule") or {}).get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise VerificationError("Original CodeQL rule identity missing")
    return rule_id


def latest_current_analysis(analyses: object, ref: str, sha: str) -> dict:
    if not isinstance(analyses, list):
        raise VerificationError("No CodeQL analyses evidence")
    current = [
        a for a in analyses if isinstance(a, dict)
        and a.get("ref") == ref
        and a.get("commit_sha") == sha
        and (a.get("tool") or {}).get("name") == "CodeQL"
    ]
    if not current:
        raise VerificationError("Exact-commit CodeQL analysis not indexed")

    def order_key(row: dict) -> tuple[str, int]:
        created = row.get("created_at")
        analysis_id = row.get("id")
        return (
            created if isinstance(created, str) else "",
            analysis_id if isinstance(analysis_id, int) else -1,
        )

    latest = max(current, key=order_key)
    if (
        latest.get("error")
        or latest.get("warning")
        or not isinstance(latest.get("rules_count"), int)
        or latest["rules_count"] <= 0
        or not isinstance(latest.get("id"), int)
    ):
        raise VerificationError("Exact-commit CodeQL analysis incomplete or invalid")
    return latest


def verify_open_alerts(open_alerts: object, ref: str, rule_id: str) -> None:
    if not isinstance(open_alerts, list):
        raise VerificationError("Missing code-scanning alert evidence")
    for row in open_alerts:
        if not isinstance(row, dict):
            raise VerificationError("Malformed code-scanning alert")
        if row.get("state") != "open":
            raise VerificationError("Open-alert query returned unexpected state")
        instance = row.get("most_recent_instance") or {}
        if instance.get("ref") != ref:
            raise VerificationError("Alert evidence is from another ref")
        if (row.get("tool") or {}).get("name") != "CodeQL":
            continue
        if (row.get("rule") or {}).get("id") == rule_id:
            raise VerificationError("Original CodeQL TLS rule still has an open finding")


def verify_premerge(
    alert: object, analyses: object, open_alerts: object, merge_sha: str,
) -> tuple[str, int]:
    """Require a complete exact-merge analysis and absence of the original rule."""
    rule_id = validate_original_alert(alert)
    ref = f"refs/pull/{PR_NUMBER}/merge"
    latest = latest_current_analysis(analyses, ref, merge_sha)
    verify_open_alerts(open_alerts, ref, rule_id)
    return rule_id, latest["id"]


def verify_postmerge(
    alert: object, analyses: object, open_alerts: object, main_sha: str,
) -> tuple[str, int, str]:
    """Require GitHub to have formally fixed alert #2 on the exact main analysis."""
    rule_id = validate_original_alert(alert)
    latest = latest_current_analysis(analyses, MAIN_REF, main_sha)
    if alert.get("state") != "fixed":
        raise VerificationError("Original CodeQL alert is not formally fixed on main")
    fixed_at = alert.get("fixed_at")
    if not isinstance(fixed_at, str) or not fixed_at:
        raise VerificationError("Fixed CodeQL alert is missing fixed_at evidence")
    verify_open_alerts(open_alerts, MAIN_REF, rule_id)
    return rule_id, latest["id"], fixed_at


def collect_paginated(base: str, name: str, token: str, params: dict) -> list:
    collected = []
    for page in range(1, 11):
        query = urllib.parse.urlencode({**params, "page": page, "per_page": 100})
        chunk = api_get(base + f"/code-scanning/{name}?{query}", token)
        if not isinstance(chunk, list):
            raise VerificationError(f"Malformed code scanning {name} response")
        collected.extend(chunk)
        if len(chunk) < 100:
            return collected
    raise VerificationError(f"Incomplete code scanning {name} pagination")


def verify_main_branch(branch: object, expected_sha: str | None = None) -> None:
    """Require actual GitHub branch protection, and optionally bind to the main tip."""
    if not isinstance(branch, dict) or branch.get("name") != "main":
        raise VerificationError("Missing main branch evidence")
    if branch.get("protected") is not True:
        raise VerificationError("main is not protected")
    if expected_sha is not None:
        actual = (branch.get("commit") or {}).get("sha")
        if not _valid_sha(expected_sha) or actual != expected_sha:
            raise VerificationError("main tip does not match the verified commit")


def verify_merge_ancestry(pull: object, commit: object, merge_sha: str) -> None:
    """Bind the checked-out merge tree to the latest base and head commits."""
    if not isinstance(pull, dict) or not isinstance(commit, dict):
        raise VerificationError("Missing PR or merge commit ancestry")
    base, head = pull.get("base"), pull.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise VerificationError("PR base/head metadata incomplete")
    expected = [base.get("sha"), head.get("sha")]
    parents = commit.get("parents")
    if (
        not all(_valid_sha(value) for value in expected)
        or commit.get("sha") != merge_sha
        or not isinstance(parents, list)
        or [p.get("sha") if isinstance(p, dict) else None for p in parents] != expected
    ):
        raise VerificationError("Checked-out merge commit is not current PR base+head merge")


def check_premerge(token: str, merge_sha: str) -> tuple[str, int]:
    base = f"/repos/{REPO}"
    alert = api_get(base + f"/code-scanning/alerts/{ALERT_NUMBER}", token)
    pull = api_get(base + f"/pulls/{PR_NUMBER}", token)
    merge = api_get(base + f"/git/commits/{merge_sha}", token)
    branch = api_get(base + "/branches/main", token)

    verify_merge_ancestry(pull, merge, merge_sha)
    if (
        pull.get("number") != PR_NUMBER
        or pull.get("state") != "open"
        or (pull.get("base") or {}).get("ref") != "main"
        or pull.get("merge_commit_sha") not in (None, merge_sha)
    ):
        raise VerificationError("Unexpected PR metadata")
    verify_main_branch(branch, (pull.get("base") or {}).get("sha"))

    ref = f"refs/pull/{PR_NUMBER}/merge"
    # CodeQL uploads and GitHub's code-scanning index are eventually consistent.
    # Retry only missing exact-commit analysis. Never retry a positive finding.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        analyses = collect_paginated(
            base, "analyses", token, {"ref": ref, "tool_name": "CodeQL"}
        )
        try:
            latest_current_analysis(analyses, ref, merge_sha)
        except VerificationError as exc:
            if "Exact-commit CodeQL analysis not indexed" not in str(exc):
                raise
            if attempt == MAX_ATTEMPTS:
                raise
            time.sleep(DELAY_SECONDS)
            continue
        open_alerts = collect_paginated(
            base, "alerts", token,
            {"ref": ref, "tool_name": "CodeQL", "state": "open"},
        )
        return verify_premerge(alert, analyses, open_alerts, merge_sha)
    raise VerificationError("CodeQL analysis indexing not completed")


def check_postmerge(token: str, main_sha: str) -> tuple[str, int, str]:
    base = f"/repos/{REPO}"
    branch = api_get(base + "/branches/main", token)
    verify_main_branch(branch, main_sha)

    # Both the analysis index and fixed-state transition are eventually consistent.
    # Retry those two propagation states only. Dismissal, malformed evidence, wrong
    # refs, incomplete analyses, or a persistent positive finding fail closed.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        analyses = collect_paginated(
            base, "analyses", token, {"ref": MAIN_REF, "tool_name": "CodeQL"}
        )
        try:
            latest_current_analysis(analyses, MAIN_REF, main_sha)
        except VerificationError as exc:
            if "Exact-commit CodeQL analysis not indexed" not in str(exc):
                raise
            if attempt == MAX_ATTEMPTS:
                raise
            time.sleep(DELAY_SECONDS)
            continue

        alert = api_get(base + f"/code-scanning/alerts/{ALERT_NUMBER}", token)
        try:
            rule_id = validate_original_alert(alert)
        except VerificationError:
            raise
        if alert.get("state") != "fixed":
            if alert.get("state") != "open" or attempt == MAX_ATTEMPTS:
                raise VerificationError("Original CodeQL alert is not formally fixed on main")
            time.sleep(DELAY_SECONDS)
            continue

        open_alerts = collect_paginated(
            base, "alerts", token,
            {"ref": MAIN_REF, "tool_name": "CodeQL", "state": "open"},
        )
        result = verify_postmerge(alert, analyses, open_alerts, main_sha)
        if result[0] != rule_id:
            raise VerificationError("Original CodeQL rule identity changed during verification")
        return result
    raise VerificationError("CodeQL fixed-state indexing not completed")


# Backwards-compatible name used by existing callers/tests.
check = check_premerge


def checked_out_commit_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("Cannot resolve checked-out commit") from exc
    sha = result.stdout.strip()
    if not _valid_sha(sha):
        raise VerificationError("Invalid checked-out commit SHA")
    return sha


# Backwards-compatible name used by existing tests.
checked_out_merge_sha = checked_out_commit_sha


def main() -> int:
    try:
        sha = checked_out_commit_sha()
        mode = execution_mode(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_REF", ""),
            os.environ.get("GITHUB_EVENT_NAME", ""),
            sha,
        )
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise VerificationError("Missing read-only GitHub Actions token")
        if mode == "premerge":
            rule_id, analysis_id = check_premerge(token, sha)
            print(
                f"VERIFIED: main is protected and original CodeQL rule {rule_id} "
                f"has no open finding on exact PR merge analysis {analysis_id} ({sha}). "
                "Default-branch alert closure remains a post-merge gate."
            )
        else:
            rule_id, analysis_id, fixed_at = check_postmerge(token, sha)
            print(
                f"VERIFIED: main is protected; original CodeQL alert #{ALERT_NUMBER} "
                f"for rule {rule_id} is formally fixed at {fixed_at}; exact main "
                f"analysis {analysis_id} covers {sha}; no open finding for that rule remains."
            )
    except VerificationError as exc:
        print(f"NOT VERIFIED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
