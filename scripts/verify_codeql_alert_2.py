#!/usr/bin/env python3
"""Verify original CodeQL TLS finding is absent from a freshly analysed PR merge.

Original alert closure on the default branch is a post-merge requirement.
Read-only security-events token. No dismissal, mutation, or waiver.
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
MAX_ATTEMPTS = 18
DELAY_SECONDS = 5


class VerificationError(Exception):
    """Alert evidence is unavailable, stale, or ambiguous."""


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


def require_identity(repo: str, ref: str, event: str, merge_sha: str) -> None:
    if repo != REPO or event != "pull_request" or ref != f"refs/pull/{PR_NUMBER}/merge":
        raise VerificationError("Unexpected repository, event or PR merge ref")
    if len(merge_sha) != 40 or any(c not in "0123456789abcdef" for c in merge_sha):
        raise VerificationError("Invalid merge SHA")


def validate_original_alert(alert: object) -> str:
    if not isinstance(alert, dict) or alert.get("number") != ALERT_NUMBER:
        raise VerificationError("Wrong original CodeQL alert")
    if (alert.get("tool") or {}).get("name") != "CodeQL":
        raise VerificationError("Original alert is not CodeQL")
    if alert.get("state") == "dismissed" or alert.get("dismissed_at") is not None:
        raise VerificationError("Dismissal cannot stand in for remediation")
    location = ((alert.get("most_recent_instance") or {}).get("location") or {})
    if location.get("path") != "scripts/smoke_idp.py":
        raise VerificationError("Original alert path no longer matches TLS fixture")
    rule_id = (alert.get("rule") or {}).get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise VerificationError("Original CodeQL rule identity missing")
    return rule_id


def verify_premerge(
    alert: object, analyses: object, open_alerts: object,
    merge_sha: str,
) -> tuple[str, int]:
    """A missing fixed instance is NOT a shortcut: require a current CodeQL analysis.

    A clean PR merge ref often has no alert instance at all. Verify an actual
    CodeQL analysis with the exact merge SHA and non-empty rules, then check
    every open CodeQL alert for the original vulnerability rule on that ref.
    """
    rule_id = validate_original_alert(alert)
    ref = f"refs/pull/{PR_NUMBER}/merge"
    if not isinstance(analyses, list):
        raise VerificationError("No CodeQL analyses evidence")
    current = [
        a for a in analyses if isinstance(a, dict)
        and a.get("ref") == ref
        and a.get("commit_sha") == merge_sha
        and (a.get("tool") or {}).get("name") == "CodeQL"
    ]
    if not current:
        raise VerificationError("Exact-merge CodeQL analysis not indexed")
    if any(
        a.get("error") or a.get("warning")
        or not isinstance(a.get("rules_count"), int)
        or a["rules_count"] <= 0
        for a in current
    ):
        raise VerificationError("Exact-merge CodeQL analysis incomplete or invalid")
    if not isinstance(open_alerts, list):
        raise VerificationError("Missing PR code-scanning alert evidence")
    for row in open_alerts:
        if not isinstance(row, dict):
            raise VerificationError("Malformed PR alert")
        if row.get("state") != "open":
            raise VerificationError("PR open-alert query returned unexpected state")
        instance = row.get("most_recent_instance") or {}
        if instance.get("ref") != ref:
            raise VerificationError("PR alert evidence is from another ref")
        if (row.get("tool") or {}).get("name") != "CodeQL":
            continue
        if (row.get("rule") or {}).get("id") == rule_id:
            raise VerificationError("Original CodeQL TLS rule still has open PR finding")
    return rule_id, current[0]["id"]


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


def verify_merge_ancestry(pull: object, commit: object, merge_sha: str) -> None:
    """Bind the checked-out merge tree to the latest base and head commits."""
    if not isinstance(pull, dict) or not isinstance(commit, dict):
        raise VerificationError("Missing PR or merge commit ancestry")
    base, head = pull.get("base"), pull.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise VerificationError("PR base/head metadata incomplete")
    expected = [base.get("sha"), head.get("sha")]
    parents = commit.get("parents")
    if (not all(isinstance(value, str) and len(value) == 40 for value in expected)
            or commit.get("sha") != merge_sha
            or not isinstance(parents, list)
            or [p.get("sha") if isinstance(p, dict) else None for p in parents] != expected):
        raise VerificationError("Checked-out merge commit is not current PR base+head merge")


def check(token: str, merge_sha: str) -> tuple[str, int]:
    base = f"/repos/{REPO}"
    alert = api_get(base + f"/code-scanning/alerts/{ALERT_NUMBER}", token)
    pull = api_get(base + f"/pulls/{PR_NUMBER}", token)
    merge = api_get(base + f"/git/commits/{merge_sha}", token)
    verify_merge_ancestry(pull, merge, merge_sha)
    if (pull.get("number") != PR_NUMBER or pull.get("state") != "open"
            or (pull.get("base") or {}).get("ref") != "main"
            or pull.get("merge_commit_sha") not in (None, merge_sha)):
        raise VerificationError("Unexpected PR metadata")
    ref = f"refs/pull/{PR_NUMBER}/merge"
    # CodeQL uploads and GitHub's code-scanning index are eventually consistent.
    # Retry only a missing exact-head analysis. Never retry a positive finding.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        analyses = collect_paginated(
            base, "analyses", token, {"ref": ref, "tool_name": "CodeQL"}
        )
        # Check readiness before querying the alert list; otherwise an absent
        # alert list would be a false green when CodeQL never analysed the ref.
        try:
            verify_premerge(alert, analyses, [], merge_sha)
        except VerificationError as exc:
            if "Exact-merge CodeQL analysis not indexed" not in str(exc):
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


def checked_out_merge_sha() -> str:
    # Actions checkout resolves the actual PR merge ref. GITHUB_SHA describes
    # the workflow event and is not a substitute for the checked-out tree.
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, text=True,
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("Cannot resolve checked-out PR merge commit") from exc
    sha = result.stdout.strip()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise VerificationError("Invalid checked-out PR merge commit SHA")
    return sha


def main() -> int:
    try:
        merge_sha = checked_out_merge_sha()
        require_identity(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_REF", ""),
            os.environ.get("GITHUB_EVENT_NAME", ""),
            merge_sha,
        )
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise VerificationError("Missing read-only GitHub Actions token")
        rule_id, analysis_id = check(token, merge_sha)
    except VerificationError as exc:
        print(f"NOT VERIFIED: {exc}", file=sys.stderr)
        return 1
    print(f"VERIFIED: original CodeQL rule {rule_id} has no open finding on "
          f"the exact PR merge analysis {analysis_id} ({merge_sha}). "
          "Default-branch alert closure remains a post-merge gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
