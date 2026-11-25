#!/usr/bin/env python3
"""Verify CodeQL alert #2 is truly fixed on PR #10's exact merge SHA.

Read-only security-events token. No dismissal, modification, or waiver.
"""
from __future__ import annotations

import json
import os
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


def api_get(path: str, token: str) -> object:
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
        with urllib.request.urlopen(request, timeout=15) as response:
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


def verify(alert: object, instances: object, pull: object, merge_sha: str) -> None:
    if not isinstance(alert, dict) or alert.get("number") != ALERT_NUMBER:
        raise VerificationError("Wrong original alert")
    if (alert.get("tool") or {}).get("name") != "CodeQL":
        raise VerificationError("Alert is not from CodeQL")
    if alert.get("state") == "dismissed" or alert.get("dismissed_at") is not None:
        raise VerificationError("Dismissal is not remediation")
    location = ((alert.get("most_recent_instance") or {}).get("location") or {})
    if location.get("path") != "scripts/smoke_idp.py":
        raise VerificationError("Original alert source path mismatch")
    if not isinstance(pull, dict) or pull.get("number") != PR_NUMBER:
        raise VerificationError("Wrong pull request")
    if (pull.get("merge_commit_sha") != merge_sha
            or pull.get("state") != "open"
            or (pull.get("base") or {}).get("ref") != "main"):
        raise VerificationError("Stale PR merge SHA or unexpected base")
    if not isinstance(instances, list):
        raise VerificationError("Missing alert instance list")
    rows = [row for row in instances if isinstance(row, dict)
            and row.get("ref") == f"refs/pull/{PR_NUMBER}/merge"]
    if not rows:
        raise VerificationError("No CodeQL instance for PR merge ref")
    if any(row.get("state") != "fixed" for row in rows):
        raise VerificationError("CodeQL instance not fixed on PR merge ref")
    if any(row.get("commit_sha") != merge_sha for row in rows):
        raise VerificationError("CodeQL instance commit does not match merge SHA")


def check(token: str, merge_sha: str) -> None:
    base = f"/repos/{REPO}"
    alert = api_get(base + f"/code-scanning/alerts/{ALERT_NUMBER}", token)
    pull = api_get(base + f"/pulls/{PR_NUMBER}", token)
    params = urllib.parse.urlencode(
        {"ref": f"refs/pull/{PR_NUMBER}/merge", "per_page": 100}
    )
    for attempt in range(1, MAX_ATTEMPTS + 1):
        instances = api_get(
            base + f"/code-scanning/alerts/{ALERT_NUMBER}/instances?{params}", token
        )
        if isinstance(instances, list) and len(instances) >= 100:
            raise VerificationError("CodeQL instance pagination incomplete")
        try:
            verify(alert, instances, pull, merge_sha)
        except VerificationError as exc:
            # SARIF ingestion can lag the finished CodeQL action. No retry is
            # permitted for permission failures, dismissals or stale identity.
            if ("No CodeQL instance for PR merge ref" not in str(exc)
                    and "CodeQL instance not fixed" not in str(exc)):
                raise
            if attempt == MAX_ATTEMPTS:
                raise
            time.sleep(DELAY_SECONDS)
        else:
            return
    raise VerificationError("CodeQL verification exhausted")


def main() -> int:
    try:
        require_identity(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_REF", ""),
            os.environ.get("GITHUB_EVENT_NAME", ""),
            os.environ.get("GITHUB_SHA", ""),
        )
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise VerificationError("Missing read-only GitHub Actions token")
        check(token, os.environ["GITHUB_SHA"])
    except VerificationError as exc:
        print(f"NOT VERIFIED: {exc}", file=sys.stderr)
        return 1
    print("VERIFIED: original CodeQL alert #2 fixed on exact PR merge SHA")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
