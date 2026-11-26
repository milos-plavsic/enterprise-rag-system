"""Fail-closed tests for exact-merge CodeQL analysis and original TLS rule."""
from unittest import TestCase, mock

from scripts import verify_codeql_alert_2 as q

MERGE = "a" * 40
BASE = "b" * 40
HEAD = "c" * 40
REF = "refs/pull/10/merge"
RULE = "py/insecure-protocol"


def fixture():
    original = {
        "number": 2, "tool": {"name": "CodeQL"}, "rule": {"id": RULE},
        "state": "open", "dismissed_at": None,
        "most_recent_instance": {"location": {"path": "scripts/smoke_idp.py"}},
    }
    current = [{
        "ref": REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
        "error": "", "warning": "", "rules_count": 320, "id": 9001,
    }]
    pull = {
        "number": 10, "merge_commit_sha": None, "state": "open",
        "base": {"ref": "main", "sha": BASE}, "head": {"sha": HEAD},
    }
    merge = {"sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]}
    return original, current, pull, merge


def protected_branch(sha=BASE):
    return {"name": "main", "protected": True, "commit": {"sha": sha}}


class TestCodeQLPremergeProof(TestCase):
    def test_positive_clean_analysis(self):
        alert, analyses, _, _ = fixture()
        self.assertEqual(q.verify_premerge(alert, analyses, [], MERGE),
                         (RULE, 9001))

    def test_missing_current_analysis_fails(self):
        alert, _, _, _ = fixture()
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, [], [], MERGE)

    def test_stale_analysis_fails(self):
        alert, analyses, _, _ = fixture()
        analyses[0]["commit_sha"] = HEAD
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_wrong_analysis_ref_fails(self):
        alert, analyses, _, _ = fixture()
        analyses[0]["ref"] = "refs/heads/main"
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_wrong_analysis_tool_fails(self):
        alert, analyses, _, _ = fixture()
        analyses[0]["tool"]["name"] = "OtherScanner"
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_empty_rules_count_fails(self):
        alert, analyses, _, _ = fixture()
        analyses[0]["rules_count"] = 0
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_analysis_error_fails(self):
        alert, analyses, _, _ = fixture()
        analyses[0]["error"] = "SARIF invalid"
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_matching_open_alert_fails_even_if_file_moved(self):
        alert, analyses, _, _ = fixture()
        opened = [{
            "state": "open", "rule": {"id": RULE},
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": REF, "location": {"path": "elsewhere.py"}},
        }]
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, opened, MERGE)

    def test_unrelated_rule_does_not_claim_tls_failure(self):
        alert, analyses, _, _ = fixture()
        unrelated = [{
            "state": "open", "rule": {"id": "py/unrelated"},
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": REF},
        }]
        self.assertEqual(q.verify_premerge(alert, analyses, unrelated, MERGE),
                         (RULE, 9001))

    def test_open_alert_wrong_ref_fails(self):
        alert, analyses, _, _ = fixture()
        wrong = [{
            "state": "open", "rule": {"id": "py/unrelated"},
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": "refs/heads/main"},
        }]
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, wrong, MERGE)

    def test_original_dismissal_is_not_remediation(self):
        alert, analyses, _, _ = fixture()
        alert["state"] = "dismissed"
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_missing_original_rule_fails(self):
        alert, analyses, _, _ = fixture()
        alert["rule"] = {}
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_wrong_original_source_fails(self):
        alert, analyses, _, _ = fixture()
        alert["most_recent_instance"]["location"]["path"] = "not_fixture.py"
        with self.assertRaises(q.VerificationError):
            q.verify_premerge(alert, analyses, [], MERGE)

    def test_correct_merge_ancestry(self):
        _, _, pull, merge = fixture()
        q.verify_merge_ancestry(pull, merge, MERGE)

    def test_invalid_merge_ancestry_fails(self):
        _, _, pull, merge = fixture()
        merge["parents"][1]["sha"] = "d" * 40
        with self.assertRaises(q.VerificationError):
            q.verify_merge_ancestry(pull, merge, MERGE)

    def test_wrong_merge_sha_fails(self):
        _, _, pull, merge = fixture()
        merge["sha"] = "d" * 40
        with self.assertRaises(q.VerificationError):
            q.verify_merge_ancestry(pull, merge, MERGE)

    def test_reject_unexpected_execution_context(self):
        for args in [
            ("someone/else", REF, "pull_request", MERGE),
            (q.REPO, "refs/heads/main", "pull_request", MERGE),
            (q.REPO, REF, "push", MERGE),
            (q.REPO, REF, "pull_request", "invalid"),
        ]:
            with self.assertRaises(q.VerificationError):
                q.require_identity(*args)

    def test_paginated_query_reads_to_end(self):
        rows = [{"state": "open"}] * 101
        with mock.patch.object(q, "api_get", side_effect=[rows[:100], rows[100:]]) as get:
            self.assertEqual(
                q.collect_paginated(f"/repos/{q.REPO}", "alerts", "fake", {}),
                rows,
            )
            self.assertEqual(get.call_count, 2)

    def test_paginated_query_fails_on_malformed(self):
        with mock.patch.object(q, "api_get", return_value={"bad": "data"}):
            with self.assertRaises(q.VerificationError):
                q.collect_paginated(f"/repos/{q.REPO}", "analyses", "fake", {})

    def test_full_check_success(self):
        alert, analyses, pull, merge = fixture()
        with mock.patch.object(
            q, "api_get", side_effect=[alert, pull, merge, protected_branch(), analyses, []]
        ):
            self.assertEqual(q.check("fake", MERGE), (RULE, 9001))

    def test_full_check_eventual_indexing(self):
        alert, analyses, pull, merge = fixture()
        with mock.patch.object(
            q, "api_get", side_effect=[alert, pull, merge, protected_branch(), [], analyses, []]
        ), mock.patch.object(q.time, "sleep") as sleep:
            self.assertEqual(q.check("fake", MERGE), (RULE, 9001))
            sleep.assert_called_once_with(q.DELAY_SECONDS)

    def test_full_check_does_not_retry_positive_finding(self):
        alert, analyses, pull, merge = fixture()
        finding = [{
            "state": "open", "rule": {"id": RULE}, "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": REF},
        }]
        with mock.patch.object(
            q, "api_get", side_effect=[alert, pull, merge, protected_branch(), analyses, finding]
        ), mock.patch.object(q.time, "sleep") as sleep:
            with self.assertRaises(q.VerificationError):
                q.check("fake", MERGE)
            sleep.assert_not_called()

    def test_full_check_rejects_wrong_base(self):
        alert, analyses, pull, merge = fixture()
        pull["base"]["ref"] = "develop"
        with mock.patch.object(q, "api_get", side_effect=[alert, pull, merge, protected_branch()]):
            with self.assertRaises(q.VerificationError):
                q.check("fake", MERGE)

    def test_permission_denied_fails_without_retry(self):
        with mock.patch.object(
            q, "api_get", side_effect=q.VerificationError("HTTP 403")
        ) as getter, mock.patch.object(q.time, "sleep") as sleep:
            with self.assertRaises(q.VerificationError):
                q.check("fake", MERGE)
            getter.assert_called_once()
            sleep.assert_not_called()

    def test_api_origin_path_escape_rejected(self):
        with self.assertRaises(q.VerificationError):
            q.api_get("/not-allowed", "fake")

    def test_redirect_refused(self):
        with self.assertRaises(q.VerificationError):
            q.NoRedirect().redirect_request(None, None, 302, "", {}, "http://bad.test")

    def test_checked_out_merge_sha(self):
        with mock.patch.object(q.subprocess, "run") as runner:
            runner.return_value.stdout = MERGE + chr(10)
            self.assertEqual(q.checked_out_merge_sha(), MERGE)
            runner.assert_called_once()

    def test_bad_checkout_merge_sha_fails(self):
        with mock.patch.object(q.subprocess, "run") as runner:
            runner.return_value.stdout = "bad-sha"
            with self.assertRaises(q.VerificationError):
                q.checked_out_merge_sha()

    def test_main_branch_must_be_protected(self):
        with self.assertRaises(q.VerificationError):
            q.verify_main_branch({"name": "main", "protected": False, "commit": {"sha": BASE}})

    def test_main_branch_tip_is_bound(self):
        q.verify_main_branch(protected_branch(), BASE)
        with self.assertRaises(q.VerificationError):
            q.verify_main_branch(protected_branch(HEAD), BASE)

    def test_postmerge_execution_context(self):
        self.assertEqual(q.execution_mode(q.REPO, q.MAIN_REF, "push", MERGE), "postmerge")

    def test_postmerge_fixed_alert_success(self):
        alert, _, _, _ = fixture()
        alert["state"] = "fixed"
        alert["fixed_at"] = "2026-11-26T12:00:00Z"
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
            "created_at": "2026-11-26T12:00:00Z",
        }]
        self.assertEqual(
            q.verify_postmerge(alert, analyses, [], MERGE),
            (RULE, 9002, "2026-11-26T12:00:00Z"),
        )

    def test_postmerge_open_state_is_not_formal_closure(self):
        alert, _, _, _ = fixture()
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
        }]
        with self.assertRaises(q.VerificationError):
            q.verify_postmerge(alert, analyses, [], MERGE)

    def test_postmerge_fixed_state_requires_fixed_at(self):
        alert, _, _, _ = fixture()
        alert["state"] = "fixed"
        alert["fixed_at"] = None
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
        }]
        with self.assertRaises(q.VerificationError):
            q.verify_postmerge(alert, analyses, [], MERGE)

    def test_postmerge_recurrence_of_original_rule_fails(self):
        alert, _, _, _ = fixture()
        alert["state"] = "fixed"
        alert["fixed_at"] = "2026-11-26T12:00:00Z"
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
        }]
        opened = [{
            "state": "open", "rule": {"id": RULE}, "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": q.MAIN_REF},
        }]
        with self.assertRaises(q.VerificationError):
            q.verify_postmerge(alert, analyses, opened, MERGE)

    def test_full_postmerge_check_success(self):
        alert, _, _, _ = fixture()
        alert["state"] = "fixed"
        alert["fixed_at"] = "2026-11-26T12:00:00Z"
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
        }]
        with mock.patch.object(
            q, "api_get",
            side_effect=[protected_branch(MERGE), analyses, alert, []],
        ):
            self.assertEqual(
                q.check_postmerge("fake", MERGE),
                (RULE, 9002, "2026-11-26T12:00:00Z"),
            )

    def test_full_postmerge_check_retries_open_to_fixed_transition(self):
        alert, _, _, _ = fixture()
        fixed = dict(alert)
        fixed["state"] = "fixed"
        fixed["fixed_at"] = "2026-11-26T12:00:00Z"
        analyses = [{
            "ref": q.MAIN_REF, "commit_sha": MERGE, "tool": {"name": "CodeQL"},
            "error": "", "warning": "", "rules_count": 320, "id": 9002,
        }]
        with mock.patch.object(
            q, "api_get",
            side_effect=[protected_branch(MERGE), analyses, alert, analyses, fixed, []],
        ), mock.patch.object(q.time, "sleep") as sleep:
            self.assertEqual(
                q.check_postmerge("fake", MERGE),
                (RULE, 9002, "2026-11-26T12:00:00Z"),
            )
            sleep.assert_called_once_with(q.DELAY_SECONDS)

