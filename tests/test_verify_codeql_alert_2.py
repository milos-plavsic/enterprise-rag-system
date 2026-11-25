"""CodeQL alert read-only proof: ensure failures cannot produce false approval."""
from unittest import TestCase, mock

from scripts import verify_codeql_alert_2 as q

SHA = "a" * 40


def merge_fixture():
    return {"sha": SHA, "parents": [{"sha": "b" * 40}, {"sha": "c" * 40}]}


def fixture():
    return (
        {"number": 2, "tool": {"name": "CodeQL"}, "state": "open",
         "dismissed_at": None,
         "most_recent_instance": {"location": {"path": "scripts/smoke_idp.py"}}},
        [{"ref": "refs/pull/10/merge", "state": "fixed", "commit_sha": SHA}],
        {"number": 10, "merge_commit_sha": SHA, "state": "open",
         "base": {"ref": "main", "sha": "b" * 40}, "head": {"sha": "c" * 40}},
    )


class TestCodeQLProof(TestCase):
    def test_fixed(self):
        q.verify(*fixture(), SHA)

    def test_no_instance(self):
        a, rows, p = fixture()
        with self.assertRaises(q.VerificationError):
            q.verify(a, [], p, SHA)

    def test_open_not_fixed(self):
        a, rows, p = fixture()
        rows[0]["state"] = "open"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_dismissal_not_fixed(self):
        a, rows, p = fixture()
        a["state"] = "dismissed"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_dismissal_timestamp_not_fixed(self):
        a, rows, p = fixture()
        a["dismissed_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_wrong_tool(self):
        a, rows, p = fixture()
        a["tool"]["name"] = "other"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_wrong_alert(self):
        a, rows, p = fixture()
        a["number"] = 3
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_wrong_file(self):
        a, rows, p = fixture()
        a["most_recent_instance"]["location"]["path"] = "wrong.py"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_stale_merge(self):
        a, rows, p = fixture()
        p["merge_commit_sha"] = "b" * 40
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_stale_instance(self):
        a, rows, p = fixture()
        rows[0]["commit_sha"] = "b" * 40
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_open_and_fixed_ambiguous(self):
        a, rows, p = fixture()
        rows.append({"ref": "refs/pull/10/merge", "state": "open",
                     "commit_sha": SHA})
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_wrong_base(self):
        a, rows, p = fixture()
        p["base"]["ref"] = "other"
        with self.assertRaises(q.VerificationError):
            q.verify(a, rows, p, SHA)

    def test_reject_wrong_execution_context(self):
        for row in (
            ("other/repo", "refs/pull/10/merge", "pull_request", SHA),
            (q.REPO, "refs/heads/main", "pull_request", SHA),
            (q.REPO, "refs/pull/10/merge", "push", SHA),
            (q.REPO, "refs/pull/10/merge", "pull_request", "broken"),
        ):
            with self.assertRaises(q.VerificationError):
                q.require_identity(*row)

    def test_retry_only_eventual_consistency(self):
        a, rows, p = fixture()
        with mock.patch.object(q, "api_get", side_effect=[a, p, merge_fixture(), [], rows]), \
             mock.patch.object(q.time, "sleep") as sleep:
            q.check("fake", SHA)
            sleep.assert_called_once_with(q.DELAY_SECONDS)

    def test_do_not_retry_auth_denial(self):
        with mock.patch.object(q, "api_get",
                               side_effect=q.VerificationError("HTTP 403")) as get, \
             mock.patch.object(q.time, "sleep") as sleep:
            with self.assertRaises(q.VerificationError):
                q.check("fake", SHA)
            get.assert_called_once()
            sleep.assert_not_called()

    def test_incomplete_pagination(self):
        a, rows, p = fixture()
        with mock.patch.object(q, "api_get",
                               side_effect=[a, p, merge_fixture(), rows * 100]):
            with self.assertRaises(q.VerificationError):
                q.check("fake", SHA)

    def test_api_path_escape_rejected(self):
        with self.assertRaises(q.VerificationError):
            q.api_get("/another/endpoint", "fake")

    def test_redirect_is_rejected(self):
        with self.assertRaises(q.VerificationError):
            q.NoRedirect().redirect_request(None, None, 302, "", {}, "http://wrong.test")

    def test_checkout_merge_commit_used(self):
        with mock.patch.object(q.subprocess, "run") as runner:
            runner.return_value.stdout = SHA + chr(10)
            self.assertEqual(q.checked_out_merge_sha(), SHA)
            runner.assert_called_once()

    def test_malformed_checkout_merge_commit_rejected(self):
        with mock.patch.object(q.subprocess, "run") as runner:
            runner.return_value.stdout = "invalid-sha"
            with self.assertRaises(q.VerificationError):
                q.checked_out_merge_sha()

    def test_null_api_merge_with_valid_ancestry(self):
        alert, rows, pull = fixture()
        pull["merge_commit_sha"] = None
        q.verify(alert, rows, pull, SHA)
        q.verify_merge_ancestry(pull, merge_fixture(), SHA)

    def test_merge_parent_mismatch_rejected(self):
        _, _, pull = fixture()
        merge = merge_fixture()
        merge["parents"][1]["sha"] = "f" * 40
        with self.assertRaises(q.VerificationError):
            q.verify_merge_ancestry(pull, merge, SHA)

    def test_wrong_merge_object_sha_rejected(self):
        _, _, pull = fixture()
        merge = merge_fixture()
        merge["sha"] = "f" * 40
        with self.assertRaises(q.VerificationError):
            q.verify_merge_ancestry(pull, merge, SHA)
