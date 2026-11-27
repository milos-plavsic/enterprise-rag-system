import copy
import pytest
from scripts.verify_trusted_acceptance import verify, WORKFLOWS, PREFIX, REPO

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40
REVIEWER_LOGIN, REVIEWER_ID, AUTHOR_ID = "independent-reviewer", 987654, 123456


def fixture():
    pull = {"number": 10, "state": "open", "draft": False,
            "user": {"id": AUTHOR_ID, "login": "pr-author"}, "head": {"sha": HEAD},
            "base": {"sha": BASE, "ref": "main", "repo": {"full_name": REPO}},
            "merge_commit_sha": MERGE}
    reviews = [{"id": 800, "user": {"id": REVIEWER_ID, "login": REVIEWER_LOGIN},
                "state": "APPROVED", "commit_id": HEAD,
                "submitted_at": "2026-11-27T14:00:00Z"}]
    runs, checks, jobs = [], [], {}
    number = 100
    for path, (wid, names) in WORKFLOWS.items():
        rid = number
        number += 1
        runs.append({"id": rid, "path": path, "workflow_id": wid, "head_sha": HEAD,
                     "event": "pull_request", "repository": {"full_name": REPO}, "status": "completed",
                     "conclusion": "success", "run_attempt": 1, "pull_requests": [pull]})
        jobs[rid] = []
        for name in sorted(names):
            jid = number
            number += 1
            url = f"https://github.com/{REPO}/actions/runs/{rid}/job/{jid}"
            jobs[rid].append({"id": jid, "name": name, "run_id": rid, "status": "completed",
                              "conclusion": "success", "html_url": url})
            checks.append({"id": jid, "name": name, "head_sha": HEAD, "app": {"id": 15368},
                           "status": "completed", "conclusion": "success", "details_url": url})
    checks.append({"id": number, "name": "CodeQL", "head_sha": HEAD, "app": {"id": 57789},
                   "status": "completed", "conclusion": "success"})

    def get(path):
        path = path.removeprefix(PREFIX).split("?")[0]
        if path == "pulls/10":
            return pull
        if path == "pulls/10/reviews":
            return reviews
        if path == "branches/main":
            return {"protected": True, "commit": {"sha": BASE}}
        if path == f"git/commits/{MERGE}":
            return {"sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]}
        if path == f"commits/{HEAD}/check-runs":
            return {"total_count": len(checks), "check_runs": checks}
        if path == "actions/runs":
            return {"total_count": len(runs), "workflow_runs": runs}
        rows = jobs[int(path.split("/")[2])]
        return {"total_count": len(rows), "jobs": rows}
    return get, pull, runs, checks, jobs, reviews


def test_valid_exact_head():
    get, *_ = fixture()
    result = verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, REVIEWER_ID)
    assert len(result["verified_jobs"]) == 13


@pytest.mark.parametrize("case", ["wrong_app", "skipped", "neutral", "spoofed_url", "duplicate",
                                  "wrong_workflow", "wrong_pr", "wrong_base", "missing_job"])
def test_reject_ambiguous_or_unsuccessful_evidence(case):
    get, pull, runs, checks, jobs, reviews = fixture()
    if case == "wrong_app":
        checks[0]["app"]["id"] = 1
    elif case == "skipped":
        next(iter(jobs.values()))[0]["conclusion"] = "skipped"
    elif case == "neutral":
        checks[0]["conclusion"] = "neutral"
    elif case == "spoofed_url":
        checks[0]["details_url"] += "/other"
    elif case == "duplicate":
        other = copy.deepcopy(checks[0])
        other["id"] = 9999
        checks.append(other)
    elif case == "wrong_workflow":
        runs[0]["workflow_id"] += 1
    elif case == "wrong_pr":
        runs[0]["pull_requests"] = []
    elif case == "wrong_base":
        pull["base"]["sha"] = "d" * 40
    else:
        next(iter(jobs.values())).pop()
    with pytest.raises(ValueError):
        verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, REVIEWER_ID)

def test_separate_push_check_same_name_does_not_mask_exact_pr_job():
    get, pull, runs, checks, jobs, reviews = fixture()
    other = copy.deepcopy(checks[0])
    other["id"] = 98765
    other["details_url"] = "https://github.com/" + REPO + "/actions/runs/99/job/100"
    checks.append(other)
    assert len(verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, REVIEWER_ID)["verified_jobs"]) == 13


def test_same_job_url_duplicate_still_fails():
    get, pull, runs, checks, jobs, reviews = fixture()
    other = copy.deepcopy(checks[0])
    other["id"] = 98765
    checks.append(other)
    with pytest.raises(ValueError, match="ambiguous"):
        verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, REVIEWER_ID)



@pytest.mark.parametrize("mutation", [
    "no_review", "self_review", "different_id", "different_login", "stale_commit",
    "dismissed", "changed_requested", "later_comment", "wrong_user_record", "no_timestamp",
    "duplicate_review_id",
])
def test_independent_review_must_approve_exact_current_commit(mutation):
    get, pull, runs, checks, jobs, reviews = fixture()
    trusted_id = REVIEWER_ID
    if mutation == "no_review":
        reviews.clear()
    elif mutation == "self_review":
        pull["user"]["id"] = REVIEWER_ID
    elif mutation == "different_id":
        trusted_id = REVIEWER_ID + 1
    elif mutation == "different_login":
        reviews[0]["user"]["login"] = "untrusted"
    elif mutation == "stale_commit":
        reviews[0]["commit_id"] = "d" * 40
    elif mutation == "dismissed":
        reviews[0]["state"] = "DISMISSED"
    elif mutation == "changed_requested":
        reviews.append({"id": 801, "user": {"id": REVIEWER_ID, "login": REVIEWER_LOGIN},
                        "state": "CHANGES_REQUESTED", "commit_id": HEAD,
                        "submitted_at": "2026-11-27T14:01:00Z"})
    elif mutation == "later_comment":
        reviews.append({"id": 801, "user": {"id": REVIEWER_ID, "login": REVIEWER_LOGIN},
                        "state": "COMMENTED", "commit_id": HEAD,
                        "submitted_at": "2026-11-27T14:01:00Z"})
    elif mutation == "wrong_user_record":
        reviews[0]["user"] = {"login": REVIEWER_LOGIN}
    elif mutation == "no_timestamp":
        reviews[0].pop("submitted_at")
    else:
        reviews.append(copy.deepcopy(reviews[0]))
    with pytest.raises(ValueError):
        verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, trusted_id)


def test_trusted_reviewer_review_is_reported():
    get, *_ = fixture()
    result = verify(get, 10, HEAD, BASE, REVIEWER_LOGIN, REVIEWER_ID)
    assert result["trusted_review"] == {
        "review_id": 800, "reviewer_id": REVIEWER_ID,
        "reviewer_login": REVIEWER_LOGIN, "submitted_at": "2026-11-27T14:00:00Z"}
