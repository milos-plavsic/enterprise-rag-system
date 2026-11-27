# Independent acceptance boundary

The GitHub Actions App ID binds a check to an integration, not to a trusted
workflow implementation. Candidate-controlled YAML and scripts must never
be the sole source of authorization to merge.

## External gate contract

Use an organization/enterprise ruleset requiring workflows from a separate
security-controlled repository, or a separately controlled GitHub App check
producer. The repository is currently a personal repository; the latter
requires an installed, independently administered App and credentials
unavailable to this repository's workflows. Do not use a candidate workflow
or a shared GitHub Actions App to impersonate that separate control.

The independently reviewed copy of `scripts/verify_trusted_acceptance.py`
is an execution-evidence validator for the external runner. Store the
validator and independent approval record outside the candidate repository.
The approval must identify the entire source tree, exact head and exact base,
not just the workflow filenames. Execute the validator with read-only
repository, Actions and checks access:

```bash
python3 verify_trusted_acceptance.py 12 \
  --approved-head "$REVIEWED_HEAD" \
  --approved-base "$REVIEWED_BASE" \
  --trusted-reviewer-login "$TRUSTED_REVIEWER_LOGIN" \
  --trusted-reviewer-id "$TRUSTED_REVIEWER_ID"
```

The program requires an exact-head GitHub approval from a separately authorised, non-author reviewer using both the trusted login and immutable numeric GitHub identity; newer change requests or comments invalidate that acceptance. The approved reviewer identity must be selected outside the candidate repository, and a GitHub approval cannot itself prove that an independent high-reasoning agent performed the review. The program also checks current PR identity, merge ancestry, base protection,
expected workflow IDs and paths, actual PR association, latest attempt jobs,
check identity and App IDs. It rejects skipped, neutral, incomplete,
ambiguous or stale mandatory checks. Base evaluation remains evidence
collection, not a successful security disposition. CodeQL default-branch
closure and artifact attestations are separate post-merge release gates.

The external check publisher must write its own app-bound check only after
this validator, independent full-source review, and other required evidence
all succeed. It must bind the check to the exact approved head, publish
failure on uncertainty, and never accept candidate-produced approval
records. The independently controlled check must be configured as required
on main; no bypass actor should be allowed. Exercise adverse cases
(skipped workflow, duplicate check, incorrect App, altered test, stale
approval and race with a new commit) in an isolated repository before
enabling the control.

No independent App, organization ruleset, or independent reviewer has been
provisioned by these code changes. The existing protection remains enabled
and must not be weakened. Administrative readback of every required control
is mandatory; run the reviewed copy of `scripts/apply_branch_protection.ps1
-VerifyOnly` using authorized administrative credentials. Do not accept
this document or unit tests as proof that live external enforcement exists.

References: [GitHub ruleset workflow rules](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets),
[GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

## PR identity boundary

The original TLS PR is #10; the remediation candidate is PR #12. Independent approval must bind the exact PR #12 head and base to independently controlled evidence. Passing candidate-defined Actions checks does not authorize merging a draft PR.

The verifier's stdout deliberately does not repeat the external reviewer's login or numeric account ID; the trusted caller retains those values privately and correlates the returned GitHub review ID. This prevents review-identity configuration supplied as CLI input from leaking to potentially public Actions logs.
