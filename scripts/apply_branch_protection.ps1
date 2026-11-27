param(
    [switch]$SelfTest,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Repo = "milos-plavsic/enterprise-rag-system"
$Branch = "main"
$Root = Split-Path -Parent $PSScriptRoot
$PolicyPath = Join-Path $Root "security\main-branch-protection.json"

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)] [object]$Object,
        [Parameter(Mandatory = $true)] [string]$Name
    )
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $null
    }
    return $Property.Value
}

function Assert-ExactBoolean {
    param([object]$Value, [string]$Name)
    if ($Value -isnot [bool]) { throw "Invalid Boolean field: $Name" }
}

function Assert-ExactCheckSet {
    param([object]$Checks)
    $RequiredActions = @(
        "tests (3.11)", "tests (3.12)", "tests (3.13)", "static", "CodeQL (Python)",
        "CodeQL original TLS regression gate", "image", "reference",
        "Evaluate alpine-current", "Evaluate debian-bookworm", "Evaluate debian-trixie",
        "Evaluate docker-hardened-dev", "Evaluate chainguard-dev"
    )
    $Expected = @($RequiredActions | ForEach-Object { "$_|15368" }) + @("CodeQL|57789")
    $Actual = @()
    foreach ($Check in @($Checks)) {
        if ($null -eq $Check -or $Check.context -isnot [string] -or
            [string]::IsNullOrWhiteSpace($Check.context) -or
            ($Check.app_id -isnot [int] -and $Check.app_id -isnot [long])) {
            throw "Invalid required check identity"
        }
        $Actual += "$($Check.context)|$($Check.app_id)"
    }
    if ($Actual.Count -ne $Expected.Count -or
        @($Actual | Sort-Object -CaseSensitive -Unique).Count -ne $Actual.Count -or
        @(Compare-Object -ReferenceObject $Expected -DifferenceObject $Actual -CaseSensitive).Count -ne 0) {
        throw "Required check inventory or approved App identity differs"
    }
}

function Assert-PolicyRequestShape {
    param(
        [Parameter(Mandatory = $true)] [object]$Policy
    )

    $StatusChecks = $Policy.required_status_checks
    $HasContexts = $null -ne $StatusChecks.PSObject.Properties["contexts"]
    $HasChecks = $null -ne $StatusChecks.PSObject.Properties["checks"]

    if ($HasContexts -or -not $HasChecks) {
        throw "Canonical policy must use app-bound checks only."
    }
    Assert-ExactCheckSet $StatusChecks.checks
    Assert-ExactBoolean $StatusChecks.strict "strict"
    if (-not $StatusChecks.strict) { throw "Strict checks must be enabled" }
    foreach ($Name in @("enforce_admins", "required_linear_history", "allow_force_pushes",
        "allow_deletions", "block_creations", "required_conversation_resolution", "lock_branch", "allow_fork_syncing")) {
        Assert-ExactBoolean (Get-OptionalPropertyValue $Policy $Name) $Name
    }
    foreach ($Name in @("enforce_admins", "required_linear_history", "required_conversation_resolution")) {
        if (-not $Policy.$Name) { throw "Required control is disabled: $Name" }
    }
    foreach ($Name in @("allow_force_pushes", "allow_deletions", "block_creations", "lock_branch", "allow_fork_syncing")) {
        if ($Policy.$Name) { throw "Unexpected enabled control: $Name" }
    }
    $Reviews = $Policy.required_pull_request_reviews
    foreach ($Name in @("dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval")) {
        Assert-ExactBoolean (Get-OptionalPropertyValue $Reviews $Name) $Name
    }
    if (-not $Reviews.dismiss_stale_reviews -or -not $Reviews.require_last_push_approval -or
        $Reviews.required_approving_review_count -isnot [int] -and $Reviews.required_approving_review_count -isnot [long] -or
        $Reviews.required_approving_review_count -ne 1) {
        throw "Required review policy differs"
    }
    Assert-NoActors "dismissal restrictions" (Get-OptionalPropertyValue $Reviews "dismissal_restrictions")
    Assert-NoActors "pull-request bypass allowances" (Get-OptionalPropertyValue $Reviews "bypass_pull_request_allowances")
    if ($null -ne $Policy.restrictions) { throw "Unexpected push restrictions" }
}

function Assert-NoActors {
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [object]$Value
    )
    if ($null -eq $Value) {
        return
    }
    foreach ($ActorType in @("users", "teams", "apps")) {
        $Property = $Value.PSObject.Properties[$ActorType]
        if ($null -ne $Property -and @($Property.Value).Count -ne 0) {
            throw "Verification failed: $Name contains $ActorType bypass/dismissal actors."
        }
    }
}

function Assert-BranchProtectionMatchesPolicy {
    param(
        [Parameter(Mandatory = $true)] [object]$Expected,
        [Parameter(Mandatory = $true)] [object]$Actual,
        [Parameter(Mandatory = $true)] [object]$BranchState
    )

    Assert-ExactBoolean $BranchState.protected "protected"
    Assert-ExactCheckSet $Actual.required_status_checks.checks
    Assert-ExactBoolean $Actual.required_status_checks.strict "actual strict"
    Assert-ExactBoolean $Actual.enforce_admins.enabled "actual enforce_admins"
    if ($BranchState.protected -ne $true) {
        throw "Verification failed: main is not reported as protected."
    }

    if ([bool]$Actual.required_status_checks.strict -ne [bool]$Expected.required_status_checks.strict) {
        throw "Verification failed: strict/up-to-date status-check policy differs."
    }
    if ([bool]$Actual.enforce_admins.enabled -ne [bool]$Expected.enforce_admins) {
        throw "Verification failed: admin enforcement differs."
    }

    $ExpectedReviews = $Expected.required_pull_request_reviews
    $ActualReviews = $Actual.required_pull_request_reviews
    foreach ($Name in @("dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval")) {
        Assert-ExactBoolean (Get-OptionalPropertyValue $ActualReviews $Name) "actual $Name"
    }
    if ($ActualReviews.required_approving_review_count -isnot [int] -and $ActualReviews.required_approving_review_count -isnot [long]) {
        throw "Invalid actual review count"
    }
    if ([bool]$ActualReviews.dismiss_stale_reviews -ne [bool]$ExpectedReviews.dismiss_stale_reviews) {
        throw "Verification failed: stale-review dismissal differs."
    }
    if ([bool]$ActualReviews.require_code_owner_reviews -ne [bool]$ExpectedReviews.require_code_owner_reviews) {
        throw "Verification failed: code-owner review policy differs."
    }
    if ([int]$ActualReviews.required_approving_review_count -ne [int]$ExpectedReviews.required_approving_review_count) {
        throw "Verification failed: required approving-review count differs."
    }
    if ([bool]$ActualReviews.require_last_push_approval -ne [bool]$ExpectedReviews.require_last_push_approval) {
        throw "Verification failed: latest-push approval policy differs."
    }

    Assert-NoActors "dismissal restrictions" (Get-OptionalPropertyValue $ActualReviews "dismissal_restrictions")
    Assert-NoActors "pull-request bypass allowances" (Get-OptionalPropertyValue $ActualReviews "bypass_pull_request_allowances")

    if ($null -eq $Expected.restrictions) {
        $ActualRestrictions = Get-OptionalPropertyValue $Actual "restrictions"
        if ($null -ne $ActualRestrictions) {
            throw "Verification failed: push restrictions exist although canonical policy requires none."
        }
    }
    else {
        throw "Verification failed: verifier does not support non-null push restrictions."
    }

    $BooleanControls = @(
        @("required_linear_history", "required_linear_history"),
        @("allow_force_pushes", "allow_force_pushes"),
        @("allow_deletions", "allow_deletions"),
        @("block_creations", "block_creations"),
        @("required_conversation_resolution", "required_conversation_resolution"),
        @("lock_branch", "lock_branch"),
        @("allow_fork_syncing", "allow_fork_syncing")
    )
    foreach ($Control in $BooleanControls) {
        $ExpectedName = $Control[0]
        $ActualName = $Control[1]
        $ExpectedValue = [bool](Get-OptionalPropertyValue $Expected $ExpectedName)
        $ActualControl = Get-OptionalPropertyValue $Actual $ActualName
        if ($null -eq $ActualControl) {
            throw "Verification failed: GitHub response omitted $ActualName."
        }
        Assert-ExactBoolean $ActualControl.enabled "actual $ActualName"
        if ($ActualControl.enabled -ne $ExpectedValue) {
            throw "Verification failed: $ExpectedName differs from canonical policy."
        }
    }

    $ExpectedChecks = @(
        $Expected.required_status_checks.checks |
            ForEach-Object { "$($_.context)|$($_.app_id)" } |
            Sort-Object
    )
    $ActualChecks = @(
        $Actual.required_status_checks.checks |
            ForEach-Object { "$($_.context)|$($_.app_id)" } |
            Sort-Object
    )
    $Diff = @(Compare-Object -ReferenceObject $ExpectedChecks -DifferenceObject $ActualChecks -CaseSensitive)
    if ($Diff.Count -ne 0) {
        $Rendered = ($Diff | Out-String).Trim()
        throw "Verification failed: required status checks differ from policy.`n$Rendered"
    }
}

if (-not (Test-Path -LiteralPath $PolicyPath)) {
    throw "Missing canonical branch-protection policy: $PolicyPath"
}
$Expected = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json

Assert-PolicyRequestShape $Expected

if ($SelfTest) {
    $Fixture = [pscustomobject]@{
        required_status_checks = [pscustomobject]@{
            strict = [bool]$Expected.required_status_checks.strict
            checks = @($Expected.required_status_checks.checks)
        }
        enforce_admins = [pscustomobject]@{ enabled = [bool]$Expected.enforce_admins }
        required_pull_request_reviews = [pscustomobject]@{
            dismiss_stale_reviews = [bool]$Expected.required_pull_request_reviews.dismiss_stale_reviews
            require_code_owner_reviews = [bool]$Expected.required_pull_request_reviews.require_code_owner_reviews
            required_approving_review_count = [int]$Expected.required_pull_request_reviews.required_approving_review_count
            require_last_push_approval = [bool]$Expected.required_pull_request_reviews.require_last_push_approval
            dismissal_restrictions = [pscustomobject]@{ users = @(); teams = @(); apps = @() }
            bypass_pull_request_allowances = [pscustomobject]@{ users = @(); teams = @(); apps = @() }
        }
        restrictions = $null
        required_linear_history = [pscustomobject]@{ enabled = [bool]$Expected.required_linear_history }
        allow_force_pushes = [pscustomobject]@{ enabled = [bool]$Expected.allow_force_pushes }
        allow_deletions = [pscustomobject]@{ enabled = [bool]$Expected.allow_deletions }
        block_creations = [pscustomobject]@{ enabled = [bool]$Expected.block_creations }
        required_conversation_resolution = [pscustomobject]@{ enabled = [bool]$Expected.required_conversation_resolution }
        lock_branch = [pscustomobject]@{ enabled = [bool]$Expected.lock_branch }
        allow_fork_syncing = [pscustomobject]@{ enabled = [bool]$Expected.allow_fork_syncing }
    }
    $BranchFixture = [pscustomobject]@{ protected = $true }

    Assert-BranchProtectionMatchesPolicy $Expected $Fixture $BranchFixture

    $Cases = @(
        @{ Name = "strict"; Apply = { param($x) $x.required_status_checks.strict = -not $x.required_status_checks.strict } },
        @{ Name = "enforce_admins"; Apply = { param($x) $x.enforce_admins.enabled = -not $x.enforce_admins.enabled } },
        @{ Name = "dismiss_stale_reviews"; Apply = { param($x) $x.required_pull_request_reviews.dismiss_stale_reviews = -not $x.required_pull_request_reviews.dismiss_stale_reviews } },
        @{ Name = "require_code_owner_reviews"; Apply = { param($x) $x.required_pull_request_reviews.require_code_owner_reviews = -not $x.required_pull_request_reviews.require_code_owner_reviews } },
        @{ Name = "required_approving_review_count"; Apply = { param($x) $x.required_pull_request_reviews.required_approving_review_count = 0 } },
        @{ Name = "require_last_push_approval"; Apply = { param($x) $x.required_pull_request_reviews.require_last_push_approval = -not $x.required_pull_request_reviews.require_last_push_approval } },
        @{ Name = "dismissal_restrictions"; Apply = { param($x) $x.required_pull_request_reviews.dismissal_restrictions.users = @("unexpected") } },
        @{ Name = "bypass_pull_request_allowances"; Apply = { param($x) $x.required_pull_request_reviews.bypass_pull_request_allowances.apps = @("unexpected") } },
        @{ Name = "restrictions"; Apply = { param($x) $x.restrictions = [pscustomobject]@{ users = @("unexpected"); teams = @(); apps = @() } } },
        @{ Name = "required_linear_history"; Apply = { param($x) $x.required_linear_history.enabled = -not $x.required_linear_history.enabled } },
        @{ Name = "allow_force_pushes"; Apply = { param($x) $x.allow_force_pushes.enabled = -not $x.allow_force_pushes.enabled } },
        @{ Name = "allow_deletions"; Apply = { param($x) $x.allow_deletions.enabled = -not $x.allow_deletions.enabled } },
        @{ Name = "block_creations"; Apply = { param($x) $x.block_creations.enabled = -not $x.block_creations.enabled } },
        @{ Name = "required_conversation_resolution"; Apply = { param($x) $x.required_conversation_resolution.enabled = -not $x.required_conversation_resolution.enabled } },
        @{ Name = "lock_branch"; Apply = { param($x) $x.lock_branch.enabled = -not $x.lock_branch.enabled } },
        @{ Name = "allow_fork_syncing"; Apply = { param($x) $x.allow_fork_syncing.enabled = -not $x.allow_fork_syncing.enabled } },
        @{ Name = "required_checks"; Apply = { param($x) $x.required_status_checks.checks = @($x.required_status_checks.checks | Select-Object -Skip 1) } }
    )

    foreach ($Case in $Cases) {
        $Candidate = $Fixture | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        & $Case.Apply $Candidate
        $Rejected = $false
        try {
            Assert-BranchProtectionMatchesPolicy $Expected $Candidate $BranchFixture
        }
        catch {
            $Rejected = $true
        }
        if (-not $Rejected) {
            throw "Self-test failed: verifier accepted mutated field '$($Case.Name)'."
        }
    }

    # Canonical requests must be rejected before any mutation, not just on readback.
    $InvalidRequests = @(
        @{ Name = "wildcard App"; Apply = { param($x) $x.required_status_checks.checks[0].app_id = -1 } },
        @{ Name = "wrong App"; Apply = { param($x) $x.required_status_checks.checks[0].app_id = 57789 } },
        @{ Name = "string App"; Apply = { param($x) $x.required_status_checks.checks[0].app_id = "15368" } },
        @{ Name = "duplicate context"; Apply = { param($x) $x.required_status_checks.checks[1] = $x.required_status_checks.checks[0] } },
        @{ Name = "string Boolean"; Apply = { param($x) $x.enforce_admins = "true" } },
        @{ Name = "disabled strict"; Apply = { param($x) $x.required_status_checks.strict = $false } },
        @{ Name = "missing check"; Apply = { param($x) $x.required_status_checks.checks = @($x.required_status_checks.checks | Select-Object -Skip 1) } }
    )
    foreach ($Case in $InvalidRequests) {
        $Candidate = $Expected | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        & $Case.Apply $Candidate
        $Rejected = $false
        try { Assert-PolicyRequestShape $Candidate } catch { $Rejected = $true }
        if (-not $Rejected) { throw "Self-test accepted invalid request: $($Case.Name)" }
    }

    $BadActual = $Fixture | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $BadActual.enforce_admins.enabled = "true"
    $Rejected = $false
    try { Assert-BranchProtectionMatchesPolicy $Expected $BadActual $BranchFixture } catch { $Rejected = $true }
    if (-not $Rejected) { throw "Self-test accepted non-Boolean readback" }

    $OmittedNullFixture = $Fixture | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $OmittedNullFixture.PSObject.Properties.Remove("restrictions")
    Assert-BranchProtectionMatchesPolicy $Expected $OmittedNullFixture $BranchFixture

    $UnprotectedBranch = [pscustomobject]@{ protected = $false }
    $Rejected = $false
    try {
        Assert-BranchProtectionMatchesPolicy $Expected $Fixture $UnprotectedBranch
    }
    catch {
        $Rejected = $true
    }
    if (-not $Rejected) {
        throw "Self-test failed: verifier accepted an unprotected main branch."
    }

    Write-Host "SELF-TEST VERIFIED: branch-protection readback rejects every canonical policy drift case."
    exit 0
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required."
}

& gh auth status --hostname github.com 1>$null
if ($LASTEXITCODE -ne 0) {
    throw "GitHub CLI is not authenticated for github.com."
}

if (-not $VerifyOnly) {
Write-Host "Applying canonical protection policy to $Repo/$Branch..."
& gh api `
    --method PUT `
    -H "Accept: application/vnd.github+json" `
    -H "X-GitHub-Api-Version: 2026-03-10" `
    "repos/$Repo/branches/$Branch/protection" `
    --input $PolicyPath 1>$null
if ($LASTEXITCODE -ne 0) {
    throw "GitHub rejected the branch-protection update."
}
} else {
    Write-Host "Read-only verification of $Repo/$Branch..."
}

$ActualRaw = & gh api `
    -H "Accept: application/vnd.github+json" `
    -H "X-GitHub-Api-Version: 2026-03-10" `
    "repos/$Repo/branches/$Branch/protection"
if ($LASTEXITCODE -ne 0) {
    throw "Could not read back branch protection."
}
$Actual = $ActualRaw | ConvertFrom-Json

$BranchRaw = & gh api `
    -H "Accept: application/vnd.github+json" `
    -H "X-GitHub-Api-Version: 2026-03-10" `
    "repos/$Repo/branches/$Branch"
if ($LASTEXITCODE -ne 0) {
    throw "Could not read back branch metadata."
}
$BranchState = $BranchRaw | ConvertFrom-Json

Assert-BranchProtectionMatchesPolicy $Expected $Actual $BranchState

$ActualChecks = @(
    $Actual.required_status_checks.checks |
        ForEach-Object { "$($_.context)|$($_.app_id)" } |
        Sort-Object
)

Write-Host "VERIFIED: main branch protection exactly matches security/main-branch-protection.json"
Write-Host "Required checks: $($ActualChecks.Count); strict=true; admins enforced; reviews/latest-push approval enforced; no bypass actors; force-push/deletion disabled."
