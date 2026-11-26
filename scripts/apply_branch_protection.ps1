$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Repo = "milos-plavsic/enterprise-rag-system"
$Branch = "main"
$Root = Split-Path -Parent $PSScriptRoot
$PolicyPath = Join-Path $Root "security\main-branch-protection.json"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required."
}
if (-not (Test-Path -LiteralPath $PolicyPath)) {
    throw "Missing canonical branch-protection policy: $PolicyPath"
}

& gh auth status --hostname github.com 1>$null
if ($LASTEXITCODE -ne 0) {
    throw "GitHub CLI is not authenticated for github.com."
}

$Expected = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json

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

if ($BranchState.protected -ne $true) {
    throw "Verification failed: main is not reported as protected."
}
if ($Actual.required_status_checks.strict -ne $true) {
    throw "Verification failed: strict/up-to-date status checks are not enabled."
}
if ($Actual.enforce_admins.enabled -ne $true) {
    throw "Verification failed: admin enforcement is not enabled."
}
if ($Actual.required_pull_request_reviews.dismiss_stale_reviews -ne $true) {
    throw "Verification failed: stale review dismissal is not enabled."
}
if ([int]$Actual.required_pull_request_reviews.required_approving_review_count -ne 1) {
    throw "Verification failed: exactly one approving review is not required."
}
if ($Actual.required_pull_request_reviews.require_last_push_approval -ne $true) {
    throw "Verification failed: latest-push approval is not required."
}
if ($Actual.required_conversation_resolution.enabled -ne $true) {
    throw "Verification failed: conversation resolution is not required."
}
if ($Actual.required_linear_history.enabled -ne $true) {
    throw "Verification failed: linear history is not required."
}
if ($Actual.allow_force_pushes.enabled -ne $false) {
    throw "Verification failed: force pushes are allowed."
}
if ($Actual.allow_deletions.enabled -ne $false) {
    throw "Verification failed: branch deletion is allowed."
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
$Diff = @(Compare-Object -ReferenceObject $ExpectedChecks -DifferenceObject $ActualChecks)
if ($Diff.Count -ne 0) {
    $Rendered = ($Diff | Out-String).Trim()
    throw "Verification failed: required status checks differ from policy.`n$Rendered"
}

Write-Host "VERIFIED: main branch protection exactly matches security/main-branch-protection.json"
Write-Host "Required checks: $($ActualChecks.Count); strict=true; admins enforced; reviews and latest-push approval required; force-push/deletion disabled."
