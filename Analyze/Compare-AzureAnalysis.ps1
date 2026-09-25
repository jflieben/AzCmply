#Requires -Version 7.2
<#
    .SYNOPSIS
    Compares two analysis results (results.json from Invoke-AzureAnalyze.ps1) and reports what improved and what regressed.
    .DESCRIPTION
    Findings are matched on test id + resource id. Reports:
    - newFailures: failing now, not failing (or not present) before
    - resolved: failing before, demonstrably passing / not applicable / gone now
    - stillFailing: failing in both
    - lostVisibility: failing before, unknown now. The weakness was not fixed; the data needed to judge it
      was no longer collected, so this is a regression in coverage and never counts as resolved.
    - otherChanges: any other status change (for example Unknown to Pass)
    - test status changes, added and removed tests, tests whose logic version changed, posture score and framework control changes
    .PARAMETER Baseline
    Older results.json, or the folder containing it.
    .PARAMETER Current
    Newer results.json, or the folder containing it.
    .PARAMETER OutputPath
    Optional file to write the comparison to as JSON.
    .EXAMPLE
    .\Compare-AzureAnalysis.ps1 -Baseline .\AzureAnalysis\<sub>_20260901-080000 -Current .\AzureAnalysis\<sub>_20261001-080000 -OutputPath .\comparison.json
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.jsolve.nl
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Baseline,
    [Parameter(Mandatory = $true)][string]$Current,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Read-Results {
    param([string]$Path)
    if (Test-Path -Path $Path -PathType Container) { $Path = Join-Path $Path 'results.json' }
    return Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 100
}

function Get-FindingMap {
    #"testId|resourceId" (lowercase) -> finding with test context
    param($Results)
    $map = @{}
    foreach ($test in $Results.tests) {
        foreach ($finding in $test.findings) {
            $map["$($test.id)|$($finding.resourceId)".ToLowerInvariant()] = [pscustomobject]@{ testId = $test.id; title = $test.title; severity = $test.severity; resourceId = $finding.resourceId; resourceName = $finding.resourceName; status = $finding.status; detail = $finding.detail }
        }
    }
    return $map
}

$old = Read-Results $Baseline
$new = Read-Results $Current
if ($old.ingest.subscriptionId -ne $new.ingest.subscriptionId) { Write-Warning "Comparing different subscriptions: $($old.ingest.subscriptionId) and $($new.ingest.subscriptionId)" }

$oldFindings = Get-FindingMap $old
$newFindings = Get-FindingMap $new
$newFailures = [System.Collections.Generic.List[object]]::new()
$resolved = [System.Collections.Generic.List[object]]::new()
$stillFailing = [System.Collections.Generic.List[object]]::new()
$lostVisibility = [System.Collections.Generic.List[object]]::new()
$otherChanges = [System.Collections.Generic.List[object]]::new()
$oldTestIds = @($old.tests | ForEach-Object id)
$newTestIds = @($new.tests | ForEach-Object id)

foreach ($key in (@($oldFindings.Keys) + @($newFindings.Keys) | Sort-Object -Unique)) {
    $before = $oldFindings[$key]
    $after = $newFindings[$key]
    $item = if ($after) { $after } else { $before }
    $entry = [ordered]@{ testId = $item.testId; severity = $item.severity; resourceId = $item.resourceId; resourceName = $item.resourceName; from = if ($before) { $before.status } else { $null }; to = if ($after) { $after.status } else { $null }; detail = $item.detail }
    #findings of tests that only exist in one of the runs are reported as added/removed tests instead
    if ((-not $before -and $item.testId -notin $oldTestIds) -or (-not $after -and $item.testId -notin $newTestIds)) { continue }
    if ($after.status -eq 'Fail' -and $before.status -eq 'Fail') { $stillFailing.Add($entry) }
    elseif ($after.status -eq 'Fail') { $newFailures.Add($entry) }
    #a failure that turned Unknown was not fixed: the data needed to judge it is gone. Never report that as resolved.
    elseif ($before.status -eq 'Fail' -and $after.status -eq 'Unknown') { $lostVisibility.Add($entry) }
    elseif ($before.status -eq 'Fail') { $resolved.Add($entry) }
    elseif ($before -and $after -and $before.status -ne $after.status) { $otherChanges.Add($entry) }
}

$oldTests = @{}
foreach ($test in $old.tests) { $oldTests[$test.id] = $test }
$testChanges = foreach ($test in $new.tests) {
    $previous = $oldTests[$test.id]
    if ($previous -and ($previous.status -ne $test.status -or $previous.version -ne $test.version)) {
        [ordered]@{ id = $test.id; title = $test.title; severity = $test.severity; from = $previous.status; to = $test.status; logicChanged = ($previous.version -ne $test.version) }
    }
}

#controls are only compared within the same version of a framework
$controlChanges = foreach ($framework in $new.frameworks.PSObject.Properties.Name) {
    if (-not $old.frameworks.$framework -or $old.frameworks.$framework.version -ne $new.frameworks.$framework.version) { continue }
    foreach ($control in $new.frameworks.$framework.controls.PSObject.Properties) {
        $previous = $old.frameworks.$framework.controls.($control.Name)
        if ($previous -and $previous.status -ne $control.Value.status) { [ordered]@{ framework = $framework; control = $control.Name; from = $previous.status; to = $control.Value.status } }
    }
}

$comparison = [ordered]@{
    baseline     = [ordered]@{ folder = $old.ingest.folder; ingestStartedAt = $old.ingest.startedAt; analyzerVersion = $old.analyzer.version; postureScore = $old.summary.postureScore }
    current      = [ordered]@{ folder = $new.ingest.folder; ingestStartedAt = $new.ingest.startedAt; analyzerVersion = $new.analyzer.version; postureScore = $new.summary.postureScore }
    scoreDelta   = if ($null -ne $old.summary.postureScore -and $null -ne $new.summary.postureScore) { [math]::Round($new.summary.postureScore - $old.summary.postureScore, 1) } else { $null }
    counts         = [ordered]@{ newFailures = $newFailures.Count; resolved = $resolved.Count; stillFailing = $stillFailing.Count; lostVisibility = $lostVisibility.Count; otherChanges = $otherChanges.Count }
    tests          = [ordered]@{ changed = @($testChanges); added = @($newTestIds | Where-Object { $_ -notin $oldTestIds }); removed = @($oldTestIds | Where-Object { $_ -notin $newTestIds }) }
    frameworks     = @($controlChanges)
    newFailures    = @($newFailures)
    resolved       = @($resolved)
    stillFailing   = @($stillFailing)
    lostVisibility = @($lostVisibility)
    otherChanges   = @($otherChanges)
}

if ($OutputPath) {
    [System.IO.File]::WriteAllText($OutputPath, (($comparison | ConvertTo-Json -Depth 20) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
}
Write-Host "Posture score $($old.summary.postureScore) -> $($new.summary.postureScore) ($($comparison.scoreDelta)). New failures: $($newFailures.Count), resolved: $($resolved.Count), still failing: $($stillFailing.Count), lost visibility: $($lostVisibility.Count), other changes: $($otherChanges.Count)"
if ($lostVisibility.Count) { Write-Warning "$($lostVisibility.Count) finding(s) went from Fail to Unknown: the data needed to judge them was not collected this time, so the score is not comparable." }
[pscustomobject]$comparison
