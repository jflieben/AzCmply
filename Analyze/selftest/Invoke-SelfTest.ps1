#Requires -Version 7.2
<#
    .SYNOPSIS
    Verifies the test suite against synthetic ingestions: every test must pass on the compliant fixture and fail on the non-compliant one,
    no test may error, and analysing the same ingestion twice must give identical output.
    .PARAMETER WorkPath
    Folder for fixtures and results. Default: a folder in the temp directory.
#>
[CmdletBinding()]
Param([string]$WorkPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'azanalyze-selftest'))

$ErrorActionPreference = 'Stop'
$analyzer = Join-Path (Split-Path $PSScriptRoot) 'Invoke-AzureAnalyze.ps1'
$generator = Join-Path $PSScriptRoot 'New-FixtureIngest.ps1'

#statuses that differ from the default because one fixture cannot satisfy two dependent tests at the same time.
#AZ-KV-005/006 and AZ-KV-010/011 are the RBAC and access policy halves of the same CIS recommendations: a vault has one
#permission model, and a compliant fixture uses RBAC (AZ-KV-002), so the access policy half has nothing in scope there.
$expectedOverrides = @{
    #AZ-NET-023 only applies to machines whose management ports are open to the Internet, which a compliant fixture has none of
    Good = @{ 'AZ-KV-009' = 'NotApplicable'; 'AZ-KV-010' = 'NotApplicable'; 'AZ-KV-011' = 'NotApplicable'; 'AZ-NET-023' = 'NotApplicable' }
    #AZ-IAM-026 fails only without enabled Conditional Access policies, and AZ-IAM-028 needs them to fail; without a Bastion (AZ-NET-011) there is no shareable link (AZ-NET-027)
    Bad  = @{ 'AZ-GOV-001' = 'Pass'; 'AZ-LOG-001' = 'Pass'; 'AZ-KV-005' = 'NotApplicable'; 'AZ-KV-006' = 'NotApplicable'; 'AZ-IAM-026' = 'NotApplicable'; 'AZ-NET-027' = 'NotApplicable' }
}

$problems = [System.Collections.Generic.List[string]]::new()
$results = @{}
foreach ($mode in 'Good', 'Bad') {
    $fixture = Join-Path $WorkPath "fixture-$mode"
    & $generator -Path $fixture -Mode $mode
    $null = & $analyzer -IngestPath $fixture -OutputPath (Join-Path $WorkPath 'results') -FolderName $mode 6>$null
    $results[$mode] = Get-Content (Join-Path $WorkPath "results\$mode\results.json") -Raw | ConvertFrom-Json
    $default = if ($mode -eq 'Good') { 'Pass' } else { 'Fail' }
    foreach ($test in $results[$mode].tests) {
        $expected = if ($expectedOverrides[$mode].ContainsKey($test.id)) { $expectedOverrides[$mode][$test.id] } else { $default }
        if ($test.status -ne $expected) {
            $sample = $test.findings | Where-Object { $_.status -ne $expected } | Select-Object -First 1
            $problems.Add("[$mode] $($test.id) is $($test.status), expected $expected. $($test.statusReason)$(if ($sample) { " e.g. $($sample.resourceName): $($sample.detail)" })")
        }
    }
}

#determinism: a second analysis of the same ingestion must be identical apart from analyzedAt
$null = & $analyzer -IngestPath (Join-Path $WorkPath 'fixture-Good') -OutputPath (Join-Path $WorkPath 'rerun') -FolderName 'Good' 6>$null
$first = (Get-Content (Join-Path $WorkPath 'results\Good\results.json')) -notmatch '"analyzedAt"'
$second = (Get-Content (Join-Path $WorkPath 'rerun\Good\results.json')) -notmatch '"analyzedAt"'
if (Compare-Object $first $second -SyncWindow 0) { $problems.Add('Analysing the same ingestion twice produced different results.json content') }
foreach ($file in 'findings.csv', 'tests.csv') {
    if ((Get-FileHash (Join-Path $WorkPath "results\Good\$file")).Hash -ne (Get-FileHash (Join-Path $WorkPath "rerun\Good\$file")).Hash) { $problems.Add("$file differs between identical analyses") }
}

#missing data must never read as compliance: re-analyse the non-compliant fixture with each ingestion file removed in
#turn, and with every child resource call marked as failed, and check that no failing test turns into a passing one
$baseline = @{}
foreach ($test in $results.Bad.tests) { $baseline[$test.id] = $test.status }

function Test-Degraded {
    param([string]$Label, [string]$Path)
    $status = @{}
    $null = & $analyzer -IngestPath $Path -OutputPath (Join-Path $WorkPath 'degraded') -FolderName 'run' 6>$null 3>$null
    foreach ($test in (Get-Content (Join-Path $WorkPath 'degraded\run\results.json') -Raw | ConvertFrom-Json).tests) {
        if ($baseline[$test.id] -eq 'Fail' -and $test.status -eq 'Pass') { $problems.Add("[$Label] $($test.id) turns a real failure into a pass when the data it needs is missing; it should report Unknown") }
        if ($test.status -eq 'Error') { $problems.Add("[$Label] $($test.id) errored: $($test.statusReason)") }
        $status[$test.id] = $test.status
    }
    return $status
}

$degradedRoot = Join-Path $WorkPath 'degraded-input'
$badFixture = (Resolve-Path (Join-Path $WorkPath 'fixture-Bad')).Path
#only the shared section files: removing a per resource file means the resource is not there, which is a different
#thing from its data being unreadable, and the index would no longer match the folder either
$dataFiles = @(Get-ChildItem $badFixture -Recurse -Filter '*.json' -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($badFixture, $_.FullName)
    } | Where-Object {
        ($_ -split '[\\/]')[0] -notin 'resources', 'resourceGroups' -and (Split-Path $_ -Leaf) -notin 'manifest.json', 'index.json'
    })
if (-not $dataFiles.Count) { $problems.Add('No ingestion section files found to test degraded collection against') }

foreach ($relative in $dataFiles) {
    if (Test-Path $degradedRoot) { Remove-Item $degradedRoot -Recurse -Force }
    Copy-Item $badFixture $degradedRoot -Recurse
    Remove-Item (Join-Path $degradedRoot $relative) -Force
    $null = Test-Degraded -Label "without $relative" -Path $degradedRoot
}

#every child resource present but null, which is how the ingestion records a failed child call
if (Test-Path $degradedRoot) { Remove-Item $degradedRoot -Recurse -Force }
Copy-Item $badFixture $degradedRoot -Recurse
foreach ($file in (Get-ChildItem (Join-Path $degradedRoot 'resources') -Recurse -Filter '*.json' -File)) {
    $record = Get-Content $file.FullName -Raw | ConvertFrom-Json
    if ($null -eq $record.children) { continue }
    foreach ($name in @($record.children.PSObject.Properties.Name)) {
        if (-not $name) { continue }
        $record.children.PSObject.Properties.Remove($name)
        $record.children | Add-Member -NotePropertyName $name -NotePropertyValue $null -Force
    }
    $record | ConvertTo-Json -Depth 60 | Set-Content $file.FullName -Encoding utf8
}
$null = Test-Degraded -Label 'with every child call failed' -Path $degradedRoot

$testCount = @($results.Good.tests).Count
if ($problems.Count) {
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    throw "Self-test failed: $($problems.Count) problem(s) across $testCount tests"
}
Write-Host "Self-test passed: $testCount tests pass on the compliant fixture, fail on the non-compliant fixture, output is deterministic, and no test reports a pass when the data it needs is missing ($($dataFiles.Count + 1) degraded runs)." -ForegroundColor Green
