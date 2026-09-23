#Requires -Version 7.2
<#
    .SYNOPSIS
    Compares the browser ingestion with the PowerShell ingestion on a live subscription.
    .DESCRIPTION
    Runs Ingest\Invoke-AzureIngest.ps1 and the browser ingestion (site\js\ingest.js, in node) with the same service
    principal against the same subscription, one after the other, and compares:
    - the files written (same layout and file names)
    - index.json: every resource with its type, file, api version and status
    - the status of every section in manifest.json
    - per resource: whether the resource, its diagnostic settings and every child resource were read or failed
    - the analysis of both ingestions (by the PowerShell analyzer): the status of every test
    Data that changes by the minute (alerts, activity log events, counts) is reported, not failed on.
    .PARAMETER CredentialsPath
    File with 'key: value' lines: appid, tenantid, secret, subscriptionid. Default Ingest\creds.local. Values are never printed.
    .PARAMETER ActivityLogDays
    Days of activity log to collect on both sides. Default 3.
    .PARAMETER Node
    Path to node.exe (or the AZCMPLY_NODE environment variable, or node on the PATH).
    .PARAMETER KeepOutput
    Keeps the working folder and prints its path.
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [string]$CredentialsPath,
    [int]$ActivityLogDays = 3,
    [string]$Node,
    [switch]$KeepOutput
)

$ErrorActionPreference = 'Stop'
$web = Split-Path -Path $PSScriptRoot -Parent
$repo = Split-Path -Path $web -Parent
if (-not $CredentialsPath) { $CredentialsPath = Join-Path $repo 'Ingest\creds.local' }
if (-not $Node) { $Node = $env:AZCMPLY_NODE }
if (-not $Node) { $Node = (Get-Command node -ErrorAction SilentlyContinue).Source }
if (-not $Node -or -not (Test-Path $Node)) { throw 'node was not found; pass -Node or set AZCMPLY_NODE' }

$settings = @{}
foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path $CredentialsPath).Path)) {
    if ($line -match '^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$') { $settings[$Matches[1].ToLowerInvariant()] = $Matches[2] }
}
foreach ($key in 'appid', 'tenantid', 'secret', 'subscriptionid') { if (-not $settings[$key]) { throw "The credentials file has no '$key'" } }
$secret = ConvertTo-SecureString -String $settings.secret -AsPlainText -Force
$settings.Remove('secret')

$failures = [System.Collections.Generic.List[string]]::new()
function Write-Result {
    param([string]$Name, [bool]$Ok, [string[]]$Detail)
    if ($Ok) { Write-Host "  PASS  $Name" -ForegroundColor Green; return }
    Write-Host "  FAIL  $Name" -ForegroundColor Red
    $Detail | Select-Object -First 15 | ForEach-Object { Write-Host "        $_" }
    if ($Detail.Count -gt 15) { Write-Host "        and $($Detail.Count - 15) more" }
    $failures.Add($Name)
}
function Read-Json { param([string]$Path) if (-not (Test-Path $Path)) { return $null }; return Get-Content $Path -Raw | ConvertFrom-Json -Depth 100 -DateKind String }

$work = Join-Path ([System.IO.Path]::GetTempPath()) "azcmply-ingest-parity-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Force -Path $work
try {
    Write-Host 'PowerShell ingestion'
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $null = & (Join-Path $repo 'Ingest\Invoke-AzureIngest.ps1') -SubscriptionId $settings.subscriptionid -TenantId $settings.tenantid -ClientId $settings.appid -ClientSecret $secret -OutputPath $work -FolderName 'ps' -ActivityLogDays $ActivityLogDays 6>$null 3>$null
    Write-Host "        $([int]$timer.Elapsed.TotalSeconds) s"
    Write-Host 'Browser ingestion'
    $timer.Restart()
    $output = & $Node (Join-Path $PSScriptRoot 'ingest-node.mjs') (Resolve-Path $CredentialsPath).Path $work 'web' $ActivityLogDays 2>&1
    if ($LASTEXITCODE -ne 0) { throw "The browser ingestion failed:`n$($output | Out-String)" }
    Write-Host "        $([int]$timer.Elapsed.TotalSeconds) s"

    $ps = Join-Path $work 'ps'
    $js = Join-Path $work 'web'

    Write-Host 'Files'
    $psFiles = @(Get-ChildItem $ps -Recurse -File | ForEach-Object { [System.IO.Path]::GetRelativePath($ps, $_.FullName).Replace('\', '/') } | Sort-Object)
    $jsFiles = @(Get-ChildItem $js -Recurse -File | ForEach-Object { [System.IO.Path]::GetRelativePath($js, $_.FullName).Replace('\', '/') } | Sort-Object)
    $fileDiff = @(Compare-Object $psFiles $jsFiles | ForEach-Object { "$(if ($_.SideIndicator -eq '<=') { 'only PowerShell' } else { 'only browser' }): $($_.InputObject)" })
    Write-Result -Name "same $($psFiles.Count) files" -Ok (-not $fileDiff.Count) -Detail $fileDiff

    Write-Host 'Index'
    $key = { "$($_.id.ToLowerInvariant())|$($_.type)|$($_.file)|$($_.apiVersion)|$($_.status)" }
    $indexDiff = @(Compare-Object @((Read-Json "$ps/index.json") | ForEach-Object $key | Sort-Object) @((Read-Json "$js/index.json") | ForEach-Object $key | Sort-Object) | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
    Write-Result -Name 'index.json entries' -Ok (-not $indexDiff.Count) -Detail $indexDiff

    Write-Host 'Sections'
    $psManifest = Read-Json "$ps/manifest.json"
    $jsManifest = Read-Json "$js/manifest.json"
    $names = @(@($psManifest.sections.PSObject.Properties.Name) + @($jsManifest.sections.PSObject.Properties.Name) | Sort-Object -Unique)
    $sectionDiff = [System.Collections.Generic.List[string]]::new()
    $countNotes = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $names) {
        $a = $psManifest.sections.$name
        $b = $jsManifest.sections.$name
        if ($a.status -ne $b.status) { $sectionDiff.Add("$name`: PowerShell $($a.status), browser $($b.status)") }
        elseif ($a.count -ne $b.count) { $countNotes.Add("$name`: $($a.count) / $($b.count)") }
    }
    Write-Result -Name "$($names.Count) section statuses" -Ok (-not $sectionDiff.Count) -Detail $sectionDiff
    if ($countNotes.Count) { Write-Host "        counts that differ (data changes between the runs): $($countNotes -join '; ')" }

    Write-Host 'Resources'
    $resourceDiff = [System.Collections.Generic.List[string]]::new()
    foreach ($file in ($psFiles | Where-Object { $_ -like 'resources/*' -and $_ -in $jsFiles })) {
        $a = Read-Json "$ps/$file"
        $b = Read-Json "$js/$file"
        if (($null -eq $a.resource) -ne ($null -eq $b.resource)) { $resourceDiff.Add("$file`: resource read on one side only") }
        if (($null -eq $a.diagnosticSettings) -ne ($null -eq $b.diagnosticSettings)) { $resourceDiff.Add("$file`: diagnostic settings read on one side only") }
        $childNames = @(@($a.children.PSObject.Properties.Name) + @($b.children.PSObject.Properties.Name) | Where-Object { $_ } | Sort-Object -Unique)
        foreach ($child in $childNames) {
            $ca = $a.children.PSObject.Properties[$child]
            $cb = $b.children.PSObject.Properties[$child]
            if (-not $ca -or -not $cb) { $resourceDiff.Add("$file`: child $child on one side only"); continue }
            if (($null -eq $ca.Value) -ne ($null -eq $cb.Value)) { $resourceDiff.Add("$file`: child $child $(if ($null -eq $ca.Value) { 'failed in PowerShell' } else { 'failed in the browser' })") }
            elseif (@($ca.Value).Count -ne @($cb.Value).Count) { $resourceDiff.Add("$file`: child $child has $(@($ca.Value).Count) / $(@($cb.Value).Count) items") }
        }
    }
    Write-Result -Name 'resources, diagnostic settings and child resources' -Ok (-not $resourceDiff.Count) -Detail $resourceDiff

    Write-Host 'Analysis of both ingestions'
    foreach ($side in 'ps', 'web') { $null = & (Join-Path $repo 'Analyze\Invoke-AzureAnalyze.ps1') -IngestPath (Join-Path $work $side) -OutputPath (Join-Path $work 'analysis') 6>$null 3>$null }
    $psTests = @{}
    foreach ($test in (Read-Json "$work/analysis/ps/results.json").tests) { $psTests[$test.id] = $test }
    $testDiff = [System.Collections.Generic.List[string]]::new()
    foreach ($test in (Read-Json "$work/analysis/web/results.json").tests) {
        $other = $psTests[$test.id]
        if ($other.status -ne $test.status) { $testDiff.Add("$($test.id): PowerShell $($other.status), browser $($test.status). $($test.statusReason)") }
        elseif ("$($other.counts.Pass)/$($other.counts.Fail)/$($other.counts.Unknown)" -ne "$($test.counts.Pass)/$($test.counts.Fail)/$($test.counts.Unknown)") {
            $testDiff.Add("$($test.id): findings $($other.counts.Pass)/$($other.counts.Fail)/$($other.counts.Unknown) (pass/fail/unknown) against $($test.counts.Pass)/$($test.counts.Fail)/$($test.counts.Unknown)")
        }
    }
    Write-Result -Name "$($psTests.Count) test results" -Ok (-not $testDiff.Count) -Detail $testDiff
} finally {
    if ($KeepOutput) { Write-Host "Output kept in $work" } else { Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count) {
    Write-Host "`n$($failures.Count) check(s) differ. Differences in data that changed between the two runs are expected; anything else is a gap in site/js/ingest.js." -ForegroundColor Yellow
    exit 1
}
Write-Host "`nThe browser ingestion collects the same data as the PowerShell ingestion." -ForegroundColor Green
