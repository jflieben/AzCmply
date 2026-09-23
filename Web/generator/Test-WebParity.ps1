#Requires -Version 7.2
<#
    .SYNOPSIS
    Verifies that the generated browser scripts give the same results as the PowerShell source.
    .DESCRIPTION
    Runs the PowerShell scripts and their generated JavaScript (on the browser runtime, in node) on the same input and
    compares the output:
    - conformance.ps1: PowerShell language behaviour the runtime reproduces, line by line
    - the analysis of the compliant and the non-compliant self-test fixture (and any -IngestPath): results.json
      (ignoring analyzedAt), tests.csv and findings.csv
    - the comparison of the two fixture analyses
    - the report of the non-compliant analysis with the compliant one as history, byte for byte
    Needs node 20 or later: -Node, the AZCMPLY_NODE environment variable, or node on the PATH.
    .PARAMETER IngestPath
    Additional ingestion folders to compare the analysis of, for example a real subscription.
    .PARAMETER Node
    Path to node.exe.
    .PARAMETER Thorough
    Also compares the analysis of the degraded ingestions the self-test uses (every section file removed in turn, every
    child call failed), which exercises the Unknown and error paths. Takes a few minutes.
    .PARAMETER KeepOutput
    Keeps the working folder and prints its path.
    .EXAMPLE
    .\Test-WebParity.ps1
    .EXAMPLE
    .\Test-WebParity.ps1 -IngestPath D:\AzureIngest\<sub>_20260922-080000
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [string[]]$IngestPath = @(),
    [string]$Node,
    [switch]$Thorough,
    [switch]$KeepOutput
)

$ErrorActionPreference = 'Stop'
$web = Split-Path -Path $PSScriptRoot -Parent
$repo = Split-Path -Path $web -Parent
$parity = Join-Path $PSScriptRoot 'parity.mjs'

if (-not $Node) { $Node = $env:AZCMPLY_NODE }
if (-not $Node) { $Node = (Get-Command node -ErrorAction SilentlyContinue).Source }
if (-not $Node -or -not (Test-Path $Node)) { throw 'node was not found; pass -Node or set AZCMPLY_NODE' }

$failures = [System.Collections.Generic.List[string]]::new()
function Write-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    if ($Ok) { Write-Host "  PASS  $Name" -ForegroundColor Green }
    else {
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "        $Detail" }
        $failures.Add($Name)
    }
}

function Invoke-Node {
    param([string[]]$Arguments)
    $output = & $Node $parity @Arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = ($output | Out-String).Trim() }
}

function Compare-TextFile {
    #exact comparison after normalizing line endings
    param([string]$A, [string]$B)
    $left = [System.IO.File]::ReadAllText($A) -replace "`r`n", "`n"
    $right = [System.IO.File]::ReadAllText($B) -replace "`r`n", "`n"
    if ($left -eq $right) { return $null }
    $i = 0
    while ($i -lt $left.Length -and $i -lt $right.Length -and $left[$i] -eq $right[$i]) { $i++ }
    $from = [math]::Max(0, $i - 80)
    return "first difference at character $i`n        PS: $($left.Substring($from, [math]::Min(200, $left.Length - $from)))`n        JS: $($right.Substring($from, [math]::Min(200, $right.Length - $from)))"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "azcmply-parity-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Force -Path $work
try {
    Write-Host 'Generated files'
    & (Join-Path $web 'Convert-AzCmplyToWeb.ps1') -Check 6>$null
    Write-Result -Name 'site/generated matches the source' -Ok ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) -Detail 'run Web/Convert-AzCmplyToWeb.ps1'

    Write-Host 'Language conformance'
    $conformance = Join-Path $PSScriptRoot 'conformance.ps1'
    $expected = & pwsh -NoProfile -File $conformance 2>&1 | Out-String
    $module = Join-Path $work 'conformance.mjs'
    $js = & (Join-Path $PSScriptRoot 'Invoke-Transpile.ps1') -Path $conformance -SourceName 'conformance.ps1' -VirtualPath '/app/conformance.ps1' -RuntimeImport ([uri](Join-Path $web 'site\js\runtime\index.js')).AbsoluteUri
    [System.IO.File]::WriteAllText($module, $js)
    $actual = & $Node (Join-Path $PSScriptRoot 'run-script.mjs') $module '/app/conformance.ps1' 2>&1 | Out-String
    $expectedLines = @(($expected -replace "`r", '').Trim() -split "`n")
    $actualLines = @(($actual -replace "`r", '').Trim() -split "`n")
    $mismatches = @(for ($i = 0; $i -lt [math]::Max($expectedLines.Count, $actualLines.Count); $i++) {
            if ($expectedLines[$i] -ne $actualLines[$i]) { "PS: $($expectedLines[$i])`n        JS: $($actualLines[$i])" }
        })
    Write-Result -Name "conformance ($($expectedLines.Count) checks)" -Ok (-not $mismatches.Count) -Detail ($mismatches | Select-Object -First 5 | Out-String).Trim()

    #inputs: the two fixtures and any real ingestions
    $inputs = [System.Collections.Generic.List[object]]::new()
    foreach ($mode in 'Good', 'Bad') {
        $folder = Join-Path $work "ingest\fixture-$($mode.ToLowerInvariant())"
        & (Join-Path $repo 'Analyze\selftest\New-FixtureIngest.ps1') -Path $folder -Mode $mode
        $inputs.Add([pscustomobject]@{ Name = "fixture-$($mode.ToLowerInvariant())"; Path = $folder })
    }
    foreach ($path in $IngestPath) { $inputs.Add([pscustomobject]@{ Name = Split-Path $path -Leaf; Path = (Resolve-Path $path).Path }) }

    Write-Host 'Analysis'
    foreach ($item in $inputs) {
        $psOut = Join-Path $work "ps\$($item.Name)"
        $jsOut = Join-Path $work "js\$($item.Name)"
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $null = & (Join-Path $repo 'Analyze\Invoke-AzureAnalyze.ps1') -IngestPath $item.Path -OutputPath (Join-Path $work 'ps') -FolderName $item.Name 6>$null 3>$null
        $psSeconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
        $run = Invoke-Node @('analyze', $item.Path, $jsOut)
        if ($run.ExitCode -ne 0) { Write-Result -Name "$($item.Name): analysis runs" -Ok $false -Detail $run.Text; continue }
        Write-Host "        PowerShell $psSeconds s, browser runtime $($run.Text)"
        $diff = Invoke-Node @('diffjson', (Join-Path $psOut 'results.json'), (Join-Path $jsOut 'results.json'), 'analyzedAt')
        Write-Result -Name "$($item.Name): results.json" -Ok ($diff.ExitCode -eq 0) -Detail $diff.Text
        foreach ($csv in 'tests.csv', 'findings.csv') {
            $detail = Compare-TextFile (Join-Path $psOut $csv) (Join-Path $jsOut $csv)
            Write-Result -Name "$($item.Name): $csv" -Ok (-not $detail) -Detail $detail
        }
    }

    #the degraded ingestions of the self-test: every section file removed in turn, and every child call failed. These
    #drive the Unknown and error paths, which the complete fixtures never reach
    if ($Thorough) {
        Write-Host 'Degraded ingestions'
        $badFixture = Join-Path $work 'ingest\fixture-bad'
        $variants = [System.Collections.Generic.List[object]]::new()
        $sections = @(Get-ChildItem $badFixture -Recurse -Filter '*.json' -File | ForEach-Object { [System.IO.Path]::GetRelativePath($badFixture, $_.FullName) } |
                Where-Object { ($_ -split '[\\/]')[0] -notin 'resources', 'resourceGroups' -and (Split-Path $_ -Leaf) -notin 'manifest.json', 'index.json' } | Sort-Object)
        foreach ($relative in $sections) {
            $name = 'without-' + ($relative -replace '[\\/.]', '-')
            $folder = Join-Path $work "degraded\$name"
            Copy-Item $badFixture $folder -Recurse
            Remove-Item (Join-Path $folder $relative) -Force
            $variants.Add([pscustomobject]@{ Name = $name; Path = $folder })
        }
        $folder = Join-Path $work 'degraded\children-failed'
        Copy-Item $badFixture $folder -Recurse
        foreach ($file in (Get-ChildItem (Join-Path $folder 'resources') -Recurse -Filter '*.json' -File)) {
            $record = Get-Content $file.FullName -Raw | ConvertFrom-Json
            if ($null -eq $record.children) { continue }
            foreach ($childName in @($record.children.PSObject.Properties.Name)) {
                if (-not $childName) { continue }
                $record.children.PSObject.Properties.Remove($childName)
                $record.children | Add-Member -NotePropertyName $childName -NotePropertyValue $null -Force
            }
            $record | ConvertTo-Json -Depth 60 | Set-Content $file.FullName -Encoding utf8
        }
        $variants.Add([pscustomobject]@{ Name = 'children-failed'; Path = $folder })
        $nodeArguments = [System.Collections.Generic.List[string]]::new()
        $nodeArguments.Add('analyze')
        foreach ($variant in $variants) {
            $null = & (Join-Path $repo 'Analyze\Invoke-AzureAnalyze.ps1') -IngestPath $variant.Path -OutputPath (Join-Path $work 'ps-degraded') -FolderName $variant.Name 6>$null 3>$null
            $nodeArguments.Add($variant.Path)
            $nodeArguments.Add((Join-Path $work "js-degraded\$($variant.Name)"))
        }
        $run = Invoke-Node $nodeArguments
        if ($run.ExitCode -ne 0) { Write-Result -Name 'degraded analyses run' -Ok $false -Detail $run.Text }
        else {
            Write-Host "        $($run.Text)"
            $different = @(foreach ($variant in $variants) {
                    $diff = Invoke-Node @('diffjson', (Join-Path $work "ps-degraded\$($variant.Name)\results.json"), (Join-Path $work "js-degraded\$($variant.Name)\results.json"), 'analyzedAt')
                    if ($diff.ExitCode -ne 0) { "$($variant.Name): $($diff.Text)" }
                })
            Write-Result -Name "$($variants.Count) degraded ingestions: results.json" -Ok (-not $different.Count) -Detail ($different | Select-Object -First 3 | Out-String).Trim()
        }
    }

    #comparison and report take the PowerShell analyses as input on both sides, so only these scripts are compared
    $good = Join-Path $work 'ps\fixture-good'
    $bad = Join-Path $work 'ps\fixture-bad'
    Write-Host 'Comparison'
    $null = & (Join-Path $repo 'Analyze\Compare-AzureAnalysis.ps1') -Baseline $good -Current $bad -OutputPath (Join-Path $work 'ps-comparison.json') 6>$null 3>$null
    $run = Invoke-Node @('compare', $good, $bad, (Join-Path $work 'js-comparison.json'))
    if ($run.ExitCode -ne 0) { Write-Result -Name 'comparison runs' -Ok $false -Detail $run.Text }
    else {
        $diff = Invoke-Node @('diffjson', (Join-Path $work 'ps-comparison.json'), (Join-Path $work 'js-comparison.json'))
        Write-Result -Name 'comparison.json' -Ok ($diff.ExitCode -eq 0) -Detail $diff.Text
    }

    Write-Host 'Report'
    $history = Join-Path $work 'history'
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $history 'earlier')
    Copy-Item -Path (Join-Path $good 'results.json') -Destination (Join-Path $history 'earlier\results.json')
    (Get-Item (Join-Path $history 'earlier\results.json')).LastWriteTimeUtc = [datetime]::new(2026, 8, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $cases = @(
        @{ Name = 'report'; History = $null }
        @{ Name = 'report with trend'; History = $history }
    )
    foreach ($case in $cases) {
        $slug = $case.Name -replace '\W', '-'
        $psHtml = Join-Path $work "ps-$slug.html"
        $jsHtml = Join-Path $work "js-$slug.html"
        $arguments = @{ AnalysisPath = $bad; OutputPath = $psHtml }
        if ($case.History) { $arguments.HistoryPath = $case.History }
        $null = & (Join-Path $repo 'Report\New-AzureSecurityReport.ps1') @arguments 6>$null 3>$null
        $nodeArguments = @('report', $bad, $jsHtml)
        if ($case.History) { $nodeArguments += $case.History }
        $run = Invoke-Node $nodeArguments
        if ($run.ExitCode -ne 0) { Write-Result -Name "$($case.Name) runs" -Ok $false -Detail $run.Text; continue }
        $detail = Compare-TextFile $psHtml $jsHtml
        Write-Result -Name "$($case.Name) html" -Ok (-not $detail) -Detail $detail
    }
} finally {
    if ($KeepOutput) { Write-Host "Output kept in $work" } else { Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count) {
    Write-Host "`n$($failures.Count) parity check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "`nThe generated browser scripts match the PowerShell source." -ForegroundColor Green
