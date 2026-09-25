#Requires -Version 7.2
<#
    .SYNOPSIS
    Runs the Azure security test suite against an ingestion made by Invoke-AzureIngest.ps1.
    .DESCRIPTION
    Every test in tests\*.ps1 evaluates one security requirement and produces a finding per evaluated resource.
    Each framework has its own catalog in catalog\frameworks: every control of the framework, and per control the tests
    that evidence it (full or partial), or whether it needs manual evidence or does not concern Azure.

    Output (in <OutputPath>\<FolderName>):
    - results.json   everything: tests with descriptions, remediation, framework controls, status and findings, results per framework control
    - tests.csv      one row per test
    - findings.csv   one row per finding
    Output is sorted and contains no timestamps except 'analyzedAt', so runs can be diffed (see Compare-AzureAnalysis.ps1).
    .PARAMETER IngestPath
    Ingestion folder or .zip.
    .PARAMETER OutputPath
    Folder in which the result folder is created. Default .\AzureAnalysis
    .PARAMETER FolderName
    Result folder name. Default: the ingestion folder name.
    .PARAMETER TestId
    Only run tests matching these ids (wildcards allowed).
    .PARAMETER ExcludeTestId
    Skip tests matching these ids (wildcards allowed).
    .EXAMPLE
    .\Invoke-AzureAnalyze.ps1 -IngestPath .\AzureIngest\<subscriptionId>_20260919-105658
    .EXAMPLE
    .\Invoke-AzureAnalyze.ps1 -IngestPath .\ingest.zip -TestId 'AZ-STG-*','AZ-KV-*'
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.jsolve.nl
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$IngestPath,
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath 'AzureAnalysis'),
    [string]$FolderName,
    [string[]]$TestId = @('*'),
    [string[]]$ExcludeTestId = @()
)

$ErrorActionPreference = 'Stop'
#all components share the version in the VERSION file at the repository or module root
$versionFile = if ($PSScriptRoot) { Join-Path (Split-Path $PSScriptRoot -Parent) 'VERSION' }
$analyzerVersion = if ($versionFile -and (Test-Path $versionFile)) { (Get-Content -Path $versionFile -Raw).Trim() } else { 'unknown' }
$schemaVersion = 3

. (Join-Path $PSScriptRoot 'lib\AnalyzeCore.ps1')

function Write-Log { param([string]$Message) Write-Host "$([DateTime]::UtcNow.ToString('HH:mm:ss')) $Message" }

$statusRank = @{ Fail = 5; Error = 4; Unknown = 3; Pass = 2; NotApplicable = 1; NotAssessed = 0 }

function Get-WorstStatus {
    param([string[]]$Statuses)
    $worst = 'NotApplicable'
    foreach ($status in $Statuses) { if ($statusRank[$status] -gt $statusRank[$worst]) { $worst = $status } }
    return $worst
}

function ConvertTo-StableValue {
    #evidence values as JSON friendly, deterministic types
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($entry in $Value.GetEnumerator()) { $ordered[[string]$entry.Key] = ConvertTo-StableValue $entry.Value }
        return $ordered
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { $ordered[$property.Name] = ConvertTo-StableValue $property.Value }
        return $ordered
    }
    if ($Value -is [System.Collections.IEnumerable]) { return , @($Value | ForEach-Object { ConvertTo-StableValue $_ }) }
    return [string]$Value
}

function Get-NaturalKey {
    #sort key that orders '9.3.10' after '9.3.9' and 'NS-10' after 'NS-9'. The value itself follows as a tie breaker:
    #catalogs contain ids like 'DE.AE-2' and 'DE.AE-02' that are equal once padded, and their order must not depend on
    #hashtable enumeration
    param([string]$Value)
    return [regex]::Replace($Value, '\d+', { param($m) $m.Value.PadLeft(6, '0') }) + ' ' + $Value
}

function Write-TextFile {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, ($Content -replace "`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
}

#region load ingestion, catalog and tests

$temporaryFolder = $null
$resolvedIngest = (Resolve-Path -Path $IngestPath).Path
if ($resolvedIngest -match '\.zip$') {
    $temporaryFolder = Join-Path ([System.IO.Path]::GetTempPath()) "azanalyze_$([guid]::NewGuid().ToString('N'))"
    Expand-Archive -Path $resolvedIngest -DestinationPath $temporaryFolder
    $ingestRoot = $temporaryFolder
    if (-not $FolderName) { $FolderName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedIngest) }
} else {
    $ingestRoot = $resolvedIngest
    if (-not $FolderName) { $FolderName = Split-Path -Path $resolvedIngest -Leaf }
}

try {
    Initialize-Ingest -Path $ingestRoot
    $script:Catalog = Import-FrameworkCatalogs -Path (Join-Path $PSScriptRoot 'catalog\frameworks')
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'tests') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }
    Test-FrameworkCatalogs

    #test id > the framework controls it evidences, in framework and control order
    $testControls = @{}
    foreach ($framework in $script:Catalog.Keys) {
        foreach ($id in @($script:Catalog[$framework].controls.Keys | Sort-Object { Get-NaturalKey $_ })) {
            $control = $script:Catalog[$framework].controls[$id]
            foreach ($mappedTest in @($control.tests | Where-Object { $_ })) {
                if (-not $testControls.ContainsKey($mappedTest)) { $testControls[$mappedTest] = [System.Collections.Generic.List[object]]::new() }
                $testControls[$mappedTest].Add(@($framework, $id, $control))
            }
        }
    }

    $selected = @($script:Tests | Where-Object {
            $id = $_.Id
            ($TestId | Where-Object { $id -like $_ }) -and -not ($ExcludeTestId | Where-Object { $id -like $_ })
        } | Sort-Object { Get-NaturalKey $_.Id })
    $manifest = $script:Ingest.Manifest
    Write-Log "Subscription $($manifest.subscription.displayName) ($($manifest.subscription.id)), ingested $($manifest.startedAt)"
    Write-Log "Running $($selected.Count) of $($script:Tests.Count) tests"

    #endregion

    #region run tests

    $testResults = [System.Collections.Generic.List[object]]::new()
    foreach ($test in $selected) {
        $findings = [System.Collections.Generic.List[object]]::new()
        $status = $null
        $statusReason = $null
        try {
            $missing = @($test.Requires | Where-Object { $_ -and -not (Test-IngestSection $_) })
            if ($missing.Count) {
                $status = 'Unknown'
                $statusReason = "Required data was not collected: $(@($missing | ForEach-Object { Get-IngestSectionProblem $_ }) -join ', ')"
            } elseif ($test.Evaluate) {
                foreach ($record in (Get-AzResourceRecords -Type $test.ResourceTypes)) {
                    if ($test.Filter -and -not (& $test.Filter $record $test)) { continue }
                    $result = & $test.Evaluate $record $test
                    if ($null -eq $result) { continue }
                    $findings.Add((New-Finding -Record $record -Result $result))
                }
                foreach ($failedId in (Get-FailedResourceIds -Type $test.ResourceTypes)) {
                    $findings.Add((New-Finding -ResourceId $failedId -ResourceType (@($script:Ingest.Index | Where-Object id -eq $failedId)[0].type) -Result (New-Unknown 'The resource could not be read during ingestion')))
                }
            } else {
                foreach ($finding in @(& $test.Run $test)) { if ($null -ne $finding) { $findings.Add($finding) } }
            }
        } catch {
            $status = 'Error'
            $statusReason = "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber) in $(Split-Path $_.InvocationInfo.ScriptName -Leaf))"
            $findings.Clear()
            Write-Warning "$($test.Id): $statusReason"
        }

        $counts = [ordered]@{ Pass = 0; Fail = 0; Unknown = 0; NotApplicable = 0 }
        foreach ($finding in $findings) { $counts[$finding.Status]++ }
        if (-not $status) {
            $status = if ($counts.Fail) { 'Fail' } elseif ($counts.Unknown) { 'Unknown' } elseif ($counts.Pass) { 'Pass' } else { 'NotApplicable' }
            if ($status -eq 'NotApplicable' -and -not $findings.Count) { $statusReason = 'No resources in scope' }
        }

        $sortedFindings = @($findings | Sort-Object { $_.ResourceId.ToLowerInvariant() }, Detail | ForEach-Object {
                [ordered]@{
                    resourceId    = $_.ResourceId
                    resourceName  = $_.ResourceName
                    resourceType  = $_.ResourceType
                    resourceGroup = $_.ResourceGroup
                    status        = $_.Status
                    detail        = $_.Detail
                    evidence      = ConvertTo-StableValue $_.Evidence
                }
            })
        $duplicates = @($sortedFindings | Group-Object { $_.resourceId.ToLowerInvariant() } | Where-Object Count -gt 1)
        if ($duplicates.Count) { Write-Warning "$($test.Id): duplicate findings for $($duplicates[0].Name)" }

        #the framework controls this test evidences, per framework
        $frameworkTags = [ordered]@{}
        foreach ($entry in @($testControls[$test.Id])) {
            if (-not $entry) { continue }
            $framework, $id, $control = $entry
            $tag = [ordered]@{ id = $id; title = $control.title; coverage = $control.coverage }
            foreach ($field in 'level', 'criticality', 'url') { if ($control[$field]) { $tag[$field] = $control[$field] } }
            if (-not $frameworkTags.Contains($framework)) { $frameworkTags[$framework] = [System.Collections.Generic.List[object]]::new() }
            $frameworkTags[$framework].Add($tag)
        }

        $testResults.Add([ordered]@{
                id                      = $test.Id
                version                 = $test.Version
                title                   = $test.Title
                category                = $test.Category
                service                 = $test.Service
                severity                = $test.Severity
                description             = $test.Description
                rationale               = $test.Rationale
                remediation             = $test.Remediation
                references              = @($test.References | Where-Object { $_ })
                frameworks              = $frameworkTags
                defenderRecommendations = @(if ($test.Defender) { $test.Defender.GetEnumerator() | Sort-Object Key | ForEach-Object { [ordered]@{ id = $_.Key; name = $_.Value } } })
                azurePolicies           = @(if ($test.Policy) { $test.Policy.GetEnumerator() | Sort-Object Key | ForEach-Object { [ordered]@{ id = $_.Key; name = $_.Value } } })
                status                  = $status
                statusReason            = $statusReason
                counts                  = $counts
                findings                = $sortedFindings
            })
    }

    #endregion

    #region rollups and score

    $summaryTests = [ordered]@{ Pass = 0; Fail = 0; Unknown = 0; NotApplicable = 0; Error = 0 }
    $summaryFindings = [ordered]@{ Pass = 0; Fail = 0; Unknown = 0; NotApplicable = 0 }
    $bySeverity = [ordered]@{}
    foreach ($severity in $script:SeverityWeights.Keys) { $bySeverity[$severity] = [ordered]@{ Pass = 0; Fail = 0; Unknown = 0; NotApplicable = 0; Error = 0 } }
    $weightTotal = 0.0
    $weightScore = 0.0
    foreach ($result in $testResults) {
        $summaryTests[$result.status]++
        $bySeverity[$result.severity][$result.status]++
        foreach ($key in $result.counts.Keys) { $summaryFindings[$key] += $result.counts[$key] }
        $evaluated = $result.counts.Pass + $result.counts.Fail
        $weight = $script:SeverityWeights[$result.severity]
        if ($evaluated -gt 0 -and $weight -gt 0) {
            $weightTotal += $weight
            $weightScore += $weight * ($result.counts.Pass / $evaluated)
        }
    }
    $score = if ($weightTotal -gt 0) { [math]::Round(100 * $weightScore / $weightTotal, 1) } else { $null }

    #every control of every framework: the worst result of its tests that ran, or NotAssessed. Controls that need manual
    #evidence or do not concern Azure are listed too, so a framework is never reduced to the controls a test covers
    $statusById = @{}
    foreach ($result in $testResults) { $statusById[$result.id] = $result.status }
    $frameworkRollups = [ordered]@{}
    foreach ($framework in $script:Catalog.Keys) {
        $meta = $script:Catalog[$framework]
        $controls = [ordered]@{}
        $count = [ordered]@{ automated = 0; full = 0; partial = 0; manual = 0; notApplicable = 0 }
        $results = [ordered]@{ Pass = 0; Fail = 0; Unknown = 0; NotApplicable = 0; Error = 0; NotAssessed = 0 }
        foreach ($id in @($meta.controls.Keys | Sort-Object { Get-NaturalKey $_ })) {
            $control = $meta.controls[$id]
            $mappedTests = @($control.tests | Where-Object { $_ })
            $ran = @($mappedTests | Where-Object { $statusById.ContainsKey($_) } | Sort-Object { Get-NaturalKey $_ })
            $item = [ordered]@{ title = $control.title }
            if ($mappedTests.Count) {
                $item.applicability = 'automated'
                $item.coverage = $control.coverage
                $item.status = if ($ran.Count) { Get-WorstStatus @($ran | ForEach-Object { $statusById[$_] }) } else { 'NotAssessed' }
                $count.automated++
                $count[$control.coverage]++
                $results[$item.status]++
            } else {
                $item.applicability = $control.applicability
                $item.status = 'NotAssessed'
                $count[$control.applicability]++
            }
            $item.tests = $ran
            foreach ($field in 'assessment', 'level', 'criticality', 'url') { if ($control[$field]) { $item[$field] = $control[$field] } }
            if (-not $item.title) { $item.Remove('title') }
            $controls[$id] = $item
        }
        #metadata from the catalog: version, publisher, source, how the tests were mapped
        $rollup = [ordered]@{}
        foreach ($key in 'key', 'name', 'shortName', 'version', 'publisher', 'type', 'url', 'download', 'retrieved', 'mapping', 'note') { if ($meta[$key]) { $rollup[$key] = $meta[$key] } }
        #the framework score counts automated controls with a result; manual and not applicable controls are reported apart
        $evaluated = $results.Pass + $results.Fail
        $rollup.coverage = [ordered]@{
            controls      = $controls.Count
            automated     = $count.automated
            full          = $count.full
            partial       = $count.partial
            manual        = $count.manual
            notApplicable = $count.notApplicable
            results       = $results
            score         = $(if ($evaluated) { [math]::Round(100 * $results.Pass / $evaluated, 1) } else { $null })
        }
        $rollup.controls = $controls
        $frameworkRollups[$framework] = $rollup
    }

    #endregion

    #region output

    $results = [ordered]@{
        schemaVersion = $schemaVersion
        analyzer      = [ordered]@{ version = $analyzerVersion; tests = $testResults.Count }
        ingest        = [ordered]@{
            folder           = $FolderName
            subscriptionId   = $manifest.subscription.id
            subscriptionName = $manifest.subscription.displayName
            tenantId         = $manifest.subscription.tenantId
            startedAt        = Format-UtcDate $manifest.startedAt
            ingestVersion    = $manifest.scriptVersion
            status           = $manifest.status
        }
        analyzedAt    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        summary       = [ordered]@{
            postureScore = $score
            scoreMethod  = 'Severity weighted pass rate of evaluated findings per test (Critical 8, High 4, Medium 2, Low 1, Informational 0)'
            tests        = $summaryTests
            findings     = $summaryFindings
            bySeverity   = $bySeverity
        }
        frameworks    = $frameworkRollups
        tests         = $testResults
    }

    $resultFolder = Join-Path $OutputPath $FolderName
    $null = New-Item -ItemType Directory -Force -Path $resultFolder
    Write-TextFile -Path (Join-Path $resultFolder 'results.json') -Content (($results | ConvertTo-Json -Depth 50) + "`n")

    $testRows = $testResults | ForEach-Object {
        [pscustomobject]@{ testId = $_.id; version = $_.version; title = $_.title; category = $_.category; service = $_.service; severity = $_.severity; status = $_.status; pass = $_.counts.Pass; fail = $_.counts.Fail; unknown = $_.counts.Unknown; notApplicable = $_.counts.NotApplicable; controls = (@(foreach ($framework in $_.frameworks.Keys) { foreach ($tag in $_.frameworks[$framework]) { "$framework $($tag.id)" } }) -join '; '); statusReason = $_.statusReason }
    }
    Write-TextFile -Path (Join-Path $resultFolder 'tests.csv') -Content (($testRows | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded) -join "`n")
    $findingRows = foreach ($result in $testResults) {
        foreach ($finding in $result.findings) {
            [pscustomobject]@{ testId = $result.id; severity = $result.severity; status = $finding.status; resourceId = $finding.resourceId; resourceName = $finding.resourceName; resourceType = $finding.resourceType; resourceGroup = $finding.resourceGroup; detail = $finding.detail }
        }
    }
    Write-TextFile -Path (Join-Path $resultFolder 'findings.csv') -Content ((@($findingRows) | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded) -join "`n")

    $line = ($summaryTests.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-Log "Tests: $line. Posture score: $score"
    Write-Log "Output: $resultFolder"
    [pscustomobject]@{ Path = $resultFolder; Tests = $testResults.Count; Failed = $summaryTests.Fail; Errors = $summaryTests.Error; PostureScore = $score }

    #endregion
} finally {
    if ($temporaryFolder -and (Test-Path $temporaryFolder)) { Remove-Item -Path $temporaryFolder -Recurse -Force }
}
