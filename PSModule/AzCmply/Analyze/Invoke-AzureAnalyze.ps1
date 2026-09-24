#Requires -Version 7.2
<#
    .SYNOPSIS
    Runs the Azure security test suite against an ingestion made by Invoke-AzureIngest.ps1.
    .DESCRIPTION
    Every test in tests\*.ps1 evaluates one security requirement and produces a finding per evaluated resource.
    Tests are tagged with the controls they implement (Microsoft cloud security benchmark v2, CIS Microsoft Azure
    Foundations Benchmark 6.0.0, Well-Architected Framework security pillar, Azure landing zone policy assignments);
    NIST SP 800-53, PCI DSS, CIS Controls, NIST CSF, ISO 27001 and SOC 2 tags are derived from the MCSB mappings.

    Output (in <OutputPath>\<FolderName>):
    - results.json   everything: tests with descriptions, remediation, framework tags, status and findings, rollups per framework control
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
$analyzerVersion = '1.0.0'
$schemaVersion = 2

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
    $script:Catalog = Get-Content -Path (Join-Path $PSScriptRoot 'catalog\frameworks.json') -Raw | ConvertFrom-Json -AsHashtable
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'tests') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }

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

        #framework tags, derived tags from MCSB mappings
        $frameworkTags = [ordered]@{}
        foreach ($framework in 'MCSB', 'CIS', 'WAF', 'ALZ') {
            if (-not $test.Frameworks[$framework]) { continue }
            $frameworkTags[$framework] = @(@($test.Frameworks[$framework]) | Sort-Object { Get-NaturalKey $_ } | ForEach-Object {
                    $control = $script:Catalog[$framework].controls[$_]
                    $tag = [ordered]@{ id = $_; title = $control.title; version = $script:Catalog[$framework].version }
                    if ($control.level) { $tag.level = $control.level }
                    if ($control.criticality) { $tag.criticality = $control.criticality }
                    if ($control.url) { $tag.url = $control.url }
                    $tag
                })
        }
        #derived: framework > control id > the MCSB controls it comes from; crosswalk tags set on the test itself have none
        $derived = @{}
        foreach ($framework in @($test.Frameworks.Keys | Where-Object { $script:Catalog[$_].kind -eq 'crosswalk' } | Sort-Object)) {
            $derived[$framework] = @{}
            foreach ($id in @($test.Frameworks[$framework])) { $derived[$framework][$id] = [System.Collections.Generic.HashSet[string]]::new() }
        }
        foreach ($control in @($test.Frameworks.MCSB | Where-Object { $_ })) {
            foreach ($mapping in $script:Catalog.MCSB.controls[$control].mappings.GetEnumerator()) {
                if (-not $derived.ContainsKey($mapping.Key)) { $derived[$mapping.Key] = @{} }
                foreach ($id in @($mapping.Value)) {
                    if (-not $id) { continue }
                    if (-not $derived[$mapping.Key].ContainsKey($id)) { $derived[$mapping.Key][$id] = [System.Collections.Generic.HashSet[string]]::new() }
                    $null = $derived[$mapping.Key][$id].Add($control)
                }
            }
        }
        $derivedTags = [ordered]@{}
        foreach ($key in ($derived.Keys | Sort-Object)) {
            $derivedTags[$key] = @($derived[$key].Keys | Sort-Object { Get-NaturalKey $_ } | ForEach-Object {
                    [ordered]@{ id = $_; version = $script:Catalog[$key].version; via = @($derived[$key][$_] | Sort-Object { Get-NaturalKey $_ }) }
                })
        }
        $frameworkTags.derived = $derivedTags

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

    $rollups = [ordered]@{}
    foreach ($result in $testResults) {
        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($framework in 'MCSB', 'CIS', 'WAF', 'ALZ') { foreach ($tag in @($result.frameworks[$framework])) { if ($tag) { $entries.Add(@($framework, $tag.id, $tag.title, $null)) } } }
        foreach ($derivedFramework in $result.frameworks.derived.Keys) { foreach ($tag in $result.frameworks.derived[$derivedFramework]) { $entries.Add(@($derivedFramework, $tag.id, $null, $tag.via)) } }
        foreach ($entry in $entries) {
            $framework, $id, $title, $via = $entry
            if (-not $rollups.Contains($framework)) { $rollups[$framework] = @{} }
            if (-not $rollups[$framework].ContainsKey($id)) { $rollups[$framework][$id] = [ordered]@{ title = $title; status = 'NotApplicable'; tests = [System.Collections.Generic.List[string]]::new(); via = [System.Collections.Generic.HashSet[string]]::new() } }
            $rollups[$framework][$id].tests.Add($result.id)
            foreach ($mcsb in @($via)) { if ($mcsb) { $null = $rollups[$framework][$id].via.Add($mcsb) } }
            $rollups[$framework][$id].status = Get-WorstStatus @($rollups[$framework][$id].status, $result.status)
        }
    }
    #catalog controls without any test are listed as NotAssessed so coverage gaps are visible;
    #without this a framework would report every control it happens to cover as its whole scope
    $crosswalks = @($script:Catalog.Keys | Where-Object { $script:Catalog[$_].kind -eq 'crosswalk' } | Sort-Object)
    foreach ($framework in @('MCSB', 'CIS', 'WAF', 'ALZ') + $crosswalks) {
        if (-not $rollups.Contains($framework)) { $rollups[$framework] = @{} }
        foreach ($id in $script:Catalog[$framework].controls.Keys) {
            if (-not $rollups[$framework].ContainsKey($id)) {
                $rollups[$framework][$id] = [ordered]@{ title = $script:Catalog[$framework].controls[$id].title; status = 'NotAssessed'; tests = [System.Collections.Generic.List[string]]::new(); via = $null }
            }
        }
    }
    $frameworkRollups = [ordered]@{}
    foreach ($framework in ($rollups.Keys | Sort-Object { @('MCSB', 'CIS', 'WAF', 'ALZ').IndexOf($_) -lt 0 }, { $_ })) {
        $controls = [ordered]@{}
        foreach ($id in ($rollups[$framework].Keys | Sort-Object { Get-NaturalKey $_ })) {
            $item = $rollups[$framework][$id]
            $catalogControl = if ($script:Catalog.Contains($framework) -and $script:Catalog[$framework].controls) { $script:Catalog[$framework].controls[$id] } else { $null }
            $title = if ($item.title) { $item.title } elseif ($catalogControl.title) { $catalogControl.title } else { $null }
            $controls[$id] = [ordered]@{ title = $title; status = $item.status; tests = @($item.tests | Sort-Object { Get-NaturalKey $_ }) }
            if (-not $controls[$id].title) { $controls[$id].Remove('title') }
            if ($catalogControl.assessment -eq 'Manual') { $controls[$id].assessment = 'Manual' }
            if ($catalogControl.url) { $controls[$id].url = $catalogControl.url }
            if ($item.via -and $item.via.Count) { $controls[$id].via = @($item.via | Sort-Object { Get-NaturalKey $_ }) }
        }
        #framework metadata from the catalog: version, publisher, source documentation
        $meta = $script:Catalog[$framework]
        $assessed = @($controls.Values | Where-Object { $_.status -ne 'NotAssessed' }).Count
        $rollup = [ordered]@{ name = $framework }
        if ($meta) { foreach ($key in $meta.Keys) { if ($key -ne 'controls') { $rollup[$key] = $meta[$key] } } }
        $rollup.coverage = [ordered]@{ controls = $controls.Count; assessed = $assessed; notAssessed = $controls.Count - $assessed }
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
        [pscustomobject]@{ testId = $_.id; version = $_.version; title = $_.title; category = $_.category; service = $_.service; severity = $_.severity; status = $_.status; pass = $_.counts.Pass; fail = $_.counts.Fail; unknown = $_.counts.Unknown; notApplicable = $_.counts.NotApplicable; mcsb = (@($_.frameworks.MCSB | ForEach-Object id) -join ' '); cis = (@($_.frameworks.CIS | ForEach-Object id) -join ' '); statusReason = $_.statusReason }
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
