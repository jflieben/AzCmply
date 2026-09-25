#Requires -Version 7.2
<#
    .SYNOPSIS
    Packages the Ingest, Analyze and Report components as the AzCmply PowerShell module in .\PSModule.
    .DESCRIPTION
    The three components stay the source of truth: the build copies them into the module unchanged, keeping their
    relative layout so every path they resolve through $PSScriptRoot (the test suite, the control catalog, the
    comparison script) keeps working. Only the module surface is generated: AzCmply.psm1 declares one function
    per component, with the parameter block read from the script itself so the module cannot drift from it, and
    AzCmply.psd1 is the manifest.

    Nothing that can contain a credential or a result is packaged (see $excluded).

    Exported commands:
      Invoke-AzCmplyIngest       collect one subscription        (Invoke-AzureIngest)
      Invoke-AzCmplyAnalysis     run the test suite              (Invoke-AzureAnalyze)
      New-AzCmplyReport          render the HTML report          (New-AzureSecurityReport)
      Compare-AzCmplyAnalysis    diff two analyses               (Compare-AzureAnalysis)
      Invoke-AzCmplySelfTest     verify the suite
      Invoke-AzCmplyAssessment   ingest, analyze and report in one call
    .PARAMETER OutputPath
    Folder to build into. Default .\PSModule
    .PARAMETER ModuleVersion
    Version for the manifest and the components. Default: the VERSION file.
    .PARAMETER SkipValidation
    Skip importing the built module and analysing a generated fixture with it.
    .PARAMETER RunSelfTest
    Also run the full test suite self-test through the built module. Takes several minutes.
    .EXAMPLE
    .\Build-AzCmplyModule.ps1
    .EXAMPLE
    .\Build-AzCmplyModule.ps1 -ModuleVersion 1.3.0 -RunSelfTest
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.jsolve.nl
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'PSModule'),
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ModuleVersion,
    [switch]$SkipValidation,
    [switch]$RunSelfTest
)

$ErrorActionPreference = 'Stop'
$moduleName = 'AzCmply'
#fixed so rebuilds keep the same module identity
$moduleGuid = '7b1d9f3a-4c58-4e2b-9a31-6f0c8d5e2a74'

#component -> exported function. Script is the path inside the module, which mirrors the source layout because the
#scripts resolve their data through $PSScriptRoot and must keep finding it.
$components = @(
    @{ Function = 'Invoke-AzCmplyIngest'; Alias = 'Invoke-AzureIngest'; Script = 'Ingest\Invoke-AzureIngest.ps1' }
    @{ Function = 'Invoke-AzCmplyAnalysis'; Alias = 'Invoke-AzureAnalyze'; Script = 'Analyze\Invoke-AzureAnalyze.ps1' }
    @{ Function = 'Compare-AzCmplyAnalysis'; Alias = 'Compare-AzureAnalysis'; Script = 'Analyze\Compare-AzureAnalysis.ps1' }
    @{ Function = 'New-AzCmplyReport'; Alias = 'New-AzureSecurityReport'; Script = 'Report\New-AzureSecurityReport.ps1' }
    @{ Function = 'Invoke-AzCmplySelfTest'; Alias = $null; Script = 'Analyze\selftest\Invoke-SelfTest.ps1' }
)

#folders copied wholesale, and what never belongs in a distributable module
$payload = 'Ingest', 'Analyze', 'Report'
$excluded = @(
    '*.local'      # creds.local and anything else holding a credential
    '*.html'       # generated reports describe real weaknesses
    '*.zip'
    '.gitignore'
    'AzureIngest'  # collected subscription data
    'AzureAnalysis'
)

function Test-Excluded {
    param([string]$RelativePath)
    foreach ($segment in ($RelativePath -split '[\\/]')) {
        foreach ($pattern in $excluded) { if ($segment -like $pattern) { return $true } }
    }
    return $false
}

#region read the source

foreach ($component in $components) {
    $component.Source = Join-Path $PSScriptRoot $component.Script
    if (-not (Test-Path $component.Source)) { throw "Component not found: $($component.Source)" }
}

if (-not $ModuleVersion) {
    #the VERSION file is the single source of truth for every component and for what gets published
    $ModuleVersion = (Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
    if ($ModuleVersion -notmatch '^\d+\.\d+\.\d+$') { throw "VERSION file must hold a three-part version (X.Y.Z), found '$ModuleVersion'" }
    Write-Host "Module version $ModuleVersion (from VERSION)"
}

function Get-ScriptSurface {
    #the help block, the CmdletBinding attribute and the parameters of a script, as text, so the generated
    #function keeps the exact same signature, defaults, validation and help as the script it calls
    param([string]$Path, [string]$FunctionName)
    $text = [System.IO.File]::ReadAllText($Path)
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count) { throw "$Path does not parse: $($parseErrors[0].Message)" }
    if (-not $ast.ParamBlock) { throw "$Path has no param block" }

    $help = ''
    if ($text -match '(?s)(<#.*?#>)') {
        #examples and the synopsis name the script; in the module they name the function
        $help = $Matches[1] -replace "\.\\$([regex]::Escape([System.IO.Path]::GetFileName($Path)))", $FunctionName
        $help = $help -replace [regex]::Escape([System.IO.Path]::GetFileName($Path)), $FunctionName
    }
    return [pscustomobject]@{
        Help       = $help
        Attributes = @($ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text })
        Parameters = @($ast.ParamBlock.Parameters)
    }
}

#endregion

#region copy the components

$moduleRoot = Join-Path $OutputPath $moduleName
if (Test-Path $moduleRoot) { Remove-Item $moduleRoot -Recurse -Force }
$null = New-Item -ItemType Directory -Force -Path $moduleRoot

$copied = 0
foreach ($folder in $payload) {
    $sourceFolder = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path $sourceFolder)) { throw "Missing component folder: $sourceFolder" }
    foreach ($file in (Get-ChildItem $sourceFolder -Recurse -File)) {
        $relative = [System.IO.Path]::GetRelativePath($PSScriptRoot, $file.FullName)
        if (Test-Excluded $relative) { continue }
        $destination = Join-Path $moduleRoot $relative
        $null = New-Item -ItemType Directory -Force -Path (Split-Path $destination)
        Copy-Item $file.FullName $destination -Force
        $copied++
    }
}
Write-Host "Copied $copied component file(s) into $moduleRoot"
#the components read their version from the VERSION file above their folder
[System.IO.File]::WriteAllText((Join-Path $moduleRoot 'VERSION'), "$ModuleVersion`n")

#a credential must never reach the module, whatever the exclusion patterns did
foreach ($file in (Get-ChildItem $moduleRoot -Recurse -File)) {
    if ($file.Extension -eq '.local' -or $file.Name -like '*creds*') { throw "Credential file reached the module: $($file.FullName)" }
}

#endregion

#region generate the module

$psm1 = [System.Text.StringBuilder]::new()
$null = $psm1.AppendLine("#Generated by Build-AzCmplyModule.ps1 - do not edit. The components in Ingest, Analyze and Report are the source.")
$null = $psm1.AppendLine("#Each function calls its component script in place, so the script keeps resolving its own data through `$PSScriptRoot.")
$null = $psm1.AppendLine()
$null = $psm1.AppendLine('$script:ComponentRoot = $PSScriptRoot')
$null = $psm1.AppendLine()

foreach ($component in $components) {
    $surface = Get-ScriptSurface -Path $component.Source -FunctionName $component.Function
    $null = $psm1.AppendLine("function $($component.Function) {")
    if ($surface.Help) { foreach ($line in ($surface.Help -split "`r?`n")) { $null = $psm1.AppendLine("    $line".TrimEnd()) } }
    foreach ($attribute in $surface.Attributes) { $null = $psm1.AppendLine("    $attribute") }
    $null = $psm1.AppendLine('    Param(')
    for ($i = 0; $i -lt $surface.Parameters.Count; $i++) {
        $lines = $surface.Parameters[$i].Extent.Text -split "`r?`n"
        $suffix = if ($i -lt $surface.Parameters.Count - 1) { ',' } else { '' }
        for ($l = 0; $l -lt $lines.Count; $l++) {
            $end = if ($l -eq $lines.Count - 1) { $suffix } else { '' }
            $null = $psm1.AppendLine("        $($lines[$l].Trim())$end")
        }
    }
    $null = $psm1.AppendLine('    )')
    $null = $psm1.AppendLine("    & (Join-Path `$script:ComponentRoot '$($component.Script)') @PSBoundParameters")
    $null = $psm1.AppendLine('}')
    $null = $psm1.AppendLine()
}

#the one function that is not a component: the whole chain in a single call. Its authentication and collection
#parameters are taken from the ingest script so they cannot drift either.
$ingestSurface = Get-ScriptSurface -Path (Join-Path $PSScriptRoot 'Ingest\Invoke-AzureIngest.ps1') -FunctionName 'Invoke-AzCmplyAssessment'
#the assessment owns where output goes, so the ingest parameters that decide that are replaced by -Path
$ownedByAssessment = 'OutputPath', 'FolderName', 'Compress'
$passThrough = @($ingestSurface.Parameters | Where-Object { $_.Name.VariablePath.UserPath -notin $ownedByAssessment })

$null = $psm1.AppendLine(@'
function Invoke-AzCmplyAssessment {
    <#
        .SYNOPSIS
        Collects a subscription, analyses it and writes the HTML report, in one call.
        .DESCRIPTION
        Runs Invoke-AzCmplyIngest, Invoke-AzCmplyAnalysis and New-AzCmplyReport in order, under one folder.
        Authentication and collection parameters are the same as Invoke-AzCmplyIngest.

        Earlier assessments under -Path are picked up automatically: from the second run on, the report gains a
        trend section with the posture score over time, the result mix per run, and what changed since the run
        before it. Nothing needs to be passed for that.

        Returns the result of each step plus the path to the report. The collected data and the analysis are kept,
        because the report is a summary of them and an investigation usually needs the detail behind it.
        .PARAMETER Path
        Folder for this assessment. A run folder <subscriptionId>_<timestamp> is created in it, holding
        ingest, analysis and report.html. Default .\AzCmply
        .PARAMETER BaselinePath
        Earlier analysis folder (or results.json) to report changes against. Left out, the most recent earlier run
        under -Path is used, so repeated assessments report their own trend without being told where to look.
        .PARAMETER Title
        Report title.
        .PARAMETER Organization
        Organization name shown on the report cover.
        .PARAMETER SkipReport
        Collect and analyse, but do not render the report.
        .EXAMPLE
        Invoke-AzCmplyAssessment -SubscriptionId $sub -TenantId $tenant -ClientId $app -ClientSecret $secret -Organization 'Contoso'
        .EXAMPLE
        Invoke-AzCmplyAssessment -SubscriptionId $sub -ManagedIdentity -Path D:\Assessments -BaselinePath D:\Assessments\<earlier run>\analysis
        .NOTES
        Author: Jos Lieben / JSolve B.V.
        Website: https://www.jsolve.nl
        Free for non-commercial use. Commercial use requires a license or written permission:
        https://jsolve.nl/commercial-use.html
    #>
'@)
foreach ($attribute in $ingestSurface.Attributes) { $null = $psm1.AppendLine("    $attribute") }
$null = $psm1.AppendLine('    Param(')
foreach ($parameter in $passThrough) {
    foreach ($line in ($parameter.Extent.Text -split "`r?`n")) { $null = $psm1.AppendLine("        $($line.Trim())") }
    $null = $psm1.Append('')
    $null = $psm1.AppendLine('        ,')
}
$null = $psm1.AppendLine(@'
        [string]$Path = (Join-Path -Path (Get-Location).Path -ChildPath 'AzCmply'),
        [string]$BaselinePath,
        [string]$Title,
        [string]$Organization,
        [switch]$SkipReport
    )

    $ingestParameters = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -in 'Path', 'BaselinePath', 'Title', 'Organization', 'SkipReport') { continue }
        $ingestParameters[$name] = $PSBoundParameters[$name]
    }
    $runFolder = Join-Path $Path "$SubscriptionId`_$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))"
    $ingestParameters.OutputPath = $runFolder
    $ingestParameters.FolderName = 'ingest'

    $ingest = Invoke-AzCmplyIngest @ingestParameters
    $analysis = Invoke-AzCmplyAnalysis -IngestPath $ingest.Path -OutputPath $runFolder -FolderName 'analysis'
    $report = $null
    if (-not $SkipReport) {
        #-HistoryPath is the assessment folder, so earlier runs under it become the trend without being named
        $reportParameters = @{ AnalysisPath = $analysis.Path; OutputPath = (Join-Path $runFolder 'report.html'); HistoryPath = $Path }
        foreach ($name in 'BaselinePath', 'Title', 'Organization') { if ($PSBoundParameters.ContainsKey($name)) { $reportParameters[$name] = $PSBoundParameters[$name] } }
        $report = New-AzCmplyReport @reportParameters
    }

    [pscustomobject]@{
        Path         = $runFolder
        Ingest       = $ingest
        Analysis     = $analysis
        Report       = $report
        PostureScore = $analysis.PostureScore
    }
}

'@)

$aliases = @($components | Where-Object { $_.Alias } | ForEach-Object { "Set-Alias -Name '$($_.Alias)' -Value '$($_.Function)'" })
foreach ($alias in $aliases) { $null = $psm1.AppendLine($alias) }
$null = $psm1.AppendLine()
$functionNames = @($components | ForEach-Object { "'$($_.Function)'" }) + "'Invoke-AzCmplyAssessment'"
$aliasNames = @($components | Where-Object { $_.Alias } | ForEach-Object { "'$($_.Alias)'" })
$null = $psm1.AppendLine("Export-ModuleMember -Function $($functionNames -join ', ') -Alias $($aliasNames -join ', ')")
$null = $psm1.AppendLine()

#shown on import so the one command that does everything is the first thing anyone sees
$null = $psm1.AppendLine("`$script:ModuleVersion = '$ModuleVersion'")
$null = $psm1.AppendLine(@'
Write-Host ''
Write-Host "  AzCmply $script:ModuleVersion" -ForegroundColor Cyan -NoNewline
Write-Host '  security posture assessment of an Azure subscription (read only)'
Write-Host ''
Write-Host '  Collect, analyse and report in one command:' -ForegroundColor White
Write-Host '    Invoke-AzCmplyAssessment -SubscriptionId <id> -TenantId <id> -ClientId <appId> -ClientSecret (Read-Host -AsSecureString) -Organization ''Contoso''' -ForegroundColor Green
Write-Host '    Invoke-AzCmplyAssessment -SubscriptionId <id> -ManagedIdentity -Path D:\Assessments' -ForegroundColor Green
Write-Host ''
Write-Host '  Or a step at a time:' -ForegroundColor White
Write-Host '    Invoke-AzCmplyIngest   ->  Invoke-AzCmplyAnalysis  ->  New-AzCmplyReport' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Needs Reader on the subscription and Directory.Read.All in Graph. Get-Help <command> -Full for the rest.' -ForegroundColor DarkGray
Write-Host ''
'@)

$psm1Path = Join-Path $moduleRoot "$moduleName.psm1"
[System.IO.File]::WriteAllText($psm1Path, ($psm1.ToString() -replace "`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))

$psm1Errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($psm1Path, [ref]$null, [ref]$psm1Errors)
if ($psm1Errors.Count) { throw "Generated $moduleName.psm1 does not parse: line $($psm1Errors[0].Extent.StartLineNumber), $($psm1Errors[0].Message)" }

$exportedFunctions = @($components | ForEach-Object { $_.Function }) + 'Invoke-AzCmplyAssessment'
$exportedAliases = @($components | Where-Object { $_.Alias } | ForEach-Object { $_.Alias })

New-ModuleManifest -Path (Join-Path $moduleRoot "$moduleName.psd1") `
    -RootModule "$moduleName.psm1" `
    -ModuleVersion $ModuleVersion `
    -GUID $moduleGuid `
    -Author 'Jos Lieben / JSolve B.V.' `
    -CompanyName 'JSolve B.V.' `
    -Copyright "(c) Jos Lieben / JSolve B.V. Free for non-commercial use; commercial use requires a license or written permission: https://jsolve.nl/commercial-use.html" `
    -Description 'Security posture assessment for an Azure subscription: read-only collection, an offline test suite mapped to MCSB v2, CIS Azure Foundations, WAF and Azure landing zone controls, and a self-contained HTML report. For a quick web based version, check out https://azcmply.jsolve.nl' `
    -PowerShellVersion '7.2' `
    -FunctionsToExport $exportedFunctions `
    -CmdletsToExport @() `
    -VariablesToExport @() `
    -AliasesToExport $exportedAliases `
    -ProjectUri 'https://www.jsolve.nl' `
    -Tags 'Azure', 'Security', 'Posture', 'CIS', 'MCSB', 'Compliance', 'Audit'

Write-Host "Generated $moduleName.psm1 and $moduleName.psd1"

#endregion

#region validate

$result = [pscustomobject]@{
    Path      = $moduleRoot
    Version   = $ModuleVersion
    Manifest  = Join-Path $moduleRoot "$moduleName.psd1"
    Files     = @(Get-ChildItem $moduleRoot -Recurse -File).Count
    Commands  = $null
    Validated = $false
}

if ($SkipValidation) {
    Write-Host 'Validation skipped'
    return $result
}

Write-Host 'Validating the built module'
$manifest = Test-ModuleManifest -Path $result.Manifest
Remove-Module $moduleName -Force -ErrorAction SilentlyContinue
Import-Module $result.Manifest -Force
$exported = @(Get-Command -Module $moduleName | ForEach-Object Name | Sort-Object)
$expected = @(@($components | ForEach-Object { $_.Function }) + 'Invoke-AzCmplyAssessment' + @($components | Where-Object { $_.Alias } | ForEach-Object { $_.Alias }) | Sort-Object)
$missingCommands = @($expected | Where-Object { $_ -notin $exported })
if ($missingCommands) { throw "The module does not export: $($missingCommands -join ', ')" }
$result.Commands = $exported

#the module is only useful if the packaged suite still runs, so analyse a fixture with it
$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) "azcmply-build-$([guid]::NewGuid().ToString('N'))"
try {
    & (Join-Path $moduleRoot 'Analyze\selftest\New-FixtureIngest.ps1') -Path (Join-Path $sandbox 'fixture') -Mode Good
    $analysis = Invoke-AzCmplyAnalysis -IngestPath (Join-Path $sandbox 'fixture') -OutputPath $sandbox -FolderName 'analysis' 6>$null
    if ($analysis.Errors) { throw "$($analysis.Errors) test(s) errored when run from the module" }
    if ($analysis.Failed) { throw "$($analysis.Failed) test(s) failed on the compliant fixture when run from the module" }
    $report = New-AzCmplyReport -AnalysisPath $analysis.Path -OutputPath (Join-Path $sandbox 'report.html') 6>$null
    if (-not (Test-Path $report.Path)) { throw 'The module did not produce a report' }
    Write-Host "  $($analysis.Tests) tests ran from the module, 0 errors, report rendered"
    $result.Validated = $true
} finally {
    Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

if ($RunSelfTest) {
    Write-Host 'Running the full self-test through the module (this takes several minutes)'
    Invoke-AzCmplySelfTest
}

Remove-Module $moduleName -Force -ErrorAction SilentlyContinue
Write-Host "`n$moduleName $ModuleVersion built: $moduleRoot"
Write-Host "  Import-Module '$($result.Manifest)'"
$result

#endregion
