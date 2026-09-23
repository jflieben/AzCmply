#Requires -Version 7.2
<#
    .SYNOPSIS
    Generates the browser variant of AzCmply from the PowerShell source.
    .DESCRIPTION
    Converts the analyzer (Analyze\lib, Analyze\tests, Invoke-AzureAnalyze.ps1), the comparison (Compare-AzureAnalysis.ps1)
    and the report (Report\New-AzureSecurityReport.ps1) to JavaScript modules that run on the runtime in site\js\runtime,
    copies the framework catalog, extracts the collection maps of the ingestion, and bundles a synthetic demo ingestion.
    Output goes to site\generated and is never edited by hand: change the PowerShell and run this again.
    It also stamps a build id (the version plus a hash of every file the page loads) into site\index.html, so browsers
    load an upload fresh; run it after any change under site as well.

    The output is idempotent: the same source always gives byte identical files, so a diff of site\generated shows exactly
    what a source change did. Anything the converter does not support stops the run with the file and line.
    .PARAMETER Check
    Generates into a temporary folder and compares with site\generated instead of writing. Exits with code 1 when the
    generated files are out of date, for use in CI.
    .EXAMPLE
    .\Convert-AzCmplyToWeb.ps1
    .EXAMPLE
    .\Convert-AzCmplyToWeb.ps1 -Check
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$generatorVersion = 1
$repo = Split-Path -Path $PSScriptRoot -Parent
$site = Join-Path $PSScriptRoot 'site'
$target = Join-Path $site 'generated'
. (Join-Path $PSScriptRoot 'generator\Transpiler.ps1')
. (Join-Path $PSScriptRoot 'generator\IngestPlan.ps1')

$utf8 = [System.Text.UTF8Encoding]::new($false)

function Get-RelativePath {
    param([string]$Path)
    return [System.IO.Path]::GetRelativePath($repo, $Path).Replace('\', '/')
}

function Get-Sha256 {
    param([byte[]]$Bytes)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

#text with LF line endings and no BOM, so the output does not depend on git or editor settings
function Set-OutputFile {
    param([string]$Root, [string]$Relative, [string]$Text)
    $path = Join-Path $Root $Relative
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $path)
    [System.IO.File]::WriteAllText($path, ($Text -replace "`r`n", "`n"), $utf8)
}

function ConvertTo-JsString {
    param([string]$Text)
    return [PsToJs]::Q($Text)
}

#JSON with object keys sorted, for data whose property order is not meaningful (the demo ingestion)
function ConvertTo-CanonicalValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $sorted = [ordered]@{}
        foreach ($key in (Get-OrdinalSorted -Items @($Value.Keys | ForEach-Object { [string]$_ }))) { $sorted[$key] = ConvertTo-CanonicalValue $Value[$key] }
        return $sorted
    }
    if ($Value -is [System.Collections.IList]) { return , @($Value | ForEach-Object { ConvertTo-CanonicalValue $_ }) }
    return $Value
}

#region sources

$version = (Get-Content -Path (Join-Path $repo 'VERSION') -Raw).Trim()
$scriptSources = Get-OrdinalSorted -Key { Get-RelativePath $_.FullName } -Items @(
    @(Get-ChildItem -Path (Join-Path $repo 'Analyze\lib') -Filter '*.ps1' -File)
    @(Get-ChildItem -Path (Join-Path $repo 'Analyze\tests') -Filter '*.ps1' -File)
    Get-Item -Path (Join-Path $repo 'Analyze\Invoke-AzureAnalyze.ps1')
    Get-Item -Path (Join-Path $repo 'Analyze\Compare-AzureAnalysis.ps1')
    Get-Item -Path (Join-Path $repo 'Report\New-AzureSecurityReport.ps1')
)
$assetSources = @(Get-Item -Path (Join-Path $repo 'Analyze\catalog\frameworks.json'))
$ingestSource = Join-Path $repo 'Ingest\Invoke-AzureIngest.ps1'
$fixtureSource = Join-Path $repo 'Analyze\selftest\New-FixtureIngest.ps1'

$parsed = foreach ($file in $scriptSources) {
    #parsed with LF line endings, so here-strings and the output do not depend on how git checked the files out
    $parseErrors = $null
    $text = [System.IO.File]::ReadAllText($file.FullName) -replace "`r`n", "`n"
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, $file.FullName, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count) { throw "$(Get-RelativePath $file.FullName) does not parse: $($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))" }
    [pscustomobject]@{ File = $file; Relative = Get-RelativePath $file.FullName; Ast = $ast }
}

#every function defined in the converted set can be called from any of it (tests call analyzer helpers, the report
#calls nothing outside itself); anything else must be a cmdlet the runtime implements
$known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($item in $parsed) {
    foreach ($function in $item.Ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$known.Add($function.Name) }
}

#endregion

#region generate

$output = Join-Path ([System.IO.Path]::GetTempPath()) "azcmply-web-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Force -Path $output
try {
    $modules = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $parsed) {
        $relativeJs = 'scripts/' + ($item.Relative -replace '\.ps1$', '.js')
        $depth = ($relativeJs.Split('/').Count - 1) + 1
        $runtimeImport = ('../' * $depth) + 'js/runtime/index.js'
        $compiler = [PsToJs]::new($known)
        $compiler.SourceName = $item.Relative
        $compiler.VirtualPath = "/app/$($item.Relative)"
        $compiler.VirtualRoot = $compiler.VirtualPath.Substring(0, $compiler.VirtualPath.LastIndexOf('/'))
        Write-Host "Converting $($item.Relative)"
        $js = $compiler.CompileFile($item.Ast, $runtimeImport)
        Set-OutputFile -Root $output -Relative $relativeJs -Text $js
        $modules.Add([pscustomobject]@{ Relative = $item.Relative; Js = $relativeJs; VirtualPath = $compiler.VirtualPath })
    }

    #assets the scripts read from their own folder, at the same virtual paths
    $assetLines = [System.Collections.Generic.List[string]]::new()
    $assetLines.Add('//Generated by Web/Convert-AzCmplyToWeb.ps1. Do not edit; run the generator instead.')
    $assetLines.Add('//Files the generated scripts read next to themselves, by virtual path.')
    $assetLines.Add('export default {')
    foreach ($asset in $assetSources) {
        $relative = Get-RelativePath $asset.FullName
        $text = [System.IO.File]::ReadAllText($asset.FullName) -replace "`r`n", "`n"
        $assetLines.Add("    $(ConvertTo-JsString "/app/$relative"): $(ConvertTo-JsString $text),")
    }
    $assetLines.Add('};')
    Set-OutputFile -Root $output -Relative 'assets.js' -Text (($assetLines -join "`n") + "`n")

    #collection maps of the ingestion
    Write-Host 'Extracting the ingestion collection plan'
    Set-OutputFile -Root $output -Relative 'ingest-plan.js' -Text (ConvertTo-IngestPlanModule -Path $ingestSource -SourceName (Get-RelativePath $ingestSource))

    #demo ingestion: the non-compliant self-test fixture, so the page can be tried without signing in
    Write-Host 'Building the demo ingestion'
    $fixtureFolder = Join-Path $output '_fixture'
    & $fixtureSource -Path $fixtureFolder -Mode Bad
    $demo = [ordered]@{}
    $jsonOptions = @{ AsHashtable = $true; Depth = 100; NoEnumerate = $true }
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $jsonOptions.DateKind = 'String' }
    foreach ($file in (Get-OrdinalSorted -Items @(Get-ChildItem -Path $fixtureFolder -Recurse -File) -Key { [System.IO.Path]::GetRelativePath($fixtureFolder, $_.FullName).Replace('\', '/') })) {
        $relative = [System.IO.Path]::GetRelativePath($fixtureFolder, $file.FullName).Replace('\', '/')
        $value = [System.IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json @jsonOptions
        $demo[$relative] = ConvertTo-CanonicalValue $value
    }
    Remove-Item -Path $fixtureFolder -Recurse -Force
    $demoJson = $demo | ConvertTo-Json -Depth 100 -Compress
    Set-OutputFile -Root $output -Relative 'demo-ingest.js' -Text ("//Generated by Web/Convert-AzCmplyToWeb.ps1 from Analyze/selftest/New-FixtureIngest.ps1 -Mode Bad. Do not edit.`n//A synthetic, fully non-compliant subscription: every file of an ingestion folder by relative path.`nexport default $demoJson;`n")

    #entry module: registers the scripts and assets in a runtime file system
    $index = [System.Collections.Generic.List[string]]::new()
    $index.Add('//Generated by Web/Convert-AzCmplyToWeb.ps1. Do not edit; run the generator instead.')
    $index.Add("//Mounts the converted AzCmply scripts in a runtime file system at /app, where they find each other as in the module.")
    $index.Add("import assets from './assets.js';")
    for ($i = 0; $i -lt $modules.Count; $i++) { $index.Add("import s$i from './$($modules[$i].Js)';") }
    $index.Add('')
    $index.Add("export const version = $(ConvertTo-JsString $version);")
    $index.Add("export const generatorVersion = $generatorVersion;")
    $index.Add('export const scripts = {')
    for ($i = 0; $i -lt $modules.Count; $i++) { $index.Add("    $(ConvertTo-JsString $modules[$i].VirtualPath): s$i,") }
    $index.Add('};')
    $index.Add('')
    $index.Add('export function mount(vfs) {')
    $index.Add('    for (const [path, block] of Object.entries(scripts)) { vfs.registerScript(path, block); }')
    $index.Add('    for (const [path, text] of Object.entries(assets)) { vfs.writeText(path, text, 0); }')
    $index.Add('}')
    Set-OutputFile -Root $output -Relative 'index.js' -Text (($index -join "`n") + "`n")

    #manifest: what was converted, from which source, so a stale generation is detectable
    $sourceHashes = [ordered]@{}
    foreach ($path in (Get-OrdinalSorted -Items (@($scriptSources.FullName) + @($assetSources.FullName) + $ingestSource + $fixtureSource) -Key { Get-RelativePath $_ })) {
        $sourceHashes[(Get-RelativePath $path)] = Get-Sha256 ([System.Text.Encoding]::UTF8.GetBytes(([System.IO.File]::ReadAllText($path) -replace "`r`n", "`n")))
    }
    #build id: the version plus a hash of every file the page loads (hand-written and generated). index.html loads its
    #scripts with it (js/boot.js?v=<build>), so each upload is fetched fresh however long the host lets browsers cache
    $pageFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($file in (Get-ChildItem -Path $site -Recurse -File)) {
        $relative = [System.IO.Path]::GetRelativePath($site, $file.FullName).Replace('\', '/')
        if ($relative -like 'generated/*' -or $relative -in 'index.html', '.htaccess', 'staticwebapp.config.json') { continue }
        $pageFiles.Add([pscustomobject]@{ Relative = $relative; Path = $file.FullName })
    }
    foreach ($file in (Get-ChildItem -Path $output -Recurse -File)) {
        $relative = [System.IO.Path]::GetRelativePath($output, $file.FullName).Replace('\', '/')
        if ($relative -eq 'manifest.json') { continue }
        $pageFiles.Add([pscustomobject]@{ Relative = "generated/$relative"; Path = $file.FullName })
    }
    $pageFiles = Get-OrdinalSorted -Items $pageFiles.ToArray() -Key { $_.Relative }
    $buildInput = [System.Text.StringBuilder]::new()
    foreach ($file in $pageFiles) { [void]$buildInput.Append($file.Relative).Append("`n").Append(([System.IO.File]::ReadAllText($file.Path) -replace "`r`n", "`n")).Append("`n") }
    $build = "$version-$((Get-Sha256 ([System.Text.Encoding]::UTF8.GetBytes($buildInput.ToString()))).Substring(0, 10))"

    $manifest = [ordered]@{
        generatorVersion = $generatorVersion
        version          = $version
        build            = $build
        sources          = $sourceHashes
        files            = @($pageFiles.Relative)
    }
    Set-OutputFile -Root $output -Relative 'manifest.json' -Text (($manifest | ConvertTo-Json -Depth 5) + "`n")

    #index.html references the entry script and stylesheet with the build id
    $indexPath = Join-Path $site 'index.html'
    $indexText = [System.IO.File]::ReadAllText($indexPath)
    $stampPattern = '(?<=["''](?:js/boot\.js|css/app\.css))(?:\?v=[^"'']*)?(?=["''])'
    if ([regex]::Matches($indexText, $stampPattern).Count -ne 2) { throw 'site/index.html must load js/boot.js and css/app.css (each once) for the build id to be stamped' }
    $stampedIndex = [regex]::Replace($indexText, $stampPattern, "?v=$build") -replace "`r`n", "`n"

    #Content Security Policy: the inline scripts of index.html (the analytics snippet) may run by their hash only, so an
    #edited snippet keeps working after regenerating and nothing else inline can run. The hashes go into every copy of the
    #page's policy: the meta tag, .htaccess and staticwebapp.config.json.
    $inlineHashes = @([regex]::Matches($stampedIndex, '<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)</script>') | ForEach-Object {
            "'sha256-$([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($_.Groups[1].Value))))'"
        })
    $scriptSource = "script-src 'self' https://www.googletagmanager.com$(@($inlineHashes | ForEach-Object { " $_" }) -join '')"
    $policyFiles = [ordered]@{}
    foreach ($name in 'index.html', '.htaccess', 'staticwebapp.config.json') {
        $path = Join-Path $site $name
        $current = [System.IO.File]::ReadAllText($path)
        $text = if ($name -eq 'index.html') { $stampedIndex } else { $current -replace "`r`n", "`n" }
        $pattern = "script-src 'self' https://www\.googletagmanager\.com(?: 'sha256-[A-Za-z0-9+/=]+')*"
        if ([regex]::Matches($text, $pattern).Count -ne 1) { throw "site/$name must contain the page's policy with `"script-src 'self' https://www.googletagmanager.com`" exactly once" }
        $updated = [regex]::Replace($text, $pattern, { param($m) $scriptSource })
        $policyFiles[$name] = [pscustomobject]@{ Path = $path; Current = $current; Updated = $updated }
    }

    #endregion

    #region compare or publish

    $newFiles = @{}
    foreach ($file in (Get-ChildItem -Path $output -Recurse -File)) { $newFiles[[System.IO.Path]::GetRelativePath($output, $file.FullName).Replace('\', '/')] = $file.FullName }
    $oldFiles = @{}
    if (Test-Path $target) { foreach ($file in (Get-ChildItem -Path $target -Recurse -File)) { $oldFiles[[System.IO.Path]::GetRelativePath($target, $file.FullName).Replace('\', '/')] = $file.FullName } }
    $changed = @(foreach ($key in ($newFiles.Keys + $oldFiles.Keys | Sort-Object -Unique)) {
            if (-not $oldFiles.ContainsKey($key)) { "added     $key"; continue }
            if (-not $newFiles.ContainsKey($key)) { "removed   $key"; continue }
            if ((Get-Sha256 ([System.IO.File]::ReadAllBytes($newFiles[$key]))) -ne (Get-Sha256 ([System.IO.File]::ReadAllBytes($oldFiles[$key])))) { "changed   $key" }
        })
    foreach ($entry in $policyFiles.GetEnumerator()) {
        if ($entry.Value.Updated -ne $entry.Value.Current) { $changed += "changed   ../$($entry.Key) (build id $build, $($inlineHashes.Count) inline script hash(es))" }
    }

    if ($Check) {
        if ($changed.Count) {
            Write-Host "site/generated is out of date ($($changed.Count) file(s)); run Web/Convert-AzCmplyToWeb.ps1:"
            $changed | ForEach-Object { Write-Host "  $_" }
            exit 1
        }
        Write-Host 'site/generated is up to date.'
        return
    }

    if (Test-Path $target) { Remove-Item -Path $target -Recurse -Force }
    $null = New-Item -ItemType Directory -Force -Path $target
    Copy-Item -Path (Join-Path $output '*') -Destination $target -Recurse -Force
    foreach ($entry in $policyFiles.Values) { if ($entry.Updated -ne $entry.Current) { [System.IO.File]::WriteAllText($entry.Path, $entry.Updated, $utf8) } }
    if ($changed.Count) { $changed | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  no changes' }
    Write-Host "Generated $($modules.Count) scripts for AzCmply $version (build $build) in $target"

    #endregion
} finally {
    Remove-Item -Path $output -Recurse -Force -ErrorAction SilentlyContinue
}
