#Requires -Version 7.2
<#
    .SYNOPSIS
    Transpiles one PowerShell file to a JavaScript module for the AzCmply browser runtime.
    .DESCRIPTION
    Used by Convert-AzCmplyToWeb.ps1 for every converted script and by Test-WebParity.ps1 for the conformance snippets.
    .PARAMETER Path
    PowerShell file to convert.
    .PARAMETER SourceName
    Name recorded in the output and in error positions, e.g. Analyze/tests/06-Storage.ps1.
    .PARAMETER VirtualPath
    Path of the script in the runtime file system, e.g. /app/Analyze/tests/06-Storage.ps1.
    .PARAMETER RuntimeImport
    Import specifier of the runtime, relative to the output file.
    .PARAMETER KnownCommands
    Function names defined anywhere in the converted set; any other command must be a runtime cmdlet.
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$SourceName,
    [Parameter(Mandatory = $true)][string]$VirtualPath,
    [Parameter(Mandatory = $true)][string]$RuntimeImport,
    [string[]]$KnownCommands = @()
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Transpiler.ps1')

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Path).Path, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count) { throw "$SourceName does not parse: $($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))" }

$known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($name in $KnownCommands) { [void]$known.Add($name) }
foreach ($function in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$known.Add($function.Name) }

$compiler = [PsToJs]::new($known)
$compiler.SourceName = $SourceName
$compiler.VirtualPath = $VirtualPath
$compiler.VirtualRoot = $VirtualPath.Substring(0, $VirtualPath.LastIndexOf('/'))
$compiler.CompileFile($ast, $RuntimeImport)
