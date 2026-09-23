#Extracts the collection maps of Ingest\Invoke-AzureIngest.ps1 (the '#region collection maps' block, the cloud endpoints
#and the version constants) as data for the browser ingestion. Only literal data is accepted: arrays, hashtables, strings
#and numbers, strings built from earlier variables of the region, and '+'. Anything else stops the generator, because
#logic in that region would not reach the browser.

function Get-OrdinalSorted {
    #items sorted by a string key with ordinal comparison, so the order is the same in every culture
    param([object[]]$Items, [scriptblock]$Key = { [string]$_ })
    if (-not $Items.Count) { return , @() }
    #a List sorts in place; [Array]::Sort would get converted copies of PowerShell arrays and sort those
    $keys = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Items.Count; $i++) { $keys.Add("$([string]($Items[$i] | ForEach-Object $Key))$([char]0)$($i.ToString('D8'))") }
    $keys.Sort([System.StringComparer]::Ordinal)
    return , @(foreach ($k in $keys) { $Items[[int]$k.Substring($k.LastIndexOf([char]0) + 1)] })
}

function ConvertTo-PlanValue {
    #plain arrays and dictionaries; unordered hashtables get sorted keys so the output does not depend on hashing
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.Specialized.OrderedDictionary]) {
        $out = [ordered]@{}
        foreach ($entry in $Value.GetEnumerator()) { $out[[string]$entry.Key] = ConvertTo-PlanValue $entry.Value }
        return $out
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in (Get-OrdinalSorted -Items @($Value.Keys | ForEach-Object { [string]$_ }))) { $out[$key] = ConvertTo-PlanValue $Value[$key] }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return , @($Value | ForEach-Object { ConvertTo-PlanValue $_ }) }
    return $Value
}

function Test-PlanExpression {
    #throws unless an expression is literal data that only reads the given variables
    param([System.Management.Automation.Language.Ast]$Ast, [string[]]$Variables, [string]$SourceName)
    $allowed = 'PipelineAst', 'CommandExpressionAst', 'ArrayExpressionAst', 'StatementBlockAst', 'ArrayLiteralAst', 'HashtableAst',
    'StringConstantExpressionAst', 'ExpandableStringExpressionAst', 'ConstantExpressionAst', 'VariableExpressionAst', 'BinaryExpressionAst',
    'UnaryExpressionAst', 'ParenExpressionAst', 'ConvertExpressionAst', 'TypeConstraintAst'
    foreach ($node in $Ast.FindAll({ $true }, $true)) {
        $type = $node.GetType().Name
        $problem = $null
        if ($type -notin $allowed) { $problem = "$type is not data" }
        elseif ($node -is [System.Management.Automation.Language.VariableExpressionAst] -and $node.VariablePath.UserPath -notin $Variables) { $problem = "reads `$$($node.VariablePath.UserPath), which is not defined earlier in the region" }
        elseif ($node -is [System.Management.Automation.Language.BinaryExpressionAst] -and $node.Operator -ne 'Plus') { $problem = "operator -$($node.Operator) is not allowed" }
        elseif ($node -is [System.Management.Automation.Language.UnaryExpressionAst] -and $node.TokenKind -ne 'Comma') { $problem = "operator $($node.TokenKind) is not allowed" }
        elseif ($node -is [System.Management.Automation.Language.ConvertExpressionAst] -and $node.Type.TypeName.Name -ne 'ordered') { $problem = "cast [$($node.Type.TypeName.Name)] is not allowed" }
        if ($problem) { throw "$SourceName`:$($node.Extent.StartLineNumber): the collection maps must be literal data: $problem" }
    }
}

function ConvertTo-IngestPlanModule {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$SourceName)
    $text = [System.IO.File]::ReadAllText($Path) -replace "`r`n", "`n"
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count) { throw "$SourceName does not parse: $($parseErrors[0].Message)" }
    $lines = $text -split "`r?`n"
    $start = [array]::FindIndex($lines, [Predicate[string]] { param($l) $l -match '^#region collection maps\b' }) + 1
    if ($start -lt 1) { throw "$SourceName has no '#region collection maps'" }
    $end = $start
    while ($end -lt $lines.Count -and $lines[$end] -notmatch '^#endregion') { $end++ }
    $end++

    $script = [System.Text.StringBuilder]::new()
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
        $name = $statement.Left.VariablePath.UserPath
        $right = $statement.Right
        $inRegion = $statement.Extent.StartLineNumber -gt $start -and $statement.Extent.EndLineNumber -lt $end
        if ($name -in 'scriptVersion', 'schemaVersion') {
            Test-PlanExpression -Ast $right -Variables @() -SourceName $SourceName
        } elseif ($name -eq 'cloudEndpoints') {
            #@{ AzureCloud = @{...}; ... }[$Environment]: the table before the index
            $index = $right.Expression
            if ($index -isnot [System.Management.Automation.Language.IndexExpressionAst]) { throw "$SourceName`: `$cloudEndpoints is expected to be a hashtable indexed by `$Environment" }
            $right = $index.Target
            Test-PlanExpression -Ast $right -Variables @() -SourceName $SourceName
        } elseif ($inRegion) {
            if ($statement.Operator -ne 'Equals' -or $statement.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { throw "$SourceName`:$($statement.Extent.StartLineNumber): only plain assignments belong in the collection maps" }
            Test-PlanExpression -Ast $right -Variables $names -SourceName $SourceName
        } else {
            continue
        }
        [void]$script.AppendLine("`$$name = $($right.Extent.Text)")
        $names.Add($name)
    }
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement.Extent.StartLineNumber -gt $start -and $statement.Extent.EndLineNumber -lt $end -and $statement -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
            throw "$SourceName`:$($statement.Extent.StartLineNumber): only assignments belong in the collection maps"
        }
    }
    [void]$script.AppendLine('$__plan = [ordered]@{}')
    foreach ($name in $names) { [void]$script.AppendLine("`$__plan['$name'] = `$$name") }
    [void]$script.AppendLine('$__plan')
    $plan = & ([scriptblock]::Create($script.ToString()))
    $json = ConvertTo-Json -InputObject (ConvertTo-PlanValue $plan) -Depth 20
    return "//Generated by Web/Convert-AzCmplyToWeb.ps1 from the collection maps of $SourceName. Do not edit; run the generator instead.`n//What the browser ingestion collects: the same endpoints, api versions and child resources as the PowerShell ingestion.`nexport default $json;`n"
}
