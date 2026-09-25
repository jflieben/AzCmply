#Requires -Version 7.2
<#
    .SYNOPSIS
    Writes a self-contained HTML report of an analysis made by Invoke-AzureAnalyze.ps1.
    .DESCRIPTION
    The report contains an executive summary with the posture score, the highest priority failures, results per
    security domain and per framework, every test with its remediation, framework mappings and findings, and the
    version, publisher and source documentation of every framework. With -BaselinePath it adds the changes since an
    earlier analysis. The file has no external dependencies, works offline, supports light and dark mode and prints
    with the visible tests expanded.
    .PARAMETER AnalysisPath
    results.json of the analysis, or the folder containing it.
    .PARAMETER OutputPath
    HTML file to write, or a folder to write <ingest folder>.html in. Default: report.html next to results.json.
    .PARAMETER BaselinePath
    Optional earlier results.json (or folder) to report changes against. With -HistoryPath this defaults to the
    most recent earlier run found there.
    .PARAMETER HistoryPath
    Optional folder holding earlier analyses of the same subscription, searched recursively for results.json.
    When two or more runs are found the report gains a trend section: the posture score over time, the result mix
    per run, and the changes since the previous run.
    .PARAMETER HistoryLimit
    Most recent runs to read from -HistoryPath. Default 24.
    .PARAMETER Title
    Report title. Default 'Azure security assessment'.
    .PARAMETER Organization
    Optional organization name shown on the cover.
    .EXAMPLE
    .\New-AzureSecurityReport.ps1 -AnalysisPath ..\Analyze\AzureAnalysis\<sub>_20261001-080000
    .EXAMPLE
    .\New-AzureSecurityReport.ps1 -AnalysisPath <new results> -BaselinePath <old results> -Organization 'Contoso' -OutputPath .\contoso.html
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.jsolve.nl
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$AnalysisPath,
    [string]$OutputPath,
    [string]$BaselinePath,
    [string]$HistoryPath,
    [int]$HistoryLimit = 24,
    [string]$Title = 'Azure security assessment',
    [string]$Organization
)

$ErrorActionPreference = 'Stop'

#region helpers

function Read-Results {
    param([string]$Path)
    if (Test-Path -Path $Path -PathType Container) { $Path = Join-Path $Path 'results.json' }
    $text = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path)
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { return ConvertFrom-Json -InputObject $text -Depth 100 -DateKind String }
    return ConvertFrom-Json -InputObject $text -Depth 100
}

function Enc { param($Value) return [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function Format-Date {
    param($Value, [switch]$DateOnly)
    if (-not $Value) { return '' }
    $date = if ($Value -is [datetime]) { $Value.ToUniversalTime() } else { [DateTimeOffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
    if ($DateOnly) { return $date.ToString('d MMMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture) }
    return $date.ToString('d MMMM yyyy, HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Format-Number { param($Value) return ([double]$Value).ToString('0.#', [System.Globalization.CultureInfo]::InvariantCulture) }

function ConvertTo-UtcDateOrDefault {
    #an ingest timestamp as UTC; $Default when it is missing or unparseable, so one odd run cannot stop the report
    param($Value, [datetime]$Default)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $parsed = [DateTimeOffset]::MinValue
    if ($Value -and [DateTimeOffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed.UtcDateTime }
    return $Default
}

function Get-Slug { param([string]$Value) return ($Value -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant() }

$statusOrder = @{ Fail = 0; Error = 1; Unknown = 2; Pass = 3; NotApplicable = 4; NotAssessed = 5 }
$severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
$severityLevel = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Informational = 0 }
$statusLabels = @{ Fail = 'Fail'; Error = 'Error'; Unknown = 'Unknown'; Pass = 'Pass'; NotApplicable = 'Not applicable'; NotAssessed = 'Not assessed' }
$statusIcons = @{ Fail = '&#10005;'; Error = '!'; Unknown = '?'; Pass = '&#10003;'; NotApplicable = '&#8211;'; NotAssessed = '&#8211;' }
$auditDisclaimer = 'AzCmply is an automated technical assessment of Azure configuration, not an audit or a certification. It does not establish compliance with any framework or regulation and does not replace an assessment by an accredited auditor, certification body or supervisory authority. Framework names and control identifiers show where results relate to their requirements; the frameworks belong to their publishers.'

function New-StatusBadge {
    param([string]$Status, [string]$Label)
    if (-not $Label) { $Label = $statusLabels[$Status] }
    return "<span class=""badge""><span class=""dot s-$($Status.ToLowerInvariant())"" aria-hidden=""true"">$($statusIcons[$Status])</span>$(Enc $Label)</span>"
}

function New-SeverityChip {
    param([string]$Severity)
    return "<span class=""sev"" data-level=""$($severityLevel[$Severity])""><span class=""pips"" aria-hidden=""true""><i></i><i></i><i></i><i></i></span>$(Enc $Severity)</span>"
}

function New-ExternalLink {
    param([string]$Url, [string]$Text, [string]$Class)
    if (-not $Url) { return (Enc $Text) }
    return "<a class=""ext $Class"" href=""$(Enc $Url)"" target=""_blank"" rel=""noopener noreferrer"">$(Enc $Text)</a>"
}

#Azure portal deep links, derived from the resource id. Only the shapes the portal really has a page for are linked:
#a link that lands on an error page is worse than no link at all, so anything else stays plain text.
$portalRoot = 'https://portal.azure.com/#'
$guidPattern = '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
#Microsoft.Authorization objects have no page of their own, so they link to the scope they apply to
$portalScopeKinds = @{
    roleassignments                 = 'role assignment'
    denyassignments                 = 'deny assignment'
    policyassignments               = 'policy assignment'
    policysetdefinitions            = 'policy initiative'
    roledefinitions                 = 'role definition'
    rolemanagementpolicyassignments = 'role management policy'
    locks                           = 'resource lock'
}

function ConvertTo-PortalPath {
    #escape every segment so an unusual resource name cannot change the url, and leave the separators alone
    param([string]$ResourceId)
    return (($ResourceId.Trim('/') -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
}

function Get-PortalTarget {
    #$null when the portal has no page for this id, otherwise the url and, when it opens something other than the
    #resource itself, a note saying what it opens
    param([string]$ResourceId, $Evidence)
    if (-not $ResourceId -or $ResourceId -notlike '/*') { return $null }
    $id = $ResourceId.TrimEnd('/')
    $resourceRoot = "$portalRoot@$($results.ingest.tenantId)/resource"

    #directory objects have their own blades, addressed by object id
    if ($id -match "^/users/($guidPattern)$") { return [pscustomobject]@{ Url = $portalRoot + "view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$($Matches[1])"; Tip = $null } }
    if ($id -match "^/groups/($guidPattern)$") { return [pscustomobject]@{ Url = $portalRoot + "view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/$($Matches[1])"; Tip = $null } }
    #the enterprise application blade needs the application id next to the object id, so link only where the finding carries it
    if ($id -match "^/servicePrincipals/($guidPattern)$") {
        $objectId = $Matches[1]
        $appId = [string]$Evidence.appId
        if ($appId -notmatch "^$guidPattern$") { return $null }
        return [pscustomobject]@{ Url = $portalRoot + "view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$objectId/appId/$appId"; Tip = $null }
    }
    #a policy definition has a detail blade keyed on the whole definition id, url encoded
    if ($id -match '(?i)^(?<scope>.*)/providers/microsoft\.authorization/policydefinitions/(?<name>[^/]+)$') {
        $definitionId = "$($Matches.scope)/providers/Microsoft.Authorization/policyDefinitions/$($Matches.name)"
        return [pscustomobject]@{ Url = $portalRoot + "view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/$([uri]::EscapeDataString($definitionId))"; Tip = $null }
    }
    #the rest of Microsoft.Authorization: the portal has no page for one assignment, so open the scope it sits on
    if ($id -match '(?i)^(?<scope>/.+)/providers/microsoft\.authorization/(?<kind>[^/]+)/[^/]+$') {
        #read these out before recursing, because the nested call writes its own $Matches
        $scopeId = $Matches.scope
        $kind = $Matches.kind.ToLowerInvariant()
        $scope = Get-PortalTarget -ResourceId $scopeId
        if (-not $scope) { return $null }
        $noun = if ($portalScopeKinds.ContainsKey($kind)) { $portalScopeKinds[$kind] } else { 'entry of this kind' }
        return [pscustomobject]@{ Url = $scope.Url; Tip = "The Azure portal has no page for a single $noun, so this opens the scope it applies to." }
    }
    if ($id -match "^/subscriptions/(?<sub>$guidPattern)$") { return [pscustomobject]@{ Url = "$resourceRoot/subscriptions/$($Matches.sub)/overview"; Tip = $null } }
    if ($id -match "(?i)^/subscriptions/(?<sub>$guidPattern)/resourcegroups/(?<rg>[^/]+)$") { return [pscustomobject]@{ Url = "$resourceRoot/subscriptions/$($Matches.sub)/resourceGroups/$([uri]::EscapeDataString($Matches.rg))/overview"; Tip = $null } }
    #every other resource in the subscription, as long as the id really is a provider path
    if ($id -match "(?i)^/subscriptions/$guidPattern/(resourcegroups/[^/]+/)?providers/[^/]+/[^/]+/[^/]+") { return [pscustomobject]@{ Url = "$resourceRoot/$(ConvertTo-PortalPath $id)"; Tip = $null } }
    return $null
}

function New-ResourceLink {
    #a resource name, linked to its page in the Azure portal when there is one
    param([string]$Name, [string]$ResourceId, $Evidence, [string]$Class = 'rname')
    $target = Get-PortalTarget -ResourceId $ResourceId -Evidence $Evidence
    if (-not $target) { return "<span class=""$Class"">$(Enc $Name)</span>" }
    $tip = if ($target.Tip) { " data-tip=""$(Enc $target.Tip)""" } else { '' }
    return "<a class=""ext $Class"" href=""$(Enc $target.Url)"" target=""_blank"" rel=""noopener noreferrer""$tip>$(Enc $Name)</a>"
}

function New-ResourceNameList {
    #distinct resource names, linked where the portal has a page for them, then "and N more" past $Max
    param($Findings, [int]$Max = 4)
    $groups = @($Findings | Where-Object { $_.resourceName } | Group-Object resourceName | Sort-Object Name)
    if (-not $groups.Count) { return '' }
    $shown = @($groups | Select-Object -First $Max | ForEach-Object { New-ResourceLink -Name $_.Name -ResourceId $_.Group[0].resourceId -Evidence $_.Group[0].evidence -Class 'rlink' })
    $text = $shown -join ', '
    if ($groups.Count -gt $Max) { $text += " and $($groups.Count - $Max) more" }
    return $text
}

function Format-EvidenceValue {
    param($Value)
    if ($null -eq $Value) { return 'none' }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { return ($Value | ConvertTo-Json -Compress -Depth 10) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | ForEach-Object { Format-EvidenceValue $_ })
        if (-not $items.Count) { return 'none' }
        return ($items -join ', ')
    }
    return [string]$Value
}

function New-Evidence {
    param($Evidence)
    if ($null -eq $Evidence) { return '' }
    $lines = foreach ($property in $Evidence.PSObject.Properties) { "<div><span class=""ek"">$(Enc $property.Name)</span> $(Enc (Format-EvidenceValue $property.Value))</div>" }
    return "<div class=""evidence"">$($lines -join '')</div>"
}

#failing, unknown (incl. error) and passing go in the bars; not applicable and not assessed stay out
function Get-Buckets {
    param([string[]]$Statuses)
    $buckets = [ordered]@{ Fail = 0; Unknown = 0; Pass = 0; NotApplicable = 0; NotAssessed = 0 }
    foreach ($status in $Statuses) {
        switch ($status) { 'Fail' { $buckets.Fail++ } 'Error' { $buckets.Unknown++ } 'Unknown' { $buckets.Unknown++ } 'Pass' { $buckets.Pass++ } 'NotAssessed' { $buckets.NotAssessed++ } default { $buckets.NotApplicable++ } }
    }
    return $buckets
}

function New-StackBar {
    #one stacked bar; -Scale is the value that spans the full track
    param($Buckets, [double]$Scale, [string]$Label, [string]$Unit)
    $total = $Buckets.Fail + $Buckets.Unknown + $Buckets.Pass
    $width = if ($Scale -gt 0) { [math]::Max(0.5, 100 * $total / $Scale) } else { 0 }
    $segments = foreach ($key in 'Fail', 'Unknown', 'Pass') {
        $value = $Buckets[$key]
        if (-not $value) { continue }
        $name = @{ Fail = 'failing'; Unknown = 'unknown or error'; Pass = 'passing' }[$key]
        $share = [math]::Round(100 * $value / $total)
        "<span class=""seg b-$($key.ToLowerInvariant())"" style=""flex-grow:$value"" tabindex=""0"" role=""img"" aria-label=""$(Enc "$Label, $value $name $Unit")"" data-tip=""$(Enc "$value $name $Unit ($share%)")"" data-sub=""$(Enc $Label)""></span>"
    }
    return "<div class=""track""><div class=""bar"" style=""width:$(Format-Number $width)%"">$($segments -join '')</div></div>"
}

function New-ChartRow {
    param([string]$LabelHtml, $Buckets, [double]$Scale, [string]$Label, [string]$Unit, [string]$Note, [string]$Extra)
    $total = $Buckets.Fail + $Buckets.Unknown + $Buckets.Pass
    $value = if ($total) { "$($Buckets.Fail) of $total failing" } else { 'nothing evaluated' }
    if ($Note) { $value += "<span class=""row-note"">$(Enc $Note)</span>" }
    $extraHtml = if ($Extra) { "<div class=""row-extra"">$Extra</div>" } else { '' }
    return "<div class=""row$(if ($Extra) { ' has-extra' })""><div class=""row-label"">$LabelHtml</div>$(New-StackBar -Buckets $Buckets -Scale $Scale -Label $Label -Unit $Unit)<div class=""row-value"">$value</div>$extraHtml</div>"
}

function New-TableView {
    param([string]$FirstColumn, $Rows, [switch]$WithNotAssessed)
    $head = "<th>$(Enc $FirstColumn)</th><th class=""num"">Failing</th><th class=""num"">Unknown or error</th><th class=""num"">Passing</th><th class=""num"">Not applicable</th>"
    if ($WithNotAssessed) { $head += '<th class="num">Not assessed</th>' }
    $body = foreach ($row in $Rows) {
        $cells = "<td>$(Enc $row.Label)</td><td class=""num"">$($row.Buckets.Fail)</td><td class=""num"">$($row.Buckets.Unknown)</td><td class=""num"">$($row.Buckets.Pass)</td><td class=""num"">$($row.Buckets.NotApplicable)</td>"
        if ($WithNotAssessed) { $cells += "<td class=""num"">$($row.Buckets.NotAssessed)</td>" }
        "<tr>$cells</tr>"
    }
    return "<details class=""table-view""><summary>Table view</summary><div class=""scroll""><table><thead><tr>$head</tr></thead><tbody>$($body -join '')</tbody></table></div></details>"
}

$legend = '<div class="legend" aria-hidden="true"><span class="key"><i class="sw b-fail"></i>Failing</span><span class="key"><i class="sw b-unknown"></i>Unknown or error</span><span class="key"><i class="sw b-pass"></i>Passing</span></div>'

function New-TrendChart {
    #posture score over time as one line. One measure, one axis: the result counts per run have a different scale
    #and get their own bars below, never a second y axis on this chart.
    param($Points)
    $plotted = @($Points | Where-Object { $null -ne $_.Score })
    if ($plotted.Count -lt 2) { return '' }

    #geometry in user units; the svg keeps its aspect and scrolls on narrow screens like the wide tables do
    $left = 46; $right = 706; $top = 20; $bottom = 198
    $width = $right - $left
    $height = $bottom - $top

    #a score moves in a narrow band, so the axis is a padded window around the data rather than a fixed 0 to 100,
    #which would flatten every real change into a straight line. The window is snapped to tens and always labelled.
    $values = @($plotted | ForEach-Object { [double]$_.Score })
    $low = [math]::Max(0, [math]::Floor((($values | Measure-Object -Minimum).Minimum - 10) / 10) * 10)
    $high = [math]::Min(100, [math]::Ceiling((($values | Measure-Object -Maximum).Maximum + 10) / 10) * 10)
    if ($high - $low -lt 30) {
        $low = [math]::Max(0, $low - [math]::Ceiling((30 - ($high - $low)) / 2 / 10) * 10)
        $high = [math]::Min(100, $low + 30)
    }
    $span = [math]::Max(1, $high - $low)
    $x = { param([int]$Index) $left + $(if ($plotted.Count -eq 1) { $width / 2 } else { $width * $Index / ($plotted.Count - 1) }) }
    $y = { param($Score) $bottom - ($height * ([math]::Max($low, [math]::Min($high, [double]$Score)) - $low) / $span) }

    $svg = [System.Text.StringBuilder]::new()
    #gridlines at the window edges plus whichever rating boundaries fall inside it: recessive, they orient the eye
    $ticks = @($low, $high) + @(50, 70, 85 | Where-Object { $_ -gt $low -and $_ -lt $high })
    foreach ($value in ($ticks | Sort-Object -Unique)) {
        $gy = Format-Number (& $y $value)
        [void]$svg.Append("<line class=""tg"" x1=""$left"" y1=""$gy"" x2=""$right"" y2=""$gy""/>")
        [void]$svg.Append("<text class=""tl"" x=""$($left - 8)"" y=""$(Format-Number ((& $y $value) + 3.5))"" text-anchor=""end"">$value</text>")
    }

    #x labels thin out rather than collide, and the outermost ones hang inward so they stay inside the viewBox
    $step = [math]::Max(1, [math]::Ceiling($plotted.Count / 8))
    for ($i = 0; $i -lt $plotted.Count; $i++) {
        if ($i % $step -ne 0 -and $i -ne $plotted.Count - 1) { continue }
        $px = Format-Number (& $x $i)
        $anchor = if ($i -eq 0) { 'start' } elseif ($i -eq $plotted.Count - 1) { 'end' } else { 'middle' }
        [void]$svg.Append("<text class=""tl"" x=""$px"" y=""$($bottom + 18)"" text-anchor=""$anchor"">$(Enc ($plotted[$i].StartedAt.ToString('d MMM', [System.Globalization.CultureInfo]::InvariantCulture)))</text>")
    }

    $coordinates = @(for ($i = 0; $i -lt $plotted.Count; $i++) { "$(Format-Number (& $x $i)),$(Format-Number (& $y $plotted[$i].Score))" })
    [void]$svg.Append("<polyline class=""tline"" points=""$($coordinates -join ' ')""/>")

    for ($i = 0; $i -lt $plotted.Count; $i++) {
        $point = $plotted[$i]
        $px = Format-Number (& $x $i)
        $py = Format-Number (& $y $point.Score)
        $bandRating = Get-ScoreRating $point.Score
        $evaluated = $point.Tests.Pass + $point.Tests.Fail + $point.Tests.Unknown + $point.Tests.Error
        $when = $point.StartedAt.ToString('d MMMM yyyy, HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
        $tip = "Score $(Format-Number $point.Score) - $($bandRating.Label)"
        $sub = "$when UTC - $($point.Tests.Fail) of $evaluated tests failing"
        $radius = if ($point.IsCurrent) { 6 } else { 4.5 }
        [void]$svg.Append("<circle class=""tdot$(if ($point.IsCurrent) { ' now' })"" cx=""$px"" cy=""$py"" r=""$(Format-Number $radius)"" tabindex=""0"" role=""img"" aria-label=""$(Enc "$tip, $sub")"" data-tip=""$(Enc $tip)"" data-sub=""$(Enc $sub)""/>")
        #a number on every point is noise; the first and the last carry the story
        if ($i -eq 0 -or $i -eq $plotted.Count - 1) {
            $anchor = if ($i -eq 0) { 'start' } else { 'end' }
            [void]$svg.Append("<text class=""tv"" x=""$px"" y=""$(Format-Number ([double]$py - 14))"" text-anchor=""$anchor"">$(Format-Number $point.Score)</text>")
        }
    }

    $first = $plotted[0]
    $last = $plotted[-1]
    $label = "Posture score from $(Format-Number $first.Score) on $($first.StartedAt.ToString('d MMMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture)) to $(Format-Number $last.Score) on $($last.StartedAt.ToString('d MMMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture)), over $($plotted.Count) runs"
    #the caption names the axis window it actually drew, not a fixed one
    $caption = "Each point is one analysis. The axis covers $low to $high, the range these scores fall in. Rating boundaries: 85 and up is good, 70 fair, 50 needs improvement, below 50 at risk."
    return "<div class=""scroll""><svg class=""trend"" viewBox=""0 0 720 224"" role=""img"" aria-label=""$(Enc $label)"">$($svg.ToString())</svg></div><p class=""trend-note"">$(Enc $caption)</p>"
}

#endregion

#region load and prepare

$results = Read-Results $AnalysisPath
$resultsFile = if (Test-Path -Path $AnalysisPath -PathType Container) { Join-Path $AnalysisPath 'results.json' } else { $AnalysisPath }
#-OutputPath is a file, or a folder (existing, or given without extension) that gets <ingest folder>.html
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path (Resolve-Path $resultsFile).Path) 'report.html' }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ((Test-Path -Path $OutputPath -PathType Container) -or -not [System.IO.Path]::GetExtension($OutputPath)) {
    $OutputPath = Join-Path $OutputPath $(if ($results.ingest.folder) { "$($results.ingest.folder).html" } else { 'report.html' })
}
#earlier runs of the same subscription, oldest first. Only the summary of each is kept: the findings of an old run
#are not needed for a trend and reading them all would mean parsing every historical results.json in full.
$history = @()
if ($HistoryPath -and (Test-Path $HistoryPath)) {
    $currentFile = (Resolve-Path $resultsFile).Path
    $candidates = @(Get-ChildItem -Path $HistoryPath -Recurse -Filter 'results.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First $HistoryLimit)
    $found = foreach ($candidate in $candidates) {
        #resolve both sides the same way: a short (8.3) path, different casing or a trailing separator would
        #otherwise let this very analysis through and it would appear as its own predecessor
        if ((Resolve-Path $candidate.FullName).Path -eq $currentFile) { continue }
        try { $run = Read-Results $candidate.FullName } catch { continue }
        if (-not $run.summary -or $run.ingest.subscriptionId -ne $results.ingest.subscriptionId) { continue }
        #and whatever the path says, an analysis of the same ingestion made at the same moment is this one
        if ($run.analyzedAt -eq $results.analyzedAt -and $run.ingest.startedAt -eq $results.ingest.startedAt) { continue }
        [pscustomobject]@{
            Folder    = Split-Path $candidate.FullName -Parent
            StartedAt = ConvertTo-UtcDateOrDefault $run.ingest.startedAt $candidate.LastWriteTimeUtc
            Score     = $run.summary.postureScore
            Tests     = $run.summary.tests
            Findings  = $run.summary.findings
            Analyzer  = $run.analyzer.version
            TestCount = $run.analyzer.tests
            IsCurrent = $false
        }
    }
    $history = @($found | Sort-Object StartedAt)
    #without an explicit baseline the newest earlier run is the natural one to compare against
    if (-not $BaselinePath -and $history.Count) { $BaselinePath = $history[-1].Folder }
}

$comparison = $null
if ($BaselinePath) {
    $compareScript = Join-Path (Split-Path $PSScriptRoot) 'Analyze\Compare-AzureAnalysis.ps1'
    $comparison = & $compareScript -Baseline $BaselinePath -Current $AnalysisPath 6>$null
}

$subscription = $results.ingest
$score = $results.summary.postureScore
$tests = @($results.tests | Sort-Object { $statusOrder[$_.status] }, { $severityOrder[$_.severity] }, { $_.id })
$testsById = @{}
foreach ($test in $tests) { $testsById[$test.id] = $test }
$evaluated = @($tests | Where-Object { $_.status -in 'Pass', 'Fail', 'Unknown', 'Error' })
$failing = @($tests | Where-Object status -eq 'Fail')
$failingCriticalHigh = @($failing | Where-Object { $_.severity -in 'Critical', 'High' })
$failingResources = @($tests | ForEach-Object { $_.findings } | Where-Object { $_.status -eq 'Fail' -and $_.resourceId } | ForEach-Object { $_.resourceId.ToLowerInvariant() } | Sort-Object -Unique)
$notEvaluated = @($tests | Where-Object { $_.status -in 'Unknown', 'Error' })
$categories = @($tests | ForEach-Object category | Sort-Object -Unique)
$findingTotals = $results.summary.findings

#frameworks with every control and its result
$frameworks = [ordered]@{}
foreach ($key in @($results.frameworks.PSObject.Properties.Name)) {
    $fw = $results.frameworks.$key
    $controls = [System.Collections.Generic.List[object]]::new()
    foreach ($property in @($fw.controls.PSObject.Properties)) {
        $item = $property.Value
        $controls.Add([pscustomobject]@{ Id = $property.Name; Title = $item.title; Status = $item.status; Applicability = $item.applicability; Coverage = $item.coverage; Tests = @($item.tests | Where-Object { $_ }); Url = $item.url; Assessment = $item.assessment })
    }
    $automated = @($controls | Where-Object Applicability -eq 'automated')
    $buckets = Get-Buckets @($automated | ForEach-Object Status)
    $scoredControls = $buckets.Fail + $buckets.Pass
    $frameworks[$key] = [pscustomobject]@{
        Key        = $key
        Slug       = Get-Slug $key
        Label      = $fw.shortName
        Name       = $fw.name
        Version    = $fw.version
        Publisher  = $fw.publisher
        Url        = $fw.url
        Download   = $fw.download
        Retrieved  = $fw.retrieved
        Note       = $fw.note
        Mapping    = $fw.mapping
        Buckets    = $buckets
        Automated  = $automated.Count
        Full       = @($automated | Where-Object Coverage -eq 'full').Count
        Partial    = @($automated | Where-Object Coverage -eq 'partial').Count
        Manual     = @($controls | Where-Object Applicability -eq 'manual').Count
        OutOfScope = @($controls | Where-Object Applicability -eq 'notApplicable').Count
        Score      = $(if ($scoredControls) { [math]::Round(100 * $buckets.Pass / $scoredControls, 1) } else { $null })
        Controls   = $controls
    }
}

function Get-ControlLink {
    #control id linked to its source documentation when the analysis has a url for it
    param([string]$Id, [string]$Url)
    if ($Url) { return (New-ExternalLink -Url $Url -Text $Id -Class 'mono') }
    return "<span class=""mono"">$(Enc $Id)</span>"
}

function Get-CoverageText {
    #'58 of 88 controls that concern Azure have tests (3 full, 55 partial); 30 need manual evidence; 65 outside Azure scope'
    param($Framework)
    $relevant = $Framework.Automated + $Framework.Manual
    $text = "$($Framework.Automated) of $relevant controls that concern Azure have tests"
    if ($Framework.Full + $Framework.Partial) { $text += " ($($Framework.Full) full, $($Framework.Partial) partial)" }
    if ($Framework.Manual) { $text += "; $($Framework.Manual) need manual evidence" }
    if ($Framework.OutOfScope) { $text += "; $($Framework.OutOfScope) outside Azure scope" }
    return $text
}

function Get-MappingLabel {
    param([string]$Mapping)
    if ($Mapping -eq 'jsolve') { return 'Mapped by JSolve' }
    return 'The framework''s own Azure checks'
}

function Get-TestControls {
    #the framework controls a test evidences, in framework order
    param($Test)
    $entries = foreach ($key in $frameworks.Keys) {
        foreach ($tag in @($Test.frameworks.$key | Where-Object { $_ })) {
            [pscustomobject]@{
                Framework   = $key
                Id          = $tag.id
                Title       = $tag.title
                Coverage    = $tag.coverage
                Level       = $tag.level
                Criticality = $tag.criticality
                Url         = $tag.url
            }
        }
    }
    return @($entries)
}

#rating bands for the posture score, used for the current score and for every point on the trend
function Get-ScoreRating {
    param($Score)
    if ($null -eq $Score) { return $null }
    if ($Score -ge 85) { return @{ Label = 'Good'; Status = 'Pass'; Class = 'good' } }
    if ($Score -ge 70) { return @{ Label = 'Fair'; Status = 'Unknown'; Class = 'fair' } }
    if ($Score -ge 50) { return @{ Label = 'Needs improvement'; Status = 'Error'; Class = 'weak' } }
    return @{ Label = 'At risk'; Status = 'Fail'; Class = 'risk' }
}
$rating = Get-ScoreRating $score

#the current run appended to the earlier ones is the series the trend section plots
$trendPoints = @()
if ($history.Count) {
    $trendPoints = @($history) + @([pscustomobject]@{
            Folder    = Split-Path (Resolve-Path $resultsFile).Path -Parent
            StartedAt = ConvertTo-UtcDateOrDefault $subscription.startedAt ([DateTime]::UtcNow)
            Score     = $score
            Tests     = $results.summary.tests
            Findings  = $findingTotals
            Analyzer  = $results.analyzer.version
            TestCount = $results.analyzer.tests
            IsCurrent = $true
        })
}

$categoryRows = @(foreach ($category in $categories) {
        $categoryTests = @($tests | Where-Object category -eq $category)
        $buckets = Get-Buckets @($categoryTests | ForEach-Object status)
        [pscustomobject]@{ Label = $category; Buckets = $buckets; Evaluated = $buckets.Fail + $buckets.Unknown + $buckets.Pass }
    }) | Sort-Object { - $_.Buckets.Fail }, { - $_.Evaluated }, Label
$categoryRows = @($categoryRows)

$severityRows = @(foreach ($severity in 'Critical', 'High', 'Medium', 'Low', 'Informational') {
        $severityTests = @($tests | Where-Object severity -eq $severity)
        if (-not $severityTests.Count) { continue }
        $buckets = Get-Buckets @($severityTests | ForEach-Object status)
        [pscustomobject]@{ Label = $severity; Buckets = $buckets; Evaluated = $buckets.Fail + $buckets.Unknown + $buckets.Pass }
    })

#endregion

$html = [System.Text.StringBuilder]::new()
function Add { param([string]$Text) [void]$html.Append($Text) }

#the JSolve B.V. mark in the footer (64x44 PNG), embedded so the report stays a single file
$jsolveMark = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAAAsCAYAAADVX77/AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAuJSURBVGhD5VoLcBT1GfcttrXaOu04Wh2nPjplqmNV1KqBQDABIR0RHEqRFoUS8rw87/3KXcg7HAHkpcjoqDToTKcitQ/I5XLv9+USAhgjamewKCW53dvb3cvj1/nv3h2XxVba6ojnb+Y3u//H9+1+v/2+/3/35i655CJEoaVQV9xdbJL2fyPwRNcTGwp3F2JBx8LTna7OWdLxnMaql9beUdBVkMxrm4v8jgV4ctuKh6VzcgKlr5VeX/Zm2a3S/kWWJyz5W+fjEVMe5nbOR15L/lPSOTmB5duX/7JoayFXuHlhqPj54oZ9+/ZdTfrnNuf3LrQUYdn2p/HY5nlY2LmkWGqbEyjevnz2Aks+8i35mL91Pgotj7s6ezpnzWl68O11b6zHb194Dvdp5iRX71l/s9Q2J2DoNVy+oKNgZN7meVixYwWKdixCQdt88yPNeSXN1lb8+tVn8GjTPKPULqewdNvSksLdj2NxxyIY3jKgqLvwVKGh8HuWv211Ld+50iCdn5NY3Llk57ytc7HhjfVoPdSGpZ1LbyhsXaRIj+/a5b9izf41d655eeWd3YcOXTXTOkewau+quQUdBZoNL2y0LOl+am+RpVh4+nM75j6db8k/vrCzYGphe8FUUffC0aXbl3SvfWntj6Q+cgYLtizyzdtSVGL4o+Fu+cEGaA5qsHLXSsxrz0PhC4/jcUvBmXWvrLtdapczeEj/2Pq5rQv/IO9RvKx6S5Vcvu8pFGwvQOGuQizetti6es/q3NwV0rhP+VDp/Oai6I2/u/Gam1U33714+2Jz8bbirmV7VjwpnZuTeMDwgOwXTQ+VSvu/EThwFt9d9fqOkdX79/oBXCEdz2kcGMKV+gjvk3v+AbWfgs7HvSadk9MwBBM95mOA2Tf5jNKVGDeeAHTeeJd0Xs6h23PmWnOEP2D5BNA4Y2sBXCp30owmOImWUUDjYTZIbXIGh96dvsoYTLi3xQC9l2knfduHTn9b446f1gYnoA4moQ7ycZM7dofUNidg9LOvbBsHDH5mb7qPZIDaTY/owlNQumk0HgU0PnbA8Kcz1860/prDHEiodo0DxlDisHRM7Ykf0w9MQ+2NQ0VEGAb0IS5i8DBf/5cg/QFc2TXEt+4cA5oH+RM7ouPXp8f8fv8VbWF2izEyManxJqD2xAWqPHGYRwGtlz4009vXDC8Px75vOZ4M7KGBruPJ3g7P2G3pseYB/ldNkWSk9QSg9jJC4BqvSCKA2peAfhBo9McenOn1IkZXiL+n+4Opne1R5sntQ+O3Nw/yvs7Riam2KP9sek5rmJ7dPMjb2kYA0xCEgLVZJG21h4bSTUEbnYYuyIYM1rHrZl7pIkRngLqhdZAf3fYx0H5CSPdkyxDPtPji96bndETY20xhbqz9PUDni8+glvA8EWg0HieLImPvAS6becWLCD09uKw5zNq63gcaA3GYQgl0fkjO6cxqT9Adon7aHJ1A23uAKcTD4I9D70uRnPtFMTReOqscaDS9TzKFvnh/MdoUYF7cfBIw+uMwBuJoDDLYNDSBpih/nDz17LlNrjNzWoaSb26KcFzHKNAUnRTsGv3xjCBaL53JCiKGLsRBF+GSreHkHHMwcWvHILd08/vT+jZ//OfZvr8SmL10DQnE4GeEANLU+2g0HZ2GeYA/03k0qd4SpX+YbbflKHdH+xBvao1yp0jmmMIcDD5atM1iWgR9mCdCJXQ+mm05BnT9HWgMsR9Ywl/h+mB2jRc1DU3BEOKF2hXrmT6X1j4ajREx5Y0h7symAX7rpiB9d7YPslO0D/LG1kGO3zQ4KdhkC5C9TjSGeTSSbCCieGi0jJA3SvrNbH9fOky+2F2mAe6uZi93pzHInTUOTInblocWbiqTvpmVXezTh5JofhdojE5MNvoYsxa4NNtvu596xBThPjUKAYoiin5Ef+dEPddPXpyaRgCjjy7L9vWlwWA/e4smwJ1WeRO80k2f0YQmIXdSULhogaIQohhk8Uq3xXMaKjcF8zARYRpk15D6N3pjrS3vkg8isgjSoqgpIbN3i/QuQfzpgjyMYZ4zeenZUn9fKPb1nrxa5UkEtIOA3JOA0sej3kEJbHDSAuVuGgp3XNi+CBVpeuLQhqdhIp+8AxOcxhNvACC9xCU6L/22cXBaCEztps8xk2HpwGkoXWlSMBwF6Q/iy9wqFc74fv0wUGenZtIhst5Bo56IQOgiYjBQh6dBbLSRaWgD7HFDhG8xBKifSH23OT79jt7P7SKZQYJNByalykWyLYtOSshAuYtC4wlA6Yy1Sn1/IVDYabN2CKjpp1Frp1Brp1HTLx5JWzwX2/LAFLRHAaWPg9rPBnUBvqVxIPnYLr//vJ+8dgdwjSnErjME+RHTMQjZIwREyipFsU1DkRY3LbCQdST7KDQ4YlB4GOgjEzAHqEel1/m/oLTT5doBoMbBQGajUG0TAyZiiKRQY4tBHpiGMgzI3Ymo0sfpTVlvgFJ0BBO3NoaTGqWPG9WT1+HQlLCGZIJy0GggpZUuMdJOlVmGqbHMuIOChnxSe5nRjsj0t6TX/J9gcFKlqjBQ60wIgRMBBBFSAohHCsoI0ODlh7Q+bhn5vpf6SUNrp2frAskXlR6WJhml9E8KZUSyh5QQCUQoJQeNun5KZFa5CQHb6VTpZc1NjRM/umFA5aT2Sa/9X0PtokrIk69zsai2xTICZDIgdZQHJ6HwsFZSx1If2Wiw01Vy3wSrjgJ1TvZcCZFjSsg0M+1Mtp3rF8YyZSfaZ8+pc8ShiQJy29nfSO/hgqF00TI1efIuNnMTogiiEGmSsqjzsJOftbBlw+Aav11FxPROoco6DlmfmEWCn9Qxk10pptvC3Bmll7qfFLNtCKv6Yqh2cahzs6zCfvYe6b18LnQetkU3SJ5SArW2mKiwLTaDws3YKNQSAVzMpNk//mOpn2wYArim1kYfaAgDDUFA1s+gyhqbEWSaVQJjqOyjUGkVKfal5qQFktiQ+RXWGMqtFMqtMVT7AJmdGbFc6Kd0p+ujWRov+7pxGGhwxlFP6qo/hpp+UQRyXm+Pob4/JpyL6RiDKjwNhSt+QOrvs6B1M8UNbu6dajsDRQSodk2iso8Wbjw70AoSRG8sQ9KutMVRRYTLzBdtCCtS88qOpNhLofRIDNVBoKKP+bP0Ps6DyU7PVnm5AFmRxRU3LixQ2iigCZNVGlD7kmiwxwTKHZRAQRA7BfUAoHQl3thhP/dz13+Cyc//rMHJbqq2J4Zr3FOoCwLV7ilU2OIzAi8XghGeKltupZgKa4yTuSZRHwDqg0CtF5A5eJRb40LAJHhit/HwOEoOk2MM1SFA1jfzs3wG5HZmg9zNxcneTeqepL/CzRAOKd3Miwb3+EqTm16t9yVOmcj+7qSgJPuugxLpYaEOAab3yBsif1LWO14ovca/A9B7ucabyKt1sC2y/kS00s4JYsjcUyjvpYVAKvoTkNnZiMKVWNMR+fgHtX1j98od8fV1Nvr5ij7aWtZLfVTRG5uq9QG1AaDKC1Q6p1BmY7Gxl0bJERpVAaDiCNU54+KyvsTDVXbWrx8F6v1AtY3+QO1mfm/0sxtaw/x579VdrjM3bQryPc1DgGkAMA+S3/kAo5umlE7KV2cbG652cFAI6wezu/TtC8uGbBi8zP0KF9tYaWMGyuwTqPIBZf1JlDmnUWqNT2y0MgdlzmRetk3PR9OzTD7uLqWbKZb1xeXlvdQr5b20v+ww/UmZlUGFG6j0A7XHgMpeeodgVN9Hr2rwcO/UuiderXYwJWovc/++kxD+tvZ5aAkkVrQNJAfbQuxBS5R/tucEcxPpJ+/2CvvZW1Rubpncy+2qscZaOwM474PnQlFnS+TV2BN7Sq3MyLq/jo+ue2fsw+f+Qv1zw2HmlKyf3ae0j98ntcmGIYzrFB7+nmp74unSI7Sh5HB8f7WTP1FxeKzhX/VHBsxoQFenAAAAAElFTkSuQmCC'

$css = @'
/* the look of M365Permissions: slate neutrals, white cards with a soft shadow, cyan accent (#00acd7); text and lines
   that need contrast on white use the deeper --accent-strong */
:root {
  color-scheme: light;
  --page: #f8fafc; --surface: #ffffff; --surface-2: #f8fafc; --ink: #1e293b; --ink-2: #475569; --muted: #64748b;
  --grid: #e2e8f0; --axis: #cbd5e1; --border: #e2e8f0; --link: #007ea3; --wash: #f0f9ff;
  --accent: #00acd7; --accent-strong: #007ea3; --accent-wash: #f0f9ff; --shadow: 0 2px 8px rgba(0,0,0,0.08);
  --fail: #dc2626; --unknown: #f59e0b; --pass-bar: #94a3b8; --good: #16a34a; --serious: #fb923c; --neutral: #cbd5e1;
  --on-fail: #ffffff; --on-good: #ffffff; --on-unknown: #1e293b; --on-serious: #1e293b; --on-neutral: #1e293b;
  --up: #15803d; --down: #b91c1c;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --page: #0f172a; --surface: #1e293b; --surface-2: #172033; --ink: #f1f5f9; --ink-2: #cbd5e1; --muted: #94a3b8;
    --grid: #334155; --axis: #475569; --border: #334155; --link: #00acd7; --wash: #1e3a4d;
    --accent-strong: #00acd7; --accent-wash: #1e3a4d; --shadow: 0 2px 8px rgba(0,0,0,0.3);
    --fail: #ef4444; --good: #22c55e; --on-good: #0f172a;
    --pass-bar: #64748b; --neutral: #475569; --on-neutral: #ffffff; --up: #22c55e; --down: #f87171;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0f172a; --surface: #1e293b; --surface-2: #172033; --ink: #f1f5f9; --ink-2: #cbd5e1; --muted: #94a3b8;
  --grid: #334155; --axis: #475569; --border: #334155; --link: #00acd7; --wash: #1e3a4d;
  --accent-strong: #00acd7; --accent-wash: #1e3a4d; --shadow: 0 2px 8px rgba(0,0,0,0.3);
  --fail: #ef4444; --good: #22c55e; --on-good: #0f172a;
  --pass-bar: #64748b; --neutral: #475569; --on-neutral: #ffffff; --up: #22c55e; --down: #f87171;
}
* { box-sizing: border-box; }
html { background: var(--page); scroll-behavior: smooth; }
body { margin: 0; background: var(--page); color: var(--ink); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; -webkit-font-smoothing: antialiased; }
a { color: var(--link); font-weight: 500; text-decoration: none; }
a:hover { text-decoration: underline; }
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
a.ext::after { content: "\2197"; font-size: 0.8em; margin-left: 2px; text-decoration: none; display: inline-block; }
p { margin: 0 0 12px; }
.mono { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12.5px; }

/* cover */
.cover { background: var(--surface); border-top: 4px solid var(--accent); border-bottom: 1px solid var(--border); }
.cover-inner { max-width: 1320px; margin: 0 auto; padding: 24px 24px 32px; }
.cover-top { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.eyebrow { font-size: 12px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent-strong); }
.pill { font-size: 11px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase; background: var(--accent-wash); border-radius: 999px; padding: 3px 10px; color: var(--accent-strong); }
.cover-actions { margin-left: auto; display: flex; gap: 8px; }
.cover h1 { font-size: 32px; line-height: 1.2; font-weight: 600; margin: 24px 0 6px; }
.cover-sub { color: var(--muted); font-size: 16px; margin: 0; }
.cover-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px 32px; margin: 24px 0 0; padding-top: 20px; border-top: 1px solid var(--border); }
.cover-meta dt { font-size: 12px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); margin-bottom: 2px; }
.cover-meta dd { margin: 0; font-size: 14px; overflow-wrap: anywhere; }
.btn { font: inherit; font-size: 14px; font-weight: 500; color: var(--ink); background: var(--surface); border: 1px solid var(--accent); border-radius: 8px; padding: 7px 14px; cursor: pointer; transition: background-color 0.2s, color 0.2s; }
.btn:hover { background: var(--accent-strong); border-color: var(--accent-strong); color: var(--surface); }
.btn.ghost { background: transparent; border-color: var(--border); }
.btn.ghost:hover { background: var(--accent-wash); border-color: var(--border); color: var(--ink); }

/* layout */
.layout { max-width: 1320px; margin: 0 auto; padding: 0 24px 64px; display: grid; grid-template-columns: 200px minmax(0, 1fr); gap: 48px; }
.toc { position: sticky; top: 0; align-self: start; padding-top: 40px; max-height: 100vh; overflow-y: auto; }
.toc-title { font-size: 12px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
.toc ol { list-style: none; margin: 0; padding: 0; }
.toc a { display: flex; gap: 10px; align-items: baseline; padding: 7px 10px; border-radius: 8px; color: var(--ink-2); text-decoration: none; font-size: 14px; font-weight: 400; border: 1px solid transparent; }
.toc a:hover { background: var(--accent-wash); color: var(--ink); }
.toc a.active { color: var(--ink); background: var(--accent-wash); border-color: var(--accent); font-weight: 500; }
.toc .n { font-size: 11px; color: var(--muted); font-variant-numeric: tabular-nums; min-width: 16px; }
.toc .c { margin-left: auto; font-size: 12px; color: var(--muted); font-weight: 400; }
main { min-width: 0; }

/* sections */
.section { padding-top: 40px; scroll-margin-top: 8px; }
.section-head { display: flex; gap: 16px; align-items: baseline; margin-bottom: 20px; }
.section-head .num { font-size: 13px; font-weight: 600; color: var(--accent-strong); font-variant-numeric: tabular-nums; }
.section-head h2 { font-size: 24px; line-height: 1.25; font-weight: 600; margin: 0 0 4px; }
.section-head .sub { color: var(--muted); margin: 0; max-width: 820px; }
h3 { font-size: 16px; font-weight: 600; margin: 0 0 12px; }
.card { background: var(--surface); border-radius: 12px; padding: 24px; box-shadow: var(--shadow); }
.card + .card, .card + h3 { margin-top: 16px; }
.fw-grid > .card, .two > .card { margin-top: 0; }
.note { color: var(--ink-2); font-size: 13px; }
.muted { color: var(--muted); }

/* executive summary */
.exec { display: grid; grid-template-columns: 220px minmax(0, 1fr); gap: 32px; align-items: start; }
.score { text-align: center; }
.meter { position: relative; width: 180px; height: 180px; margin: 0 auto; }
.meter svg { width: 180px; height: 180px; display: block; }
.meter .track-ring { fill: none; stroke: var(--grid); stroke-width: 12; }
.meter .arc { fill: none; stroke-width: 12; stroke-linecap: round; }
.meter .arc.good { stroke: var(--good); } .meter .arc.fair { stroke: var(--unknown); } .meter .arc.weak { stroke: var(--serious); } .meter .arc.risk { stroke: var(--fail); }
.meter-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.meter-value .big { font-size: 48px; font-weight: 700; line-height: 1; }
.meter-value .of { font-size: 13px; color: var(--muted); margin-top: 4px; }
.score .caption { font-size: 12px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); margin-bottom: 12px; }
.score .rating { margin-top: 14px; font-size: 15px; }
.score .delta { margin-top: 6px; font-size: 13px; color: var(--ink-2); }
.up { color: var(--up); font-weight: 600; } .down { color: var(--down); font-weight: 600; }
.lead { font-size: 16px; line-height: 1.6; }
.lead:last-of-type { margin-bottom: 0; }
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); margin-top: 24px; border-top: 1px solid var(--grid); }
.kpi { padding: 16px 16px 0 0; }
.kpi + .kpi { padding-left: 16px; border-left: 1px solid var(--grid); }
.kpi .label { font-size: 12px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); }
.kpi .value { font-size: 30px; font-weight: 700; line-height: 1.2; margin-top: 4px; }
.kpi .value small { font-size: 14px; font-weight: 400; color: var(--muted); }
.kpi .hint { font-size: 12px; color: var(--muted); }

/* tables */
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { text-align: left; font-weight: 500; font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); background: var(--surface-2); border-bottom: 1px solid var(--grid); padding: 10px 12px; white-space: nowrap; }
td { border-bottom: 1px solid var(--grid); padding: 10px 12px; vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr { transition: background-color 0.15s; }
tbody tr:hover td { background: var(--wash); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.rank { color: var(--muted); font-variant-numeric: tabular-nums; width: 32px; }
.prio td:nth-child(3) { min-width: 300px; width: 38%; } .prio td:nth-child(4) { min-width: 150px; } .chg td:nth-child(2) { min-width: 300px; width: 42%; }
.scroll { overflow-x: auto; }
.card.flush { padding: 8px 14px; }

/* status and severity */
.badge { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; font-weight: 500; }
.dot { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; font-size: 11px; font-weight: 700; line-height: 1; flex: none; }
.s-fail { background: var(--fail); color: var(--on-fail); }
.s-error { background: var(--serious); color: var(--on-serious); }
.s-unknown { background: var(--unknown); color: var(--on-unknown); }
.s-pass { background: var(--good); color: var(--on-good); }
.s-notapplicable, .s-notassessed { background: var(--neutral); color: var(--on-neutral); }
.sev { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; color: var(--ink-2); }
.pips { display: inline-flex; gap: 2px; }
.pips i { width: 6px; height: 11px; border-radius: 1.5px; border: 1px solid var(--ink-2); }
.sev[data-level="1"] .pips i:nth-child(-n+1), .sev[data-level="2"] .pips i:nth-child(-n+2), .sev[data-level="3"] .pips i:nth-child(-n+3), .sev[data-level="4"] .pips i:nth-child(-n+4) { background: var(--ink-2); }

/* charts */
.legend { display: flex; flex-wrap: wrap; gap: 18px; font-size: 13px; color: var(--ink-2); margin-bottom: 14px; }
.key { display: inline-flex; align-items: center; gap: 6px; }
.sw { width: 12px; height: 12px; border-radius: 3px; display: inline-block; flex: none; }
.row { display: grid; grid-template-columns: 230px minmax(0, 1fr) 160px; gap: 14px; align-items: center; min-height: 42px; padding: 3px 0; }
.row.has-extra { grid-template-columns: 230px minmax(0, 1fr) 160px 150px; }
.row-label { font-size: 14px; }
.row-label a { color: var(--ink); text-decoration: none; }
.row-label a:hover { text-decoration: underline; }
.row-note { display: block; font-size: 12px; color: var(--muted); }
.row-value { font-size: 13px; color: var(--ink-2); font-variant-numeric: tabular-nums; }
.row-extra { font-size: 13px; text-align: right; }
.trend { display: block; width: 100%; min-width: 560px; max-width: 920px; height: auto; margin: 4px auto 2px; }
.trend .tg { stroke: var(--grid); stroke-width: 1; }
.trend .tl { fill: var(--muted); font-size: 11px; font-family: inherit; }
.trend .tv { fill: var(--ink); font-size: 12px; font-weight: 600; font-family: inherit; }
.trend .tline { fill: none; stroke: var(--accent-strong); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
/* the 2px surface ring keeps a marker readable where it sits on the line or on a neighbour */
.trend .tdot { fill: var(--accent-strong); stroke: var(--surface); stroke-width: 2; cursor: default; }
.trend .tdot.now { stroke-width: 2.5; }
.trend .tdot:focus { outline: none; stroke: var(--ink); }
.trend-note { color: var(--muted); font-size: 13px; margin: 2px 0 0; }
.track { border-left: 1px solid var(--axis); padding: 2px 0; }
.bar { display: flex; gap: 2px; height: 16px; min-width: 2px; }
.seg { min-width: 3px; height: 100%; cursor: default; }
.seg:last-child { border-radius: 0 4px 4px 0; }
.seg:hover, .seg:focus-visible { filter: brightness(1.1); outline: 2px solid var(--ink); outline-offset: 1px; }
.b-fail { background: var(--fail); } .b-unknown { background: var(--unknown); } .b-pass { background: var(--pass-bar); }
.table-view { margin-top: 14px; }
.table-view > summary, details.more > summary { cursor: pointer; color: var(--link); font-size: 13px; width: fit-content; }
.table-view table { margin-top: 8px; }
.two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }

/* framework cards */
.fw-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; }
.fwcard { display: flex; flex-direction: column; gap: 14px; }
.fw-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.fw-head h3 { margin: 0; font-size: 18px; }
.fw-name { font-size: 13px; color: var(--ink-2); margin-top: 2px; }
.ver-chip { font-size: 12px; font-weight: 500; max-width: 50%; text-align: right; border: 1px solid var(--border); background: var(--surface-2); border-radius: 12px; padding: 2px 10px; color: var(--ink-2); }
.fw-figure { display: flex; align-items: baseline; gap: 8px; }
.fw-figure .big { font-size: 30px; font-weight: 700; line-height: 1; }
.fw-figure .of { font-size: 13px; color: var(--ink-2); }
.fwcard .track { border-left: 0; padding: 0; }
.fw-stats { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: var(--ink-2); }
.fw-cov { margin: 0; font-size: 13px; color: var(--ink-2); }
.fw-stats span { display: inline-flex; align-items: center; gap: 6px; }
.fw-stats b { color: var(--ink); font-weight: 600; font-variant-numeric: tabular-nums; }
.fw-foot { margin-top: auto; padding-top: 12px; border-top: 1px solid var(--grid); display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px 16px; font-size: 13px; color: var(--ink-2); }
.fw-foot > span { display: flex; flex-wrap: wrap; gap: 4px 14px; }
.fw-foot a { white-space: nowrap; }

/* control tables */
details.fw { background: var(--surface); border-radius: 12px; box-shadow: var(--shadow); margin-top: 10px; scroll-margin-top: 16px; }
details.fw > summary { cursor: pointer; list-style: none; padding: 14px 20px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
details.fw > summary::-webkit-details-marker { display: none; }
details.fw > summary::before, details.test > summary::before { content: ""; width: 7px; height: 7px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(-45deg); transition: transform 0.15s; flex: none; margin-right: 2px; }
details[open].fw > summary::before, details[open].test > summary::before { transform: rotate(45deg); }
details.fw > summary .t { font-weight: 600; }
details.fw > summary .c { margin-left: auto; font-size: 13px; color: var(--ink-2); }
details.fw[open] > summary { border-bottom: 1px solid var(--grid); }
.fw-meta { padding: 16px 20px 4px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px 24px; font-size: 13px; }
.fw-meta dt { color: var(--muted); font-size: 12px; }
.fw-meta dd { margin: 0; }
.fw-note { padding: 8px 20px 0; font-size: 13px; color: var(--ink-2); max-width: 900px; }
.fw-table { padding: 8px 10px 10px; }
.links a { white-space: nowrap; }
.more-links > summary { cursor: pointer; color: var(--link); font-size: 12px; }

/* filters and tests */
.filters { position: sticky; top: 0; z-index: 5; background: var(--page); padding: 12px 0; border-bottom: 1px solid var(--grid); }
.frow { display: flex; flex-wrap: wrap; gap: 10px 12px; align-items: center; }
.frow + .frow { margin-top: 10px; }
.fsep { width: 1px; height: 22px; background: var(--grid); }
.filters input[type="search"], .filters select { font: inherit; font-size: 14px; color: var(--ink); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 7px 10px; }
.filters input[type="search"] { min-width: 200px; flex: 1 1 240px; }
.filters select { max-width: 230px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 500; border: 1px solid var(--border); border-radius: 999px; padding: 4px 12px; background: var(--surface); cursor: pointer; user-select: none; transition: background-color 0.2s, border-color 0.2s; }
.chip:hover { background: var(--accent-wash); }
.chip:has(input:checked) { border-color: var(--accent); background: var(--accent-wash); }
.chip input { margin: 0; accent-color: var(--accent-strong); }
.count { font-size: 13px; color: var(--ink-2); margin-left: auto; }
.test-list { margin-top: 12px; }
details.test { background: var(--surface); border-left: 4px solid var(--neutral); border-radius: 12px; margin-top: 8px; box-shadow: var(--shadow); scroll-margin-top: 150px; overflow: hidden; }
details.test[data-status="Fail"] { border-left-color: var(--fail); }
details.test[data-status="Error"] { border-left-color: var(--serious); }
details.test[data-status="Unknown"] { border-left-color: var(--unknown); }
details.test[data-status="Pass"] { border-left-color: var(--good); }
details.test > summary { list-style: none; cursor: pointer; padding: 12px 16px; display: grid; grid-template-columns: auto 120px 130px minmax(0, 1fr) auto; gap: 14px; align-items: center; }
details.test > summary::-webkit-details-marker { display: none; }
details.test > summary:hover { background: var(--wash); }
details.test[open] > summary { border-bottom: 1px solid var(--grid); }
.tid { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; color: var(--muted); display: block; }
.ttitle { font-weight: 600; }
.tcounts { font-size: 13px; color: var(--ink-2); white-space: nowrap; font-variant-numeric: tabular-nums; }
.tbody { padding: 20px; }
.tcols { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: 32px; }
.tbody h4 { font-size: 12px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); margin: 0 0 6px; }
.tbody h4.sp { margin-top: 24px; }
.fix { background: var(--accent-wash); border: 1px solid var(--accent); border-radius: 8px; padding: 12px 14px; margin-bottom: 4px; }
.fix h4 { color: var(--accent-strong); }
.fix p { margin: 0; }
.facts { margin: 0 0 16px; display: grid; grid-template-columns: auto 1fr; gap: 6px 14px; font-size: 13px; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; }
.plain { list-style: none; padding: 0; margin: 0 0 16px; font-size: 13px; }
.plain li { margin-bottom: 6px; overflow-wrap: anywhere; }
.reason { font-size: 13px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; margin-bottom: 16px; }
.map-table td, .map-table th { padding: 7px 10px; }
.map-table .fwl { white-space: nowrap; font-weight: 600; }
.map-table .fwv { color: var(--ink-2); font-size: 12.5px; }
.rname { font-weight: 600; overflow-wrap: anywhere; }
.rmeta { color: var(--ink-2); font-size: 12px; }
.rid { color: var(--muted); font-size: 11px; word-break: break-all; font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }
.rlink { overflow-wrap: anywhere; }
.evidence { font-size: 12px; color: var(--ink-2); overflow-wrap: anywhere; }
.evidence .ek { color: var(--ink); font-weight: 600; }
details.findings { margin-top: 12px; }
.empty { color: var(--ink-2); }

/* sources */
.src-table td:first-child { min-width: 180px; }
.defs { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; font-size: 14px; margin: 0; }
.defs dt { font-weight: 600; }
.defs dd { margin: 0; color: var(--ink-2); }
footer.foot { max-width: 1320px; margin: 0 auto; padding: 24px; border-top: 1px solid var(--grid); font-size: 12px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 8px 24px; justify-content: space-between; align-items: center; }
.made { display: inline-flex; align-items: center; gap: 8px; }
.made img { width: 32px; height: 22px; flex: none; }

#tip { position: fixed; z-index: 20; pointer-events: none; background: var(--surface); color: var(--ink); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; font-size: 13px; box-shadow: var(--shadow); max-width: 300px; }
#tip strong { display: block; font-weight: 600; }
#tip span { color: var(--ink-2); }

@media (max-width: 1100px) {
  .layout { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .toc { display: none; }
  .fw-grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 760px) {
  .cover-inner { padding: 20px 16px 28px; }
  .cover h1 { font-size: 28px; }
  .layout { padding: 0 16px 48px; }
  .exec { grid-template-columns: minmax(0, 1fr); }
  .kpis { grid-template-columns: repeat(2, 1fr); }
  .kpi:nth-child(3) { border-left: 0; padding-left: 0; }
  .row, .row.has-extra { grid-template-columns: minmax(0, 1fr); gap: 4px; }
  .row-extra { text-align: left; }
  .two, .tcols { grid-template-columns: minmax(0, 1fr); }
  details.test > summary { grid-template-columns: auto minmax(0, 1fr); }
  details.test > summary .sevcol, details.test > summary .tcounts { display: none; }
  details.test > summary .ttl { grid-column: 1 / -1; }
  .card { padding: 18px; }
}
@media print {
  :root, :root[data-theme="dark"] { color-scheme: light; --page: #ffffff; --surface: #ffffff; --surface-2: #f8fafc; --ink: #1e293b; --ink-2: #475569; --muted: #64748b; --grid: #e2e8f0; --axis: #cbd5e1; --border: #cbd5e1; --link: #007ea3; --wash: #f0f9ff; --accent: #00acd7; --accent-strong: #007ea3; --accent-wash: #f0f9ff; --fail: #dc2626; --good: #16a34a; --on-good: #ffffff; --pass-bar: #94a3b8; --neutral: #cbd5e1; --on-neutral: #1e293b; --shadow: none; --up: #15803d; --down: #b91c1c; }
  html { scroll-behavior: auto; }
  .card, details.fw { border: 1px solid var(--border); }
  details.test { border: 1px solid var(--border); border-left-width: 4px; }
  .layout { display: block; padding: 0; max-width: none; }
  .toc, .filters, .cover-actions, #tip, .table-view, .more-links > summary { display: none !important; }
  .cover, .seg, .dot, .sw, .pips i, .meter, details.test, .fix { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  .section { break-before: page; padding-top: 0; }
  #summary { break-before: auto; padding-top: 24px; }
  .card, details.test, .row, tr { break-inside: avoid; }
  .section-head { break-after: avoid; }
  details.test[hidden] { display: none; }
}
'@

$script = @'
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const root = document.documentElement;

  const toggle = $('#theme');
  const labels = { auto: 'Theme: automatic', light: 'Theme: light', dark: 'Theme: dark' };
  function applyTheme(theme) {
    if (theme === 'light' || theme === 'dark') { root.setAttribute('data-theme', theme); } else { root.removeAttribute('data-theme'); theme = 'auto'; }
    toggle.textContent = labels[theme];
    toggle.dataset.theme = theme;
  }
  let stored = null;
  try { stored = localStorage.getItem('azure-report-theme'); } catch (e) { stored = null; }
  applyTheme(stored);
  toggle.addEventListener('click', () => {
    const next = { auto: 'light', light: 'dark', dark: 'auto' }[toggle.dataset.theme || 'auto'];
    applyTheme(next);
    try { localStorage.setItem('azure-report-theme', next); } catch (e) { }
  });
  $('#print').addEventListener('click', () => window.print());

  const tip = $('#tip');
  function showTip(el, x, y) {
    const value = document.createElement('strong');
    value.textContent = el.getAttribute('data-tip');
    const label = document.createElement('span');
    label.textContent = el.getAttribute('data-sub') || '';
    tip.replaceChildren(value, label);
    tip.hidden = false;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, x + 12)) + 'px';
    tip.style.top = Math.max(8, y - h - 12) + 'px';
  }
  function hideTip() { tip.hidden = true; }
  $$('[data-tip]').forEach(el => {
    el.addEventListener('pointermove', e => showTip(el, e.clientX, e.clientY));
    el.addEventListener('pointerleave', hideTip);
    el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); showTip(el, r.left + r.width / 2, r.top); });
    el.addEventListener('blur', hideTip);
  });

  const tocLinks = $$('.toc a');
  if ('IntersectionObserver' in window && tocLinks.length) {
    const visible = new Map();
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => visible.set(entry.target.id, entry.isIntersecting));
      const current = tocLinks.find(a => visible.get(a.getAttribute('href').slice(1)));
      if (current) { tocLinks.forEach(a => a.classList.toggle('active', a === current)); }
    }, { rootMargin: '-10% 0px -70% 0px' });
    $$('.section').forEach(section => observer.observe(section));
  }

  const cards = $$('details.test');
  const search = $('#f-search'), category = $('#f-category'), framework = $('#f-framework'), count = $('#f-count'), empty = $('#f-empty');
  function checked(name) { return new Set($$('input[name="' + name + '"]:checked').map(i => i.value)); }
  function applyFilters() {
    const q = search.value.trim().toLowerCase();
    const statuses = checked('status'), severities = checked('severity');
    let shown = 0;
    cards.forEach(card => {
      const ok = statuses.has(card.dataset.status) && severities.has(card.dataset.severity)
        && (!category.value || card.dataset.category === category.value)
        && (!framework.value || card.dataset.frameworks.split(' ').includes(framework.value))
        && (!q || card.dataset.search.includes(q));
      card.hidden = !ok;
      if (ok) { shown++; }
    });
    count.textContent = 'Showing ' + shown + ' of ' + cards.length + ' tests';
    empty.hidden = shown > 0;
  }
  function resetFilters() {
    search.value = ''; category.value = ''; framework.value = '';
    $$('input[name="status"], input[name="severity"]').forEach(i => { i.checked = true; });
  }
  [search, category, framework].forEach(el => el.addEventListener('input', applyFilters));
  $$('input[name="status"], input[name="severity"]').forEach(el => el.addEventListener('change', applyFilters));
  $('#f-reset').addEventListener('click', () => { resetFilters(); applyFilters(); });
  document.addEventListener('click', e => {
    const link = e.target.closest('a[href^="#"]');
    if (!link) { return; }
    const target = document.getElementById(decodeURIComponent(link.getAttribute('href').slice(1)));
    if (!target || target.tagName !== 'DETAILS') { return; }
    if (target.hidden) { resetFilters(); applyFilters(); }
    target.open = true;
  });
  applyFilters();

  let printOpened = [];
  window.addEventListener('beforeprint', () => {
    printOpened = cards.filter(c => !c.hidden).flatMap(c => [c, ...$$('details', c)]).filter(d => !d.open);
    printOpened.forEach(d => { d.open = true; });
  });
  window.addEventListener('afterprint', () => { printOpened.forEach(c => { c.open = false; }); printOpened = []; });
})();
'@

#region cover and navigation

$heading = if ($Organization) { $Organization } else { $subscription.subscriptionName }
Add '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
Add "<title>$(Enc "$Title, $heading")</title>"
Add "<link rel=""icon"" href=""data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M8 1l6 2.5v4c0 3.5-2.6 6.3-6 7.5-3.4-1.2-6-4-6-7.5v-4z' fill='%23256abf'/%3E%3C/svg%3E"">"
Add "<style>$css</style></head><body>"
Add '<header class="cover"><div class="cover-inner"><div class="cover-top">'
Add "<span class=""eyebrow"">$(Enc $Title)</span><span class=""pill"">Confidential</span>"
Add '<div class="cover-actions"><button type="button" class="btn ghost" id="print">Print or save as PDF</button><button type="button" class="btn ghost" id="theme">Theme: automatic</button></div></div>'
Add "<h1>$(Enc $heading)</h1>"
$coverSub = if ($Organization) { "Azure subscription $($subscription.subscriptionName)" } else { 'Azure subscription' }
Add "<p class=""cover-sub"">$(Enc $coverSub)</p>"
Add '<dl class="cover-meta">'
foreach ($item in @(
        , @('Subscription ID', $subscription.subscriptionId)
        , @('Tenant ID', $subscription.tenantId)
        , @('Data collected', (Format-Date $subscription.startedAt))
        , @('Report based on', "$($results.analyzer.tests) tests, analyzer $($results.analyzer.version)")
    )) { Add "<div><dt>$(Enc $item[0])</dt><dd>$(Enc $item[1])</dd></div>" }
Add '</dl></div></header>'

$sections = [System.Collections.Generic.List[object]]::new()
$sections.Add(@('summary', 'Executive summary', $null))
if ($comparison -or $trendPoints.Count -ge 2) {
    $scoredRuns = @($trendPoints | Where-Object { $null -ne $_.Score }).Count
    #the badge counts what the entry is about: runs for a trend, changed findings for a plain comparison
    if ($scoredRuns -ge 2) { $sections.Add(@('changes', 'Trend', $scoredRuns)) }
    else { $sections.Add(@('changes', 'Changes', $comparison.counts.newFailures + $comparison.counts.resolved)) }
}
$sections.Add(@('priorities', 'Priorities', $failingCriticalHigh.Count))
$sections.Add(@('domains', 'Security domains', $categories.Count))
$sections.Add(@('frameworks', 'Frameworks', @($frameworks.Values).Count))
$sections.Add(@('tests', 'Test results', $tests.Count))
$sections.Add(@('sources', 'Scope and sources', $null))
$sectionNumber = @{}
for ($i = 0; $i -lt $sections.Count; $i++) { $sectionNumber[$sections[$i][0]] = '{0:00}' -f ($i + 1) }

Add '<div class="layout"><nav class="toc" aria-label="Report sections"><div class="toc-title">Contents</div><ol>'
foreach ($section in $sections) {
    $countHtml = if ($null -ne $section[2]) { "<span class=""c"">$($section[2])</span>" } else { '' }
    Add "<li><a href=""#$($section[0])""><span class=""n"">$($sectionNumber[$section[0]])</span><span>$(Enc $section[1])</span>$countHtml</a></li>"
}
Add '</ol></nav><main>'

function Add-SectionHead {
    param([string]$Id, [string]$Heading, [string]$Subtitle)
    Add "<section class=""section"" id=""$Id"" aria-labelledby=""h-$Id""><div class=""section-head""><span class=""num"">$($sectionNumber[$Id])</span><div><h2 id=""h-$Id"">$(Enc $Heading)</h2>"
    if ($Subtitle) { Add "<p class=""sub"">$Subtitle</p>" }
    Add '</div></div>'
}

#endregion

#region executive summary

Add-SectionHead -Id 'summary' -Heading 'Executive summary' -Subtitle "Security posture of the subscription on $(Enc (Format-Date $subscription.startedAt -DateOnly)), measured against $(@($frameworks.Values).Count) frameworks and benchmarks."
Add '<div class="card exec"><div class="score"><div class="caption">Posture score</div>'
if ($null -ne $score) {
    $circumference = 2 * [math]::PI * 76
    $arc = [math]::Max(0.01, $circumference * [double]$score / 100)
    Add "<div class=""meter""><svg viewBox=""0 0 180 180"" role=""img"" aria-label=""Posture score $(Format-Number $score) out of 100, rated $(Enc $rating.Label)""><circle class=""track-ring"" cx=""90"" cy=""90"" r=""76""/><circle class=""arc $($rating.Class)"" cx=""90"" cy=""90"" r=""76"" stroke-dasharray=""$(Format-Number $arc) $(Format-Number $circumference)"" transform=""rotate(-90 90 90)""/></svg>"
    Add "<div class=""meter-value"" aria-hidden=""true""><span class=""big"">$(Format-Number $score)</span><span class=""of"">out of 100</span></div></div>"
    Add "<div class=""rating"">$(New-StatusBadge -Status $rating.Status -Label $rating.Label)</div>"
} else {
    Add '<p class="note">No score: no test evaluated any resource.</p>'
}
if ($comparison -and $null -ne $comparison.scoreDelta) {
    $deltaClass = if ($comparison.scoreDelta -ge 0) { 'up' } else { 'down' }
    $sign = if ($comparison.scoreDelta -gt 0) { '+' } else { '' }
    Add "<div class=""delta""><span class=""$deltaClass"">$sign$(Format-Number $comparison.scoreDelta)</span> since $(Enc (Format-Date $comparison.baseline.ingestStartedAt -DateOnly))</div>"
}
Add '</div><div>'

#key findings, generated from the results
$subject = if ($Organization) { "The $($subscription.subscriptionName) subscription" } else { 'The subscription' }
$sentences = [System.Collections.Generic.List[string]]::new()
if ($null -ne $score) { $sentences.Add("$subject scores <b>$(Format-Number $score) out of 100</b>, rated <b>$(Enc $rating.Label.ToLowerInvariant())</b>.") }
if ($failing.Count) {
    $line = "<b>$($failing.Count) of $($evaluated.Count)</b> evaluated tests fail, affecting <b>$($failingResources.Count)</b> resources."
    if ($failingCriticalHigh.Count) {
        $criticalCount = @($failingCriticalHigh | Where-Object severity -eq 'Critical').Count
        $line += " $($failingCriticalHigh.Count) of these failures are rated Critical or High$(if ($criticalCount) { " ($criticalCount Critical)" }) and should be addressed first."
    } else { $line += ' None of the failures is rated Critical or High.' }
    $sentences.Add($line)
    $weakest = @($categoryRows | Where-Object { $_.Buckets.Fail } | Select-Object -First 2)
    if ($weakest.Count -eq 2) { $sentences.Add("Most failures are in <b>$(Enc $weakest[0].Label)</b> ($($weakest[0].Buckets.Fail) of $($weakest[0].Evaluated) tests) and <b>$(Enc $weakest[1].Label)</b> ($($weakest[1].Buckets.Fail) of $($weakest[1].Evaluated)).") }
    elseif ($weakest.Count -eq 1) { $sentences.Add("Most failures are in <b>$(Enc $weakest[0].Label)</b> ($($weakest[0].Buckets.Fail) of $($weakest[0].Evaluated) tests).") }
} elseif ($evaluated.Count) {
    $sentences.Add("All $($evaluated.Count) evaluated tests pass.")
}
if ($comparison) {
    $line = "Since $(Enc (Format-Date $comparison.baseline.ingestStartedAt -DateOnly)), $($comparison.counts.newFailures) findings started failing and $($comparison.counts.resolved) were resolved."
    #a failure that became Unknown was not fixed, so it must never be read as progress
    if ($comparison.counts.lostVisibility) { $line += " A further <b>$($comparison.counts.lostVisibility)</b> went from failing to unknown because the data needed to judge them was not collected this time, so the score is not comparable." }
    $sentences.Add($line)
}
if ($notEvaluated.Count) { $sentences.Add("$($notEvaluated.Count) tests could not be evaluated because the data they need was not collected; see <a href=""#tests"">test results</a>.") }
Add '<h3>Key findings</h3>'
foreach ($sentence in $sentences) { Add "<p class=""lead"">$sentence</p>" }

$evaluatedFindings = $findingTotals.Fail + $findingTotals.Pass + $findingTotals.Unknown
Add '<div class="kpis">'
foreach ($kpi in @(
        , @('Failing tests', $failing.Count, "of $($evaluated.Count)", 'evaluated tests')
        , @('Critical and high', $failingCriticalHigh.Count, '', 'failing tests')
        , @('Affected resources', $failingResources.Count, '', 'with a failing finding')
        , @('Failing findings', $findingTotals.Fail, "of $evaluatedFindings", 'resource results')
    )) {
    $of = if ($kpi[2]) { " <small>$(Enc $kpi[2])</small>" } else { '' }
    Add "<div class=""kpi""><div class=""label"">$(Enc $kpi[0])</div><div class=""value"">$($kpi[1])$of</div><div class=""hint"">$(Enc $kpi[3])</div></div>"
}
Add '</div></div></div>'

$severityScale = ($severityRows | ForEach-Object Evaluated | Measure-Object -Maximum).Maximum
Add '<div class="card" role="group" aria-label="Test results by severity"><h3>Test results by severity</h3>'
Add $legend
foreach ($row in $severityRows) {
    Add (New-ChartRow -LabelHtml (New-SeverityChip $row.Label) -Buckets $row.Buckets -Scale $severityScale -Label $row.Label -Unit 'tests' -Note $(if ($row.Buckets.NotApplicable) { "$($row.Buckets.NotApplicable) not applicable" }))
}
Add (New-TableView -FirstColumn 'Severity' -Rows $severityRows)
Add '</div></section>'

#endregion

#region changes since baseline

#history sets the baseline, so a trend always comes with a comparison
if ($comparison) {
    $logicChanged = @($comparison.tests.changed | Where-Object { $_.logicChanged })
    $lostVisibility = @($comparison.lostVisibility)
    $scored = @($trendPoints | Where-Object { $null -ne $_.Score })
    $heading = if ($scored.Count -ge 2) { 'Trend and changes' } else { 'Changes since the previous analysis' }
    $subtitle = "Compared with data collected on $(Enc (Format-Date $comparison.baseline.ingestStartedAt)). Findings are matched on test and resource."
    if ($scored.Count -ge 2) {
        $movement = [math]::Round([double]$scored[-1].Score - [double]$scored[0].Score, 1)
        $direction = if ($movement -gt 0) { "up $(Format-Number $movement) point(s)" } elseif ($movement -lt 0) { "down $(Format-Number ([math]::Abs($movement))) point(s)" } else { 'unchanged' }
        $subtitle = "$($scored.Count) analyses of this subscription since $(Enc ($scored[0].StartedAt.ToString('d MMMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture))). The posture score is $direction over that period. $subtitle"
    }
    Add-SectionHead -Id 'changes' -Heading $heading -Subtitle $subtitle

    if ($scored.Count -ge 2) {
        Add '<div class="card" role="group" aria-label="Posture score over time"><h3>Posture score over time</h3>'
        Add (New-TrendChart -Points $trendPoints)

        #result mix per run: a different measure on a different scale, so it gets its own bars rather than a second axis
        $trendRows = @(foreach ($point in $trendPoints) {
                $buckets = [ordered]@{ Fail = [int]$point.Tests.Fail; Unknown = [int]$point.Tests.Unknown + [int]$point.Tests.Error; Pass = [int]$point.Tests.Pass; NotApplicable = [int]$point.Tests.NotApplicable; NotAssessed = 0 }
                [pscustomobject]@{
                    Label     = $point.StartedAt.ToString('d MMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture) + $(if ($point.IsCurrent) { ' (this run)' } else { '' })
                    Buckets   = $buckets
                    Evaluated = $buckets.Fail + $buckets.Unknown + $buckets.Pass
                    Score     = $point.Score
                    TestCount = $point.TestCount
                }
            })
        $trendScale = ($trendRows | ForEach-Object Evaluated | Measure-Object -Maximum).Maximum
        Add '<h3 class="sp" style="margin-top:26px">Test results per run</h3>'
        Add $legend
        foreach ($row in $trendRows) {
            Add (New-ChartRow -LabelHtml (Enc $row.Label) -Buckets $row.Buckets -Scale $trendScale -Label $row.Label -Unit 'tests' -Note $(if ($null -ne $row.Score) { "score $(Format-Number $row.Score)" }))
        }
        Add '<details class="table-view"><summary>Table view</summary><div class="scroll"><table><thead><tr><th>Analysis</th><th class="num">Score</th><th class="num">Change</th><th class="num">Failing</th><th class="num">Unknown or error</th><th class="num">Passing</th><th class="num">Not applicable</th><th class="num">Tests</th></tr></thead><tbody>'
        $previousScore = $null
        foreach ($row in $trendRows) {
            $delta = if ($null -ne $row.Score -and $null -ne $previousScore) { $d = [math]::Round([double]$row.Score - [double]$previousScore, 1); "$(if ($d -gt 0) { '+' })$(Format-Number $d)" } else { '' }
            if ($null -ne $row.Score) { $previousScore = $row.Score }
            Add "<tr><td>$(Enc $row.Label)</td><td class=""num"">$(if ($null -ne $row.Score) { Format-Number $row.Score } else { '-' })</td><td class=""num"">$(Enc $delta)</td><td class=""num"">$($row.Buckets.Fail)</td><td class=""num"">$($row.Buckets.Unknown)</td><td class=""num"">$($row.Buckets.Pass)</td><td class=""num"">$($row.Buckets.NotApplicable)</td><td class=""num"">$($row.TestCount)</td></tr>"
        }
        Add '</tbody></table></div></details></div>'
    }

    Add '<div class="card"><div class="kpis" style="margin-top:0;border-top:0">'
    foreach ($kpi in @(
            , @('New failures', $comparison.counts.newFailures, 'failing now, not before')
            , @('Resolved', $comparison.counts.resolved, 'demonstrably fixed or gone')
            , @('Still failing', $comparison.counts.stillFailing, 'failing in both analyses')
            , @('Lost visibility', $lostVisibility.Count, 'failing before, unknown now')
            , @('Changed test logic', $logicChanged.Count, 'compare these with care')
        )) { Add "<div class=""kpi"" style=""padding-top:0""><div class=""label"">$(Enc $kpi[0])</div><div class=""value"">$($kpi[1])</div><div class=""hint"">$(Enc $kpi[2])</div></div>" }
    Add '</div>'
    if ($lostVisibility.Count) {
        Add "<p class=""note"" style=""margin:16px 0 0"">$($lostVisibility.Count) finding(s) went from failing to unknown because the data needed to judge them was not collected this time. They were not fixed, and the posture score is not comparable with the baseline until the collection gap is closed.</p>"
    }
    if ($logicChanged.Count) {
        $links = ($logicChanged | ForEach-Object { '<a href="#{0}">{0}</a>' -f (Enc $_.id) }) -join ', '
        Add "<p class=""note"" style=""margin:16px 0 0"">Tests whose logic changed since the baseline: $links.</p>"
    }
    Add '</div>'
    foreach ($list in @(@('New failures', $comparison.newFailures), @('Lost visibility', $lostVisibility), @('Resolved', $comparison.resolved))) {
        $items = @($list[1] | Where-Object { $_ })
        if (-not $items.Count) { continue }
        $groups = @($items | Group-Object { $_.testId } | Sort-Object { $severityOrder[$_.Group[0].severity] }, { - $_.Count }, Name)
        Add "<div class=""card""><h3>$(Enc $list[0]) <span class=""muted"" style=""font-weight:400"">$($items.Count) findings in $($groups.Count) tests</span></h3><div class=""scroll""><table class=""chg""><thead><tr><th>Severity</th><th>Test</th><th class=""num"">Findings</th><th>Resources</th></tr></thead><tbody>"
        foreach ($group in ($groups | Select-Object -First 25)) {
            $shown = New-ResourceNameList -Findings $group.Group -Max 4
            Add "<tr><td>$(New-SeverityChip $group.Group[0].severity)</td><td><a href=""#$(Enc $group.Name)"">$(Enc $testsById[$group.Name].title)</a><span class=""tid"">$(Enc $group.Name)</span></td><td class=""num"">$($group.Count)</td><td>$shown</td></tr>"
        }
        Add '</tbody></table></div>'
        if ($groups.Count -gt 25) { Add "<p class=""note"">And $($groups.Count - 25) more tests, listed with their findings below.</p>" }
        Add "<details class=""more findings""><summary>Show all $($items.Count) findings</summary><div class=""scroll""><table><thead><tr><th>Test</th><th>Resource</th><th>Change</th><th>Detail</th></tr></thead><tbody>"
        foreach ($item in ($items | Sort-Object { $severityOrder[$_.severity] }, { $_.testId }, { $_.resourceName })) {
            $change = if (-not $item.to) { "$($statusLabels[$item.from]), resource no longer present" } elseif (-not $item.from) { "new resource, $($statusLabels[$item.to])" } else { "$($statusLabels[$item.from]) to $($statusLabels[$item.to])" }
            Add "<tr><td class=""mono""><a href=""#$(Enc $item.testId)"">$(Enc $item.testId)</a></td><td>$(New-ResourceLink -Name $item.resourceName -ResourceId $item.resourceId)<div class=""rid"">$(Enc $item.resourceId)</div></td><td>$(Enc $change)</td><td>$(Enc $item.detail)</td></tr>"
        }
        Add '</tbody></table></div></details></div>'
    }
    Add '</section>'
}

#endregion

#region priorities

Add-SectionHead -Id 'priorities' -Heading 'Priorities' -Subtitle 'Failing tests rated Critical or High, most severe and most widespread first. Each links to its remediation.'
if ($failingCriticalHigh.Count) {
    Add '<div class="card flush scroll"><table class="prio"><thead><tr><th>#</th><th>Severity</th><th>Test</th><th>Domain</th><th class="num">Failing</th><th>Affected resources</th></tr></thead><tbody>'
    $rank = 0
    foreach ($test in ($failingCriticalHigh | Sort-Object { $severityOrder[$_.severity] }, { - $_.counts.Fail }, id)) {
        $rank++
        $shown = New-ResourceNameList -Findings @($test.findings | Where-Object status -eq 'Fail') -Max 3
        Add "<tr><td class=""rank"">$rank</td><td>$(New-SeverityChip $test.severity)</td><td><a href=""#$(Enc $test.id)"">$(Enc $test.title)</a><span class=""tid"">$(Enc $test.id)</span></td><td>$(Enc $test.category)</td><td class=""num"">$($test.counts.Fail)</td><td>$shown</td></tr>"
    }
    Add '</tbody></table></div>'
} else {
    Add '<div class="card"><p class="empty" style="margin:0">No failing tests rated Critical or High.</p></div>'
}
Add '</section>'

#endregion

#region security domains

Add-SectionHead -Id 'domains' -Heading 'Security domains' -Subtitle 'Tests grouped by Microsoft cloud security benchmark domain, most failures first. Bar length is the number of evaluated tests.'
$domainScale = ($categoryRows | ForEach-Object Evaluated | Measure-Object -Maximum).Maximum
Add "<div class=""card"" role=""group"" aria-label=""Test results by security domain"">$legend"
foreach ($row in $categoryRows) {
    Add (New-ChartRow -LabelHtml (Enc $row.Label) -Buckets $row.Buckets -Scale $domainScale -Label $row.Label -Unit 'tests' -Note $(if ($row.Buckets.NotApplicable) { "$($row.Buckets.NotApplicable) not applicable" }))
}
Add (New-TableView -FirstColumn 'Domain' -Rows $categoryRows)
Add '</div></section>'

#endregion

#region frameworks

Add-SectionHead -Id 'frameworks' -Heading 'Framework results' -Subtitle 'Every framework with all its controls. A control with tests takes the worst result of them: full means the tests check everything about the control that Azure configuration can show, partial that the control asks more. Controls without a test need manual evidence or are outside Azure scope.'
Add "<p class=""note"" style=""margin:-8px 0 16px"">$(Enc $auditDisclaimer)</p>"
Add $legend
Add '<div class="fw-grid">'
foreach ($fw in $frameworks.Values) {
    Add "<article class=""card fwcard""><div class=""fw-head""><div><h3>$(Enc $fw.Label)</h3><div class=""fw-name"">$(Enc $fw.Name)</div></div>"
    if ($fw.Version) { Add "<span class=""ver-chip"" title=""Version"">$(Enc $fw.Version)</span>" }
    Add '</div>'
    if ($fw.Controls.Count) {
        $total = $fw.Buckets.Fail + $fw.Buckets.Unknown + $fw.Buckets.Pass
        Add "<div class=""fw-figure""><span class=""big"">$($fw.Buckets.Fail)</span><span class=""of"">of $total controls with a result failing</span></div>"
        Add (New-StackBar -Buckets $fw.Buckets -Scale $total -Label $fw.Label -Unit 'controls')
        Add "<div class=""fw-stats""><span><i class=""sw b-fail""></i><b>$($fw.Buckets.Fail)</b> failing</span><span><i class=""sw b-unknown""></i><b>$($fw.Buckets.Unknown)</b> unknown</span><span><i class=""sw b-pass""></i><b>$($fw.Buckets.Pass)</b> passing</span><span><b>$($fw.Buckets.NotApplicable)</b> not applicable</span></div>"
        Add "<p class=""fw-cov"">$(Enc (Get-CoverageText $fw))</p>"
    } else {
        Add "<p class=""fw-cov"">$(Enc $fw.Note)</p>"
    }
    $footMeta = @($(if ($fw.Publisher) { "<span>$(Enc $fw.Publisher)</span>" }), $(if ($fw.Controls.Count) { "<span>$(Enc (Get-MappingLabel $fw.Mapping))</span>" })) | Where-Object { $_ }
    $footLinks = @($(if ($fw.Url) { New-ExternalLink -Url $fw.Url -Text 'Source' }), $(if ($fw.Controls.Count) { "<a href=""#fw-$($fw.Slug)"">Controls</a>" })) | Where-Object { $_ }
    Add "<div class=""fw-foot""><span>$($footMeta -join '')</span><span>$($footLinks -join '')</span></div></article>"
}
Add '</div>'
Add (New-TableView -FirstColumn 'Framework' -Rows @($frameworks.Values) -WithNotAssessed)

Add '<h3 style="margin-top:32px">Controls per framework</h3>'
foreach ($fw in @($frameworks.Values)) {
    $total = $fw.Buckets.Fail + $fw.Buckets.Unknown + $fw.Buckets.Pass
    Add "<details class=""fw"" id=""fw-$($fw.Slug)""><summary><span class=""t"">$(Enc $fw.Label)</span><span class=""muted"">$(Enc $fw.Name)</span><span class=""c"">$($fw.Buckets.Fail) failing of $total with a result</span></summary>"
    Add '<dl class="fw-meta">'
    foreach ($item in @(
            , @('Version', $fw.Version)
            , @('Publisher', $fw.Publisher)
            , @('Mapping', (Get-MappingLabel $fw.Mapping))
            , @('Coverage', (Get-CoverageText $fw))
        )) { if ($item[1]) { Add "<div><dt>$(Enc $item[0])</dt><dd>$(Enc $item[1])</dd></div>" } }
    $sourceLinks = @($(if ($fw.Url) { New-ExternalLink -Url $fw.Url -Text 'Source documentation' }), $(if ($fw.Download) { New-ExternalLink -Url $fw.Download -Text 'Download' })) | Where-Object { $_ }
    if ($sourceLinks) { Add "<div><dt>Source</dt><dd>$($sourceLinks -join ' &middot; ')</dd></div>" }
    Add '</dl>'
    if ($fw.Note) { Add "<p class=""fw-note"">$(Enc $fw.Note)</p>" }
    $automated = @($fw.Controls | Where-Object Applicability -eq 'automated')
    if ($automated.Count) {
        Add '<div class="fw-table scroll"><table><thead><tr><th>Control</th><th>Title</th><th>Result</th><th>Coverage</th><th>Tests</th></tr></thead><tbody>'
        foreach ($control in $automated) {
            $testLinks = @($control.Tests | ForEach-Object { '<a href="#{0}">{0}</a>' -f (Enc $_) })
            $links = ($testLinks | Select-Object -First 8) -join ', '
            if ($testLinks.Count -gt 8) {
                $rest = ($testLinks | Select-Object -Skip 8) -join ', '
                $links += "<details class=""more-links""><summary>$($testLinks.Count - 8) more</summary>$rest</details>"
            }
            Add "<tr><td style=""white-space:nowrap"">$(Get-ControlLink -Id $control.Id -Url $control.Url)</td><td>$(Enc $control.Title)</td><td>$(New-StatusBadge $control.Status)</td><td>$(Enc $control.Coverage)</td><td class=""links"">$links</td></tr>"
        }
        Add '</tbody></table></div>'
    }
    $manual = @($fw.Controls | Where-Object Applicability -eq 'manual')
    if ($manual.Count) {
        Add "<details class=""more"" style=""margin-top:10px""><summary>$($manual.Count) controls that need manual evidence</summary><div class=""fw-table scroll""><table><thead><tr><th>Control</th><th>Title</th></tr></thead><tbody>"
        foreach ($control in $manual) {
            $remark = if ($control.Assessment -eq 'Manual') { " <span class='note'>(manual in CIS)</span>" } else { '' }
            Add "<tr><td style=""white-space:nowrap"">$(Get-ControlLink -Id $control.Id -Url $control.Url)</td><td>$(Enc $control.Title)$remark</td></tr>"
        }
        Add '</tbody></table></div></details>'
    }
    if ($fw.OutOfScope) { Add "<p class=""note"" style=""margin:10px 0 0"">$($fw.OutOfScope) controls do not concern the Azure environment (people, physical security, organization-wide governance, end-user devices, software development) and are not listed.</p>" }
    Add '</details>'
}
Add '</section>'

#endregion

#region test results

Add-SectionHead -Id 'tests' -Heading 'Test results' -Subtitle 'Every test with what it checks, why it matters, how to fix it, the framework controls it maps to and the result per resource. Failing tests are shown first.'
Add '<div class="filters" role="search"><div class="frow"><input type="search" id="f-search" placeholder="Search tests, controls or resources" aria-label="Search tests, controls or resources">'
Add '<select id="f-category" aria-label="Domain"><option value="">All domains</option>'
foreach ($category in $categories) { Add "<option value=""$(Enc $category)"">$(Enc $category)</option>" }
Add '</select><select id="f-framework" aria-label="Framework"><option value="">All frameworks</option>'
foreach ($fw in @($frameworks.Values)) { Add "<option value=""$($fw.Slug)"">$(Enc $fw.Label)</option>" }
Add '</select><button type="button" id="f-reset" class="btn">Show all</button></div><div class="frow"><div class="chips" role="group" aria-label="Result">'
foreach ($status in 'Fail', 'Error', 'Unknown', 'Pass', 'NotApplicable') {
    $count = @($tests | Where-Object status -eq $status).Count
    if (-not $count) { continue }
    $checked = if ($status -in 'Fail', 'Error', 'Unknown') { ' checked' } else { '' }
    Add "<label class=""chip""><input type=""checkbox"" name=""status"" value=""$status""$checked>$(New-StatusBadge $status) $count</label>"
}
Add '</div><span class="fsep" aria-hidden="true"></span><div class="chips" role="group" aria-label="Severity">'
foreach ($severity in 'Critical', 'High', 'Medium', 'Low', 'Informational') {
    if (-not @($tests | Where-Object severity -eq $severity).Count) { continue }
    Add "<label class=""chip""><input type=""checkbox"" name=""severity"" value=""$severity"" checked>$(New-SeverityChip $severity)</label>"
}
Add '</div><span class="count" id="f-count"></span></div></div><div class="test-list">'

foreach ($test in $tests) {
    $testTags = @(Get-TestControls $test)
    $testFrameworks = @($frameworks.Keys | Where-Object { @($testTags | ForEach-Object Framework) -contains $_ } | ForEach-Object { $frameworks[$_].Slug })
    $searchText = (@($test.id, $test.title, $test.service, $test.category) + @($testTags | ForEach-Object Id) + @($test.findings | ForEach-Object resourceName) | Where-Object { $_ }) -join ' '
    $evaluatedCount = $test.counts.Pass + $test.counts.Fail + $test.counts.Unknown
    $countsText = switch ($test.status) {
        'Fail' { "$($test.counts.Fail) of $evaluatedCount failing" }
        'Pass' { "$($test.counts.Pass) passing" }
        'Unknown' { if ($test.counts.Unknown) { "$($test.counts.Unknown) of $evaluatedCount unknown" } else { 'data missing' } }
        'NotApplicable' { 'nothing in scope' }
        default { 'test error' }
    }
    Add "<details class=""test"" id=""$(Enc $test.id)"" data-status=""$($test.status)"" data-severity=""$($test.severity)"" data-category=""$(Enc $test.category)"" data-frameworks=""$($testFrameworks -join ' ')"" data-search=""$(Enc $searchText.ToLowerInvariant())"">"
    Add "<summary>$(New-StatusBadge $test.status)<span class=""sevcol"">$(New-SeverityChip $test.severity)</span><span class=""ttl""><span class=""ttitle"">$(Enc $test.title)</span><span class=""tid"">$(Enc $test.id) &middot; $(Enc $test.service)</span></span><span class=""tcounts"">$(Enc $countsText)</span></summary>"
    Add '<div class="tbody">'
    if ($test.statusReason) { Add "<div class=""reason"">$(Enc $test.statusReason)</div>" }
    Add '<div class="tcols"><div>'
    Add "<h4>What is checked</h4><p>$(Enc $test.description)</p><h4 class=""sp"">Why it matters</h4><p>$(Enc $test.rationale)</p>"
    Add "<div class=""fix""><h4>Remediation</h4><p>$(Enc $test.remediation)</p></div>"
    Add '</div><div>'
    Add "<dl class=""facts""><dt>Domain</dt><dd>$(Enc $test.category)</dd><dt>Service</dt><dd>$(Enc $test.service)</dd><dt>Severity</dt><dd>$(New-SeverityChip $test.severity)</dd><dt>Test version</dt><dd>$(Enc $test.version)</dd></dl>"
    if (@($test.defenderRecommendations).Count) {
        Add '<h4>Defender for Cloud recommendations</h4><ul class="plain">'
        foreach ($item in $test.defenderRecommendations) { Add "<li>$(Enc $item.name)<span class=""tid"">$(Enc $item.id)</span></li>" }
        Add '</ul>'
    }
    if (@($test.azurePolicies).Count) {
        Add '<h4>Azure Policy definitions</h4><ul class="plain">'
        foreach ($item in $test.azurePolicies) { Add "<li>$(Enc $item.name)<span class=""tid"">$(Enc $item.id)</span></li>" }
        Add '</ul>'
    }
    if (@($test.references).Count) {
        Add '<h4>References</h4><ul class="plain">'
        foreach ($reference in $test.references) { Add "<li>$(New-ExternalLink -Url $reference -Text ($reference -replace '^https?://', ''))</li>" }
        Add '</ul>'
    }
    Add '</div></div>'

    #the framework controls this test evidences, with version and source
    if ($testTags.Count) {
        Add '<h4 class="sp">Framework controls</h4><div class="scroll"><table class="map-table"><thead><tr><th>Framework</th><th>Version</th><th>Control</th><th>Title</th><th>Coverage</th></tr></thead><tbody>'
        foreach ($entry in $testTags) {
            $fw = $frameworks[$entry.Framework]
            $extra = @($(if ($entry.Criticality) { $entry.Criticality }), $(if ($entry.Level) { "Level $($entry.Level -replace '^L', '')" })) | Where-Object { $_ }
            $extraHtml = if ($extra) { " <span class=""muted"">($(Enc ($extra -join ', ')))</span>" } else { '' }
            Add "<tr><td class=""fwl""><a href=""#fw-$($fw.Slug)"">$(Enc $fw.Label)</a></td><td class=""fwv"">$(Enc $fw.Version)</td><td style=""white-space:nowrap"">$(Get-ControlLink -Id $entry.Id -Url $entry.Url)</td><td>$(Enc $entry.Title)$extraHtml</td><td>$(Enc $entry.Coverage)</td></tr>"
        }
        Add '</tbody></table></div>'
    }

    $findings = @($test.findings | Sort-Object { $statusOrder[$_.status] }, resourceName)
    if ($findings.Count) {
        Add "<h4 class=""sp"">Resources</h4>"
        #when something fails or is unknown, passing and out-of-scope resources go behind a toggle
        $primary = @($findings | Where-Object { $_.status -in 'Fail', 'Unknown' })
        $secondary = @($findings | Where-Object { $_.status -notin 'Fail', 'Unknown' })
        if (-not $primary.Count) { $primary = $findings; $secondary = @() }
        foreach ($set in @(@('primary', $primary), @('secondary', $secondary))) {
            if (-not @($set[1]).Count) { continue }
            if ($set[0] -eq 'secondary') {
                $passCount = @($set[1] | Where-Object status -eq 'Pass').Count
                $label = @($(if ($passCount) { "$passCount passing" }), $(if ($set[1].Count - $passCount) { "$($set[1].Count - $passCount) not applicable" })) | Where-Object { $_ }
                Add "<details class=""more findings""><summary>Show $(Enc ($label -join ' and ')) resources</summary>"
            }
            Add '<div class="scroll"><table><thead><tr><th>Result</th><th>Resource</th><th>Detail</th><th>Evidence</th></tr></thead><tbody>'
            foreach ($finding in $set[1]) {
                $meta = @($finding.resourceType, $(if ($finding.resourceGroup) { "resource group $($finding.resourceGroup)" })) | Where-Object { $_ }
                Add "<tr><td>$(New-StatusBadge $finding.status)</td><td>$(New-ResourceLink -Name $finding.resourceName -ResourceId $finding.resourceId -Evidence $finding.evidence)<div class=""rmeta"">$(Enc ($meta -join ', '))</div><div class=""rid"">$(Enc $finding.resourceId)</div></td><td>$(Enc $finding.detail)</td><td>$(New-Evidence $finding.evidence)</td></tr>"
            }
            Add '</tbody></table></div>'
            if ($set[0] -eq 'secondary') { Add '</details>' }
        }
    } elseif (-not $test.statusReason) {
        Add '<p class="note" style="margin-top:16px">No resources in scope.</p>'
    }
    Add '</div></details>'
}
Add '</div><p class="empty" id="f-empty" hidden>No tests match the filters.</p></section>'

#endregion

#region scope and sources

Add-SectionHead -Id 'sources' -Heading 'Scope and sources' -Subtitle 'What was assessed, how results are determined, and the version and source of every framework used.'
Add '<div class="two"><div class="card"><h3>Assessment scope</h3><dl class="facts" style="margin:0">'
foreach ($item in @(
        , @('Subscription', "$($subscription.subscriptionName) ($($subscription.subscriptionId))")
        , @('Tenant', $subscription.tenantId)
        , @('Data collected', (Format-Date $subscription.startedAt))
        , @('Collection status', $subscription.status)
        , @('Ingest version', $subscription.ingestVersion)
        , @('Analyzed', (Format-Date $results.analyzedAt))
        , @('Analyzer', "version $($results.analyzer.version), $($results.analyzer.tests) tests, results schema $($results.schemaVersion)")
        , @('Posture score', $results.summary.scoreMethod)
    )) { if ($item[1]) { Add "<dt>$(Enc $item[0])</dt><dd>$(Enc $item[1])</dd>" } }
Add '</dl></div><div class="card"><h3>How to read the results</h3><dl class="defs">'
foreach ($item in @(
        , @('Fail', 'Fail', 'The requirement is not met for at least one resource.')
        , @('Pass', 'Pass', 'The requirement is met for every evaluated resource.')
        , @('Unknown', 'Unknown', 'The data needed was not collected, for example because of a missing permission.')
        , @('Error', 'Error', 'The test could not run; see the test for details.')
        , @('NotApplicable', 'Not applicable', 'No resources of this kind in the subscription.')
        , @('NotAssessed', 'Not assessed', 'A framework control without a test that ran: it needs manual evidence, or its tests were not part of this analysis.')
    )) { Add "<dt>$(New-StatusBadge -Status $item[0] -Label $item[1])</dt><dd>$(Enc $item[2])</dd>" }
Add '</dl></div></div>'

Add '<div class="card flush scroll" style="margin-top:16px"><table class="src-table"><thead><tr><th>Framework</th><th>Version</th><th>Publisher</th><th>Mapping</th><th>Source</th></tr></thead><tbody>'
foreach ($fw in $frameworks.Values) {
    $mapping = Get-MappingLabel $fw.Mapping
    $links = @($(if ($fw.Url) { New-ExternalLink -Url $fw.Url -Text 'Documentation' }), $(if ($fw.Download) { New-ExternalLink -Url $fw.Download -Text 'Download' })) | Where-Object { $_ }
    $retrieved = if ($fw.Retrieved) { "<div class=""muted"" style=""font-size:12px"">checked $(Enc $fw.Retrieved)</div>" } else { '' }
    Add "<tr><td><a href=""#fw-$($fw.Slug)""><b>$(Enc $fw.Label)</b></a><div class=""muted"" style=""font-size:12px"">$(Enc $fw.Name)</div></td><td>$(Enc $fw.Version)</td><td>$(Enc $fw.Publisher)</td><td>$(Enc $mapping)</td><td style=""white-space:nowrap"">$($links -join '<br>')$retrieved</td></tr>"
}
Add '</tbody></table></div>'
Add '<p class="note" style="margin-top:16px">Resource names are links to the Azure portal wherever the portal has a page for the resource. A name without a link has no page to open: either the portal addresses that object differently, or it has no page for a single object of that kind.</p>'
Add "<p class=""note"" style=""margin-top:16px"">Results reflect the configuration at the time the data was collected, read with Reader access and Microsoft Graph read permissions. $(Enc $auditDisclaimer) This report describes weaknesses in the environment in detail: treat it as confidential.</p>"
Add '</section>'

#endregion

Add '</main></div>'
Add "<footer class=""foot""><span>$(Enc $Title), $(Enc $heading)</span><span>Generated $(Enc (Format-Date $results.analyzedAt)) from $(Enc $subscription.folder)</span><span class=""made""><img src=""$jsolveMark"" alt="""" width=""32"" height=""22"">AzCmply by $(New-ExternalLink -Url 'https://www.jsolve.nl' -Text 'JSolve B.V.') &middot; $(New-ExternalLink -Url 'https://github.com/jflieben/AzCmply#readme' -Text 'Documentation')</span></footer>"
Add '<div id="tip" role="tooltip" hidden></div>'
Add "<script>$script</script></body></html>"

$directory = Split-Path -Path $OutputPath
if ($directory -and -not (Test-Path $directory)) { $null = New-Item -ItemType Directory -Force -Path $directory }
[System.IO.File]::WriteAllText($OutputPath, $html.ToString(), [System.Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Path = (Resolve-Path $OutputPath).Path; Tests = $tests.Count; Failing = $failing.Count; PostureScore = $score }
