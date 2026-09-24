#Core of the analyzer: ingestion access, result helpers and test registration. Dot-sourced by Invoke-AzureAnalyze.ps1.

#region ingestion access

$script:Ingest = $null
$script:SupportsDateKind = (Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')

function Read-IngestJson {
    #parses a JSON file; date strings stay strings where PowerShell supports it (7.5+)
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { return $null }
    $text = [System.IO.File]::ReadAllText($Path)
    if ($script:SupportsDateKind) { return , (ConvertFrom-Json -InputObject $text -Depth 200 -NoEnumerate -DateKind String) }
    return , (ConvertFrom-Json -InputObject $text -Depth 200 -NoEnumerate)
}

function Initialize-Ingest {
    param([Parameter(Mandatory = $true)][string]$Path)
    $manifest = Read-IngestJson -Path (Join-Path $Path 'manifest.json')
    if ($null -eq $manifest) { throw "No manifest.json in $Path, not an ingestion folder" }
    $index = Read-IngestJson -Path (Join-Path $Path 'index.json')
    $script:Ingest = @{
        Root           = $Path
        Manifest       = $manifest
        Index          = @($index)
        Cache          = @{}
        Records        = @{}
        SubscriptionId = [string]$manifest.subscription.id
        ReferenceTime  = ConvertTo-UtcDate $manifest.startedAt
    }
}

function Get-IngestData {
    #content of an ingestion file, e.g. 'rbac/roleAssignments'; $null when the file does not exist
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not $script:Ingest.Cache.ContainsKey($Name)) {
        $script:Ingest.Cache[$Name] = Read-IngestJson -Path (Join-Path $script:Ingest.Root "$Name.json")
    }
    return $script:Ingest.Cache[$Name]
}

function Test-IngestSection {
    #true when a section was collected successfully (manifest status ok/partial, or the file exists for sections without status)
    param([Parameter(Mandatory = $true)][string]$Name)
    $section = $script:Ingest.Manifest.sections.$Name
    if ($null -ne $section) { return ($section.status -in 'ok', 'partial') }
    return [System.IO.File]::Exists((Join-Path $script:Ingest.Root "$Name.json"))
}

function Get-IngestSectionProblem {
    #why a section was not collected, from the ingestion itself: 'defender/pricings (HTTP 404 NotFound; resource provider
    #Microsoft.Security is NotRegistered)'. The provider state comes from subscription/providers, never from a guess.
    param([Parameter(Mandatory = $true)][string]$Name)
    $manifest = $script:Ingest.Manifest
    $section = $manifest.sections.$Name
    if ($null -eq $section) {
        if ($Name -like 'identity/*') {
            if ($manifest.parameters.skipGraph) { return "$Name (Entra ID collection was skipped)" }
            if ($manifest.sections.identity.status -eq 'failed') { return "$Name (Entra ID collection failed: $($manifest.sections.identity.message))" }
        }
        if ($Name -like 'resourceGraph/*' -and $manifest.parameters.skipResourceGraph) { return "$Name (Resource Graph collection was skipped)" }
        if ($Name -like 'activityLog/*' -and $manifest.parameters.activityLogDays -eq 0) { return "$Name (activity log collection was skipped)" }
        return "$Name (not in the ingestion)"
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $section.statusCode) {
        $parts.Add($(if ([int]$section.statusCode -eq 0) { 'network error' } else { "HTTP $($section.statusCode)$(if ($section.errorCode) { " $($section.errorCode)" })" }))
    } else {
        $parts.Add([string]$section.status)
    }
    #the failed call names the resource provider; its registration state explains a 404 or 409 on an unused service
    $pattern = '(^|[\\/])' + (@($Name -split '/' | ForEach-Object { [regex]::Escape($_) }) -join '[\\/]') + '\.json$'
    $failure = @(Get-IngestData 'failures') | Where-Object { $_ -and [string]$_.context -match $pattern } | Select-Object -First 1
    if ($failure -and [string]$failure.uri -match '(?i)/providers/(?<namespace>[^/?]+)/') {
        $namespace = $Matches.namespace
        $provider = @(Get-IngestData 'subscription/providers') | Where-Object { $_ -and $_.namespace -eq $namespace } | Select-Object -First 1
        if ($provider -and $provider.registrationState -and $provider.registrationState -ne 'Registered') {
            $parts.Add("resource provider $($provider.namespace) is $($provider.registrationState)")
        }
    }
    return "$Name ($($parts -join '; '))"
}

function Get-AzResourceRecords {
    #resource files (id, type, resource, diagnosticSettings, children, textContent, failures) of the given types
    param([string[]]$Type)
    $typeSet = @($Type | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $script:Ingest.Index) {
        if ($entry.type -eq 'resourceGroup' -or $entry.status -ne 'ok' -or -not $entry.file) { continue }
        if ($typeSet.Count -and $entry.type.ToLowerInvariant() -notin $typeSet) { continue }
        $key = $entry.id.ToLowerInvariant()
        if (-not $script:Ingest.Records.ContainsKey($key)) {
            $script:Ingest.Records[$key] = Read-IngestJson -Path (Join-Path $script:Ingest.Root $entry.file)
        }
        if ($null -ne $script:Ingest.Records[$key]) { $records.Add($script:Ingest.Records[$key]) }
    }
    return $records
}

function Get-AzResourceRecord {
    #one resource file by resource id; $null when not collected
    param([Parameter(Mandatory = $true)][string]$Id)
    $key = $Id.ToLowerInvariant()
    if ($script:Ingest.Records.ContainsKey($key)) { return $script:Ingest.Records[$key] }
    $entry = $script:Ingest.Index | Where-Object { $_.id -and $_.id.ToLowerInvariant() -eq $key -and $_.file } | Select-Object -First 1
    if (-not $entry) { return $null }
    $script:Ingest.Records[$key] = Read-IngestJson -Path (Join-Path $script:Ingest.Root $entry.file)
    return $script:Ingest.Records[$key]
}

function Get-FailedResourceIds {
    #ids of resources whose collection failed, per type
    param([string[]]$Type)
    $typeSet = @($Type | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    return @($script:Ingest.Index | Where-Object { $_.type -ne 'resourceGroup' -and $_.status -ne 'ok' -and ($typeSet.Count -eq 0 -or $_.type.ToLowerInvariant() -in $typeSet) } | ForEach-Object id)
}

function Get-ResourceGroupRecords {
    #resource group files (deployments, deploymentStacks, lighthouseRegistrationAssignments)
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ($script:Ingest.Index | Where-Object { $_.type -eq 'resourceGroup' -and $_.file })) {
        $record = Read-IngestJson -Path (Join-Path $script:Ingest.Root $entry.file)
        if ($null -ne $record) { $records.Add($record) }
    }
    return $records
}

#endregion

#region value helpers

function Get-Prop {
    #value at a dotted path, $null when any part is missing. Collections are unrolled like any PowerShell output; wrap in @() for a count.
    param($Object, [Parameter(Mandatory = $true)][string]$Path)
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $Object) { return $null }
        $Object = $Object.$segment
    }
    return $Object
}

function Get-Child {
    #child resource collected for a record, e.g. 'config/web' or 'blobServices/default/containers'.
    #Collections are unrolled (one pipeline item per child); use Test-ChildCollected to tell 'none' from 'not collected'.
    param([Parameter(Mandatory = $true)]$Record, [Parameter(Mandatory = $true)][string]$Path)
    if ($null -eq $Record.children) { return $null }
    return $Record.children.$Path
}

function Test-ChildCollected {
    #false when the child call failed or the child was not part of the ingestion
    param([Parameter(Mandatory = $true)]$Record, [Parameter(Mandatory = $true)][string]$Path)
    if ($null -eq $Record.children) { return $false }
    if ($Record.children.PSObject.Properties.Name -notcontains $Path) { return $false }
    return ($null -ne $Record.children.$Path)
}

function Get-ChildFailure {
    #status code of a failed child call, $null when not failed
    param([Parameter(Mandatory = $true)]$Record, [Parameter(Mandatory = $true)][string]$Path)
    $failure = @($Record.failures) | Where-Object { $_.path -and $_.path.ToLowerInvariant().EndsWith("/$($Path.ToLowerInvariant())") } | Select-Object -First 1
    if ($failure) { return [int]$failure.statusCode }
    return $null
}

function ConvertTo-UtcDate {
    #parses an ISO string, DateTime or unix seconds; $null when empty
    param($Value)
    if ($null -eq $Value -or ($Value -is [string] -and -not $Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [double]) { return [DateTimeOffset]::FromUnixTimeSeconds([long]$Value).UtcDateTime }
    return [DateTimeOffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Format-UtcDate {
    param($Value)
    $date = ConvertTo-UtcDate $Value
    if ($null -eq $date) { return $null }
    return $date.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-AgeInDays {
    #whole days between a date and the ingestion start, so re-analysing an ingestion is deterministic
    param($Value)
    $date = ConvertTo-UtcDate $Value
    if ($null -eq $date) { return $null }
    return [int][math]::Floor(($script:Ingest.ReferenceTime - $date).TotalDays)
}

function ConvertFrom-IsoDuration {
    #'PT8H' / 'P180D' -> TimeSpan
    param([string]$Duration)
    if (-not $Duration) { return $null }
    return [System.Xml.XmlConvert]::ToTimeSpan($Duration)
}

function Get-ResourceName { param([string]$Id) return ($Id.TrimEnd('/') -split '/')[-1] }

function Get-ResourceGroupName {
    param([string]$Id)
    if ($Id -match '/resourceGroups/([^/]+)') { return $Matches[1] }
    return $null
}

function Test-VersionAtLeast {
    #compares TLS style versions: '1.2', 'TLS1_2', 'Tls12', 'TLSv1.2', 'TLS1_3'
    param($Value, [string]$Minimum = '1.2')
    if (-not $Value) { return $false }
    $normalized = ([string]$Value) -replace '(?i)^tls\s*v?', '' -replace '_', '.'
    if ($normalized -match '^(\d)(\d)$') { $normalized = "$($Matches[1]).$($Matches[2])" }
    $parsed = $null
    if (-not [version]::TryParse($normalized, [ref]$parsed)) { return $false }
    return ($parsed -ge [version]$Minimum)
}

#endregion

#region result helpers

function New-Result {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Fail', 'Unknown', 'NotApplicable')][string]$Status,
        [string]$Detail,
        [System.Collections.IDictionary]$Evidence
    )
    return [pscustomobject]@{ Status = $Status; Detail = $Detail; Evidence = $Evidence }
}
function New-Pass { param([string]$Detail, [System.Collections.IDictionary]$Evidence) New-Result -Status Pass -Detail $Detail -Evidence $Evidence }
function New-Fail { param([string]$Detail, [System.Collections.IDictionary]$Evidence) New-Result -Status Fail -Detail $Detail -Evidence $Evidence }
function New-Unknown { param([string]$Detail, [System.Collections.IDictionary]$Evidence) New-Result -Status Unknown -Detail $Detail -Evidence $Evidence }
function New-NotApplicable { param([string]$Detail, [System.Collections.IDictionary]$Evidence) New-Result -Status NotApplicable -Detail $Detail -Evidence $Evidence }

function New-Finding {
    #a finding for any subject: pass -Record for a collected resource, or -ResourceId (+ -ResourceType) for anything else
    param(
        $Record,
        [string]$ResourceId,
        [string]$ResourceType,
        [string]$ResourceName,
        [Parameter(Mandatory = $true)]$Result
    )
    if ($Record) {
        if (-not $ResourceId) { $ResourceId = $Record.id }
        if (-not $ResourceType) { $ResourceType = $Record.type }
    }
    if (-not $ResourceName) { $ResourceName = Get-ResourceName $ResourceId }
    return [pscustomobject]@{
        ResourceId    = $ResourceId
        ResourceName  = $ResourceName
        ResourceType  = $ResourceType
        ResourceGroup = Get-ResourceGroupName $ResourceId
        Status        = $Result.Status
        Detail        = $Result.Detail
        Evidence      = $Result.Evidence
    }
}

function Get-SubscriptionScope { return "/subscriptions/$($script:Ingest.SubscriptionId)" }

#endregion

#region test registration

$script:Tests = [System.Collections.Generic.List[object]]::new()
$script:Catalog = $null
$script:SeverityWeights = [ordered]@{ Critical = 8; High = 4; Medium = 2; Low = 1; Informational = 0 }

function Add-AzTest {
    #registers a test; tags are validated against catalog/frameworks.json
    param([Parameter(Mandatory = $true)][hashtable]$Definition)
    foreach ($field in 'Id', 'Title', 'Category', 'Service', 'Severity', 'Description', 'Rationale', 'Remediation', 'Frameworks') {
        if (-not $Definition[$field]) { throw "Test $($Definition.Id): missing $field" }
    }
    if ($Definition.Id -notmatch '^AZ-[A-Z]+-\d{3}$') { throw "Test id $($Definition.Id) does not match AZ-<AREA>-<NNN>" }
    if ($script:Tests | Where-Object Id -eq $Definition.Id) { throw "Duplicate test id $($Definition.Id)" }
    if (-not $script:SeverityWeights.Contains($Definition.Severity)) { throw "Test $($Definition.Id): invalid severity $($Definition.Severity)" }
    if (-not ($Definition.Evaluate -or $Definition.Run)) { throw "Test $($Definition.Id): needs Evaluate (per resource) or Run" }
    if ($Definition.Evaluate -and -not $Definition.ResourceTypes) { throw "Test $($Definition.Id): Evaluate requires ResourceTypes" }
    foreach ($framework in $Definition.Frameworks.Keys) {
        if (-not $script:Catalog.Contains($framework) -or -not $script:Catalog[$framework].controls) { throw "Test $($Definition.Id): unknown or derived framework $framework" }
        foreach ($control in @($Definition.Frameworks[$framework])) {
            if (-not $script:Catalog[$framework].controls.Contains($control)) { throw "Test $($Definition.Id): $framework control '$control' not in catalog" }
        }
    }
    #MCSB is a security benchmark; a resilience check outside it carries a crosswalk tag (DORA) instead
    $crosswalkTags = @($Definition.Frameworks.Keys | Where-Object { $script:Catalog[$_].kind -eq 'crosswalk' })
    if (-not $Definition.Frameworks.MCSB -and -not $crosswalkTags) { throw "Test $($Definition.Id): at least one MCSB control is required" }
    if (-not $Definition.Version) { $Definition.Version = 1 }
    $script:Tests.Add([pscustomobject]$Definition)
}

#endregion

#region domain helpers

$script:BuiltInRoles = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
}
#Azure's 'privileged administrator roles'
$script:PrivilegedRoleIds = @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'b24988ac-6180-42a0-ab88-20f7382dd24c', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')

function Get-RoleDefinitionGuid { param([string]$RoleDefinitionId) return ($RoleDefinitionId -split '/')[-1].ToLowerInvariant() }

function Get-RoleDefinitionMap {
    #role definition guid -> definition object
    if (-not $script:Ingest.Cache.ContainsKey('#roleMap')) {
        $map = @{}
        foreach ($definition in @(Get-IngestData 'rbac/roleDefinitions')) { if ($definition) { $map[$definition.name.ToLowerInvariant()] = $definition } }
        $script:Ingest.Cache['#roleMap'] = $map
    }
    return $script:Ingest.Cache['#roleMap']
}

function Get-RoleName {
    param([string]$RoleDefinitionId)
    $guid = Get-RoleDefinitionGuid $RoleDefinitionId
    $definition = (Get-RoleDefinitionMap)[$guid]
    if ($definition) { return $definition.properties.roleName }
    if ($script:BuiltInRoles.ContainsKey($guid)) { return $script:BuiltInRoles[$guid] }
    return $guid
}

function Test-RoleCanWrite {
    #true when a role grants any write/delete/action outside pure reads
    param([string]$RoleDefinitionId)
    $guid = Get-RoleDefinitionGuid $RoleDefinitionId
    if ($guid -in $script:PrivilegedRoleIds) { return $true }
    $definition = (Get-RoleDefinitionMap)[$guid]
    if (-not $definition) { return $true }
    foreach ($permission in @($definition.properties.permissions)) {
        foreach ($action in @($permission.actions)) { if ($action -and $action -notmatch '/read$' -and $action -ne '*/read') { return $true } }
    }
    return $false
}

function Test-RolePrivileged {
    #privileged administrator roles, plus custom roles that can assign roles or do everything
    param([string]$RoleDefinitionId)
    $guid = Get-RoleDefinitionGuid $RoleDefinitionId
    if ($guid -in $script:PrivilegedRoleIds) { return $true }
    $definition = (Get-RoleDefinitionMap)[$guid]
    if (-not $definition -or $definition.properties.type -ne 'CustomRole') { return $false }
    foreach ($permission in @($definition.properties.permissions)) {
        foreach ($action in @($permission.actions)) {
            if ($action -in '*', 'Microsoft.Authorization/*', 'Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/*/write') { return $true }
        }
    }
    return $false
}

function Get-ScopeLevel {
    #'root', 'managementGroup', 'subscription', 'resourceGroup' or 'resource'
    param([string]$Scope)
    if ($Scope -eq '/') { return 'root' }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/') { return 'managementGroup' }
    if ($Scope -match '^/subscriptions/[^/]+$') { return 'subscription' }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'resourceGroup' }
    return 'resource'
}

function Get-PrincipalMap {
    #object id -> directory object, enriched with users.json details; includes soft deleted principals
    if (-not $script:Ingest.Cache.ContainsKey('#principals')) {
        $map = @{}
        foreach ($object in @(Get-IngestData 'identity/directoryObjects')) { if ($object) { $map[$object.id.ToLowerInvariant()] = $object } }
        foreach ($user in @(Get-IngestData 'identity/users')) { if ($user) { $map[$user.id.ToLowerInvariant()] = $user } }
        $script:Ingest.Cache['#principals'] = $map
    }
    return $script:Ingest.Cache['#principals']
}

function Get-Principal { param([string]$Id) if (-not $Id) { return $null }; return (Get-PrincipalMap)[$Id.ToLowerInvariant()] }

function Get-PrincipalLabel {
    param([string]$Id)
    $principal = Get-Principal $Id
    if (-not $principal) { return $Id }
    if ($principal.userPrincipalName) { return "$($principal.displayName) ($($principal.userPrincipalName))" }
    return "$($principal.displayName) ($Id)"
}

function Get-GroupMap {
    #group object id (lowercase) -> group record from identity/groups.json
    if (-not $script:Ingest.Cache.ContainsKey('#groups')) {
        $map = @{}
        foreach ($group in @(Get-IngestData 'identity/groups')) { if ($group) { $map[$group.id.ToLowerInvariant()] = $group } }
        $script:Ingest.Cache['#groups'] = $map
    }
    return $script:Ingest.Cache['#groups']
}

function Get-GroupMembers {
    #transitive members of a group as collected by the ingestion; empty when unknown
    param([string]$GroupId)
    $group = (Get-GroupMap)[$GroupId.ToLowerInvariant()]
    if (-not $group) { return }
    return @($group.transitiveMembers | Where-Object { $_ })
}

function Test-GroupMembersComplete {
    #false when the group was not collected or its transitive member listing failed during ingestion,
    #so "no members match" cannot be distinguished from "members unknown"
    param([string]$GroupId)
    if (-not $GroupId) { return $false }
    $group = (Get-GroupMap)[$GroupId.ToLowerInvariant()]
    if (-not $group) { return $false }
    return ($null -eq $group.transitiveMembersError)
}

function Test-GuestUser {
    param($User)
    return ($User.userType -eq 'Guest' -or ([string]$User.userPrincipalName) -match '#EXT#')
}

function Get-AssignmentUsers {
    #users behind a role assignment: the user itself, or the transitive user members of a group
    param([Parameter(Mandatory = $true)]$Assignment)
    $principalId = $Assignment.properties.principalId
    if ($Assignment.properties.principalType -eq 'User') {
        $user = Get-Principal $principalId
        if ($user) { return $user }
        return
    }
    if ($Assignment.properties.principalType -eq 'Group') {
        return @(Get-GroupMembers $principalId | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' } | ForEach-Object {
                $detail = Get-Principal $_.id
                if ($detail) { $detail } else { $_ }
            })
    }
    return
}

function Test-AssignmentUsersResolved {
    #false when the users behind an assignment cannot be determined: an unresolved user principal,
    #or a group whose transitive members were not collected. Tests report Unknown instead of Pass in that case.
    param([Parameter(Mandatory = $true)]$Assignment)
    $principalId = $Assignment.properties.principalId
    switch ($Assignment.properties.principalType) {
        'User' { return [bool](Get-Principal $principalId) }
        'Group' { return (Test-GroupMembersComplete $principalId) }
    }
    return $true
}

function Get-ActiveRoleAssignments {
    #role assignments that apply to this subscription (inherited, at subscription, and below)
    return @(Get-IngestData 'rbac/roleAssignments' | Where-Object { $_ })
}

function Get-PrincipalAccessMap {
    #principal object id (lowercase) -> role assignments that apply to it, directly or through group membership
    if (-not $script:Ingest.Cache.ContainsKey('#access')) {
        $map = @{}
        foreach ($assignment in (Get-ActiveRoleAssignments)) {
            $ids = @($assignment.properties.principalId)
            if ($assignment.properties.principalType -eq 'Group') { $ids += @(Get-GroupMembers $assignment.properties.principalId | ForEach-Object id) }
            foreach ($id in $ids) {
                if (-not $id) { continue }
                $key = $id.ToLowerInvariant()
                if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[object]]::new() }
                $map[$key].Add($assignment)
            }
        }
        $script:Ingest.Cache['#access'] = $map
    }
    return $script:Ingest.Cache['#access']
}

function New-SubscriptionFinding {
    param([Parameter(Mandatory = $true)]$Result)
    return New-Finding -ResourceId (Get-SubscriptionScope) -ResourceType 'Microsoft.Resources/subscriptions' -ResourceName $script:Ingest.Manifest.subscription.displayName -Result $Result
}

function New-TenantFinding {
    param([Parameter(Mandatory = $true)]$Result, [string]$Suffix)
    $id = "/tenants/$($script:Ingest.Manifest.subscription.tenantId)$Suffix"
    return New-Finding -ResourceId $id -ResourceType 'Microsoft.Entra/tenants' -Result $Result
}

function Get-LockMap {
    #lock scope (lowercase) -> locks; lock ids are '<scope>/providers/Microsoft.Authorization/locks/<name>'
    if (-not $script:Ingest.Cache.ContainsKey('#locks')) {
        $map = @{}
        foreach ($lock in @(Get-IngestData 'subscription/locks' | Where-Object { $_ })) {
            $scope = ($lock.id -replace '(?i)/providers/Microsoft\.Authorization/locks/[^/]+$', '').ToLowerInvariant()
            if (-not $map[$scope]) { $map[$scope] = [System.Collections.Generic.List[object]]::new() }
            $map[$scope].Add($lock)
        }
        $script:Ingest.Cache['#locks'] = $map
    }
    return $script:Ingest.Cache['#locks']
}

function Get-EffectiveLocks {
    #locks at the resource or any parent scope
    param([Parameter(Mandatory = $true)][string]$ResourceId)
    $map = Get-LockMap
    $found = [System.Collections.Generic.List[object]]::new()
    $scope = $ResourceId.ToLowerInvariant()
    while ($scope) {
        if ($map.ContainsKey($scope)) { $found.AddRange($map[$scope]) }
        $parent = $scope.Substring(0, [math]::Max(0, $scope.LastIndexOf('/')))
        if ($parent -eq $scope) { break }
        $scope = $parent
    }
    return $found
}

function Test-DiagnosticLogsEnabled {
    #true when at least one diagnostic setting sends logs (category or category group) to a destination
    param($Settings, [string[]]$RequiredCategories)
    foreach ($setting in @($Settings)) {
        if (-not $setting) { continue }
        $properties = $setting.properties
        if (-not ($properties.workspaceId -or $properties.storageAccountId -or $properties.eventHubAuthorizationRuleId -or $properties.marketplacePartnerId)) { continue }
        $enabled = @($properties.logs | Where-Object { $_.enabled })
        if (-not $enabled) { continue }
        if (-not $RequiredCategories) { return $true }
        if ($enabled | Where-Object { $_.categoryGroup -in 'allLogs', 'audit' }) { return $true }
        $categories = @($enabled | ForEach-Object category)
        if (-not ($RequiredCategories | Where-Object { $_ -notin $categories })) { return $true }
    }
    return $false
}

function Test-InternetSource {
    param([string]$Prefix)
    return ($Prefix -in '*', 'Internet', '0.0.0.0/0', '::/0', 'Any', '0.0.0.0')
}

function Test-PortInRange {
    #'*', '3389', '3000-4000'
    param([string]$Range, [int]$Port)
    if (-not $Range) { return $false }
    if ($Range -eq '*') { return $true }
    if ($Range -match '^(\d+)-(\d+)$') { return ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) }
    if ($Range -match '^\d+$') { return ([int]$Range -eq $Port) }
    return $false
}

function Get-NsgInternetExposure {
    #first inbound rule (by priority) matching traffic from the Internet to the port/protocol; returns the rule when it allows, else $null
    param([Parameter(Mandatory = $true)]$Nsg, [Parameter(Mandatory = $true)][int]$Port, [ValidateSet('Tcp', 'Udp')][string]$Protocol = 'Tcp')
    $rules = @($Nsg.properties.securityRules) + @($Nsg.properties.defaultSecurityRules) | Where-Object { $_ -and $_.properties.direction -eq 'Inbound' }
    foreach ($rule in ($rules | Sort-Object { [int]$_.properties.priority })) {
        $p = $rule.properties
        if ($p.protocol -notin '*', $Protocol) { continue }
        $sources = @($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) | Where-Object { $_ }
        if (-not ($sources | Where-Object { Test-InternetSource $_ })) { continue }
        $ranges = @($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ }
        if (-not ($ranges | Where-Object { Test-PortInRange -Range $_ -Port $Port })) { continue }
        if ($p.access -eq 'Allow') { return $rule }
        return $null
    }
    return $null
}

function Get-PolicyAssignments { return @(Get-IngestData 'policy/policyAssignments' | Where-Object { $_ }) }

function Get-SecretPatterns {
    #patterns for credentials in text; values are never copied into findings
    return [ordered]@{
        'Storage account key'           = '(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}'
        'Shared access key'             = '(?i)SharedAccessKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}'
        'SAS token signature'           = '(?i)[?&]sig=[A-Za-z0-9%+/]{30,}'
        'Entra client secret'           = '[A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}'
        'Private key'                   = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'
        'GitHub token'                  = '\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
        'AWS access key'                = '\bAKIA[0-9A-Z]{16}\b'
        'Plain text SecureString'       = '(?i)ConvertTo-SecureString\s+(?:-String\s+)?["''][^"''$]{4,}["'']\s+-AsPlainText'
        'Hardcoded password assignment' = '(?i)\b(?:password|passwd|pwd|clientsecret|client_secret|apikey|api_key)\b\s*[:=]\s*["''][^"''$\s{}]{8,}["'']'
    }
}

function Find-Secrets {
    #pattern names found in a text; the matched values are not returned
    param([string]$Text)
    $found = [System.Collections.Generic.List[string]]::new()
    if (-not $Text) { return }
    $patterns = Get-SecretPatterns
    foreach ($name in $patterns.Keys) { if ($Text -match $patterns[$name]) { $found.Add($name) } }
    return $found
}

#endregion
