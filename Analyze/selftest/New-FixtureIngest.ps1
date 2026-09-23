#Requires -Version 7.2
<#
    .SYNOPSIS
    Writes a synthetic ingestion folder in which every resource is either fully compliant (-Mode Good) or fully non-compliant (-Mode Bad).
    .DESCRIPTION
    Used by Invoke-SelfTest.ps1 to exercise the pass and fail path of every test, including resource types absent from real ingestions.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet('Good', 'Bad')][string]$Mode
)

$ErrorActionPreference = 'Stop'
$G = $Mode -eq 'Good'
$reference = [datetime]::new(2026, 9, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
$sub = '00000000-0000-0000-0000-000000000001'
$tenant = '00000000-0000-0000-0000-0000000000aa'
$subScope = "/subscriptions/$sub"
$rgId = "$subScope/resourceGroups/rg-fixture"
$location = 'westeurope'

function Iso { param([int]$Days) $reference.AddDays($Days).ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Unix { param([int]$Days) [DateTimeOffset]::new($reference.AddDays($Days)).ToUnixTimeSeconds() }
function Pick { param($Good, $Bad) if ($G) { , $Good } else { , $Bad } }
function ResId { param([string]$Type, [string]$Name) "$rgId/providers/$Type/$Name" }
function Role { param([string]$Guid) "$subScope/providers/Microsoft.Authorization/roleDefinitions/$Guid" }

$roles = @{ Owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; UAA = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; RbacAdmin = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168' }
$ids = @{
    U1 = '10000000-0000-0000-0000-000000000001'; U2 = '10000000-0000-0000-0000-000000000002'; Guest = '10000000-0000-0000-0000-000000000003'
    Disabled = '10000000-0000-0000-0000-000000000004'; Synced = '10000000-0000-0000-0000-000000000005'
    G1 = '20000000-0000-0000-0000-000000000001'; G2 = '20000000-0000-0000-0000-000000000002'; G3 = '20000000-0000-0000-0000-000000000003'
    SpApp = '30000000-0000-0000-0000-000000000001'; SpMi = '30000000-0000-0000-0000-000000000002'; Graph = '40000000-0000-0000-0000-000000000001'
    Deleted = '50000000-0000-0000-0000-000000000001'
}

$root = $Path
if (Test-Path $root) { Remove-Item -Path $root -Recurse -Force }
$null = New-Item -ItemType Directory -Force -Path $root
$index = [System.Collections.Generic.List[object]]::new()
$resourceList = [System.Collections.Generic.List[object]]::new()

function Save {
    param([string]$Name, $Value)
    $file = Join-Path $root "$Name.json"
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $file)
    [System.IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $Value -Depth 50))
}

$diag = @(@{ name = 'to-la'; properties = @{ workspaceId = "$rgId/providers/Microsoft.OperationalInsights/workspaces/lafixture"; logs = @(@{ categoryGroup = 'allLogs'; enabled = $true }) } })

function Add-Record {
    #writes a resource file; -Id defaults to a resource group level id
    param([string]$Type, [string]$Name, [hashtable]$Resource, [hashtable]$Children = @{}, $Diagnostics = 'default', [hashtable]$Text = @{}, [string]$Id)
    if (-not $Id) { $Id = ResId $Type $Name }
    $Resource.id = $Id
    $Resource.name = ($Name -split '/')[-1]
    $Resource.type = $Type
    if (-not $Resource.location) { $Resource.location = $location }
    if ($Diagnostics -eq 'default') { $Diagnostics = Pick $diag @() }
    $file = "resources/$($Type -replace '/', '.')/$($Name -replace '/', '_').json"
    Save ($file -replace '\.json$', '') ([ordered]@{ id = $Id; type = $Type; apiVersion = 'fixture'; resource = $Resource; diagnosticSettings = $Diagnostics; children = $Children; textContent = $Text; failures = @() })
    $index.Add([ordered]@{ id = $Id; type = $Type; file = $file; status = 'ok' })
    $resourceList.Add([ordered]@{ id = $Id; type = $Type; name = $Resource.name; location = $Resource.location })
    return $Id
}

$approvedPe = @(@{ properties = @{ privateLinkServiceConnectionState = @{ status = 'Approved' } } })

#region identity and access

$assignment = {
    param([string]$Name, [string]$Role, [string]$Principal, [string]$Type, [string]$Scope)
    @{ id = "$Scope/providers/Microsoft.Authorization/roleAssignments/$Name".Replace('//', '/'); type = 'Microsoft.Authorization/roleAssignments'; name = $Name; properties = @{ roleDefinitionId = (Role $Role); principalId = $Principal; principalType = $Type; scope = $Scope } }
}
$assignments = @(
    & $assignment 'ra-g1-owner' $roles.Owner $ids.G1 'Group' $subScope
    & $assignment 'ra-g2-owner' $roles.Owner $ids.G2 'Group' $subScope
    & $assignment 'ra-g3-reader' $roles.Reader $ids.G3 'Group' $subScope
    & $assignment 'ra-mi-root-reader' $roles.Reader $ids.SpMi 'ServicePrincipal' '/'
)
if ($G) {
    $assignments += & $assignment 'ra-app-contributor' $roles.Contributor $ids.SpApp 'ServicePrincipal' $rgId
} else {
    $assignments += & $assignment 'ra-app-contributor' $roles.Contributor $ids.SpApp 'ServicePrincipal' $subScope
    $assignments += & $assignment 'ra-u1-owner' $roles.Owner $ids.U1 'User' $subScope
    $assignments += & $assignment 'ra-synced-owner' $roles.Owner $ids.Synced 'User' $subScope
    $assignments += & $assignment 'ra-u1-root-uaa' $roles.UAA $ids.U1 'User' '/'
    $assignments += & $assignment 'ra-guest-reader' $roles.Reader $ids.Guest 'User' $rgId
    $assignments += & $assignment 'ra-deleted-reader' $roles.Reader $ids.Deleted 'ServicePrincipal' $subScope
}
Save 'rbac/roleAssignments' $assignments

$instances = foreach ($a in ($assignments | Where-Object { $_.properties.principalType -in 'User', 'Group' -and $_.properties.roleDefinitionId -match "$($roles.Owner)|$($roles.UAA)" })) {
    @{ id = "$($a.id)-instance"; type = 'Microsoft.Authorization/roleAssignmentScheduleInstances'; properties = @{ originRoleAssignmentId = $a.id; assignmentType = (Pick 'Activated' 'Assigned'); endDateTime = (Pick (Iso 1) $null); principalId = $a.properties.principalId; principalType = $a.properties.principalType; roleDefinitionId = $a.properties.roleDefinitionId; scope = $a.properties.scope } }
}
Save 'rbac/roleAssignmentScheduleInstances' @($instances)
Save 'rbac/denyAssignments' @(@{
        id = "$subScope/providers/Microsoft.Authorization/denyAssignments/da1"; type = 'Microsoft.Authorization/denyAssignments'
        properties = @{
            denyAssignmentName = 'Managed application deny'; scope = $rgId; isSystemProtected = $true; doNotApplyToChildScopes = $false
            permissions = @(@{ actions = @('*'); notActions = @('*/read') })
            excludePrincipals = (Pick @() @(@{ id = $ids.U1; type = 'User' }))
        }
    })
Save 'rbac/roleEligibilitySchedules' @()

$definition = { param([string]$Guid, [string]$Name, [string]$Type, [string[]]$Actions) @{ id = (Role $Guid); name = $Guid; type = 'Microsoft.Authorization/roleDefinitions'; properties = @{ roleName = $Name; type = $Type; permissions = @(@{ actions = $Actions }); assignableScopes = @($subScope) } } }
$definitions = @(
    & $definition $roles.Owner 'Owner' 'BuiltInRole' @('*')
    & $definition $roles.Contributor 'Contributor' 'BuiltInRole' @('*')
    & $definition $roles.Reader 'Reader' 'BuiltInRole' @('*/read')
    & $definition $roles.UAA 'User Access Administrator' 'BuiltInRole' @('*/read', 'Microsoft.Authorization/*')
    & $definition $roles.RbacAdmin 'Role Based Access Control Administrator' 'BuiltInRole' @('Microsoft.Authorization/roleAssignments/write')
)
$definitions += if ($G) { & $definition '60000000-0000-0000-0000-000000000001' 'Lock administrator' 'CustomRole' @('Microsoft.Authorization/locks/*', '*/read') } else { & $definition '60000000-0000-0000-0000-000000000002' 'Everything role' 'CustomRole' @('*') }
Save 'rbac/roleDefinitions' $definitions

$policyRules = if ($G) {
    @(
        @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('MultiFactorAuthentication', 'Justification') }
        @{ id = 'Expiration_EndUser_Assignment'; maximumDuration = 'PT8H' }
        @{ id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $true } }
        @{ id = 'Expiration_Admin_Assignment'; isExpirationRequired = $true; maximumDuration = 'P15D' }
    )
} else {
    @(
        @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('Justification') }
        @{ id = 'Expiration_EndUser_Assignment'; maximumDuration = 'PT24H' }
        @{ id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $false } }
        @{ id = 'Expiration_Admin_Assignment'; isExpirationRequired = $false; maximumDuration = 'P180D' }
    )
}
Save 'rbac/roleManagementPolicyAssignments' @(foreach ($role in 'Owner', 'Contributor', 'UAA', 'RbacAdmin') { @{ id = "$subScope/providers/Microsoft.Authorization/roleManagementPolicyAssignments/$role"; properties = @{ scope = $subScope; roleDefinitionId = (Role $roles[$role]); effectiveRules = $policyRules } } })

$user = { param([string]$Id, [string]$Name, [string]$UserType = 'Member', [bool]$Enabled = $true, $Synced = $null, [int]$LastSignIn = -5) @{ '@odata.type' = '#microsoft.graph.user'; id = $Id; displayName = $Name; userPrincipalName = "$Name@fixture.example"; userType = $UserType; accountEnabled = $Enabled; onPremisesSyncEnabled = $Synced; signInActivity = @{ lastSignInDateTime = (Iso $LastSignIn) } } }
$users = @(
    & $user $ids.U1 'admin1' 'Member' $true $null (Pick -5 -200)
    & $user $ids.U2 'admin2'
    & $user $ids.Guest 'guest' 'Guest'
    & $user $ids.Disabled 'leaver' 'Member' $false
    & $user $ids.Synced 'synced' 'Member' $true $true
)
Save 'identity/users' $users
$groups = @(@{ '@odata.type' = '#microsoft.graph.group'; id = $ids.G1; displayName = 'owners-1' }, @{ '@odata.type' = '#microsoft.graph.group'; id = $ids.G2; displayName = 'owners-2' }, @{ '@odata.type' = '#microsoft.graph.group'; id = $ids.G3; displayName = 'readers' })
$servicePrincipals = @(
    @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $ids.SpApp; displayName = 'fixture-app'; appId = '31000000-0000-0000-0000-000000000001'; servicePrincipalType = 'Application'; passwordCredentials = @(); keyCredentials = @() }
    @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $ids.SpMi; displayName = 'fixture-mi'; appId = '31000000-0000-0000-0000-000000000002'; servicePrincipalType = 'ManagedIdentity'; passwordCredentials = @(); keyCredentials = @() }
)
Save 'identity/directoryObjects' (@($users) + $groups + $servicePrincipals)
$member = { param($Id) $u = $users | Where-Object { $_.id -eq $Id }; @{ '@odata.type' = '#microsoft.graph.user'; id = $Id; displayName = $u.displayName; userPrincipalName = $u.userPrincipalName } }
Save 'identity/groups' @(
    @{ id = $ids.G1; transitiveMembers = (Pick @(& $member $ids.U1) @((& $member $ids.U1), (& $member $ids.Guest), (& $member $ids.Disabled))); owners = @() }
    @{ id = $ids.G2; transitiveMembers = @(& $member $ids.U2); owners = @() }
    @{ id = $ids.G3; transitiveMembers = @(& $member $ids.U1); owners = @() }
)
$graphRoles = @(@{ id = '70000000-0000-0000-0000-000000000001'; value = 'User.Read.All' }, @{ id = '70000000-0000-0000-0000-000000000002'; value = 'RoleManagement.ReadWrite.Directory' })
Save 'identity/apiServicePrincipals' @(@{ id = $ids.Graph; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; appRoles = $graphRoles })
Save 'identity/servicePrincipals' @(
    @{
        id = $ids.SpApp
        appRoleAssignments = @(@{ resourceId = $ids.Graph; appRoleId = (Pick $graphRoles[0].id $graphRoles[1].id) })
        oauth2PermissionGrants = (Pick @() @(@{ clientId = $ids.SpApp; resourceId = $ids.Graph; consentType = 'AllPrincipals'; scope = 'User.Read Directory.ReadWrite.All' }))
        owners = (Pick @() @(@{ id = $ids.U2; userPrincipalName = 'admin2@fixture.example' }))
        application = @{ id = '32000000-0000-0000-0000-000000000001'; appId = '31000000-0000-0000-0000-000000000001'; keyCredentials = @(@{ displayName = 'cert'; keyId = 'k1'; startDateTime = (Iso -10); endDateTime = (Iso (Pick 170 720)) }); passwordCredentials = (Pick @() @(@{ displayName = 'secret'; keyId = 'p1'; startDateTime = (Iso -10); endDateTime = (Iso 720) })) }
        applicationOwners = @()
        applicationFederatedIdentityCredentials = @(@{ name = 'github'; issuer = 'https://token.actions.githubusercontent.com'; subject = (Pick 'repo:contoso/app:ref:refs/heads/main' 'repo:contoso/app:*'); audiences = @('api://AzureADTokenExchange') })
    }
    @{ id = $ids.SpMi; appRoleAssignments = @(); oauth2PermissionGrants = @(); owners = @(); application = $null; applicationOwners = @(); applicationFederatedIdentityCredentials = @() }
)
Save 'identity/unresolvedPrincipalIds' (Pick @() @($ids.Deleted))
Save 'identity/deletedPrincipals' (Pick @() @(@{ id = $ids.Deleted; displayName = 'old-app'; deletedDateTime = (Iso -3) }))
$ga = '62e90394-69f5-4237-9190-012177145e10'
$pra = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
Save 'identity/directoryRoleDefinitions' @(@{ id = $ga; templateId = $ga; displayName = 'Global Administrator' }, @{ id = $pra; templateId = $pra; displayName = 'Privileged Role Administrator' })
$principalOf = { param($Id) $u = $users | Where-Object { $_.id -eq $Id }; $copy = @{}; foreach ($k in $u.Keys) { $copy[$k] = $u[$k] }; $copy }
Save 'identity/directoryRoleAssignments' $(if ($G) {
        @(@{ id = 'dra1'; principalId = $ids.U1; roleDefinitionId = $ga; principal = (& $principalOf $ids.U1) }, @{ id = 'dra2'; principalId = $ids.U2; roleDefinitionId = $ga; principal = (& $principalOf $ids.U2) })
    } else {
        @(@{ id = 'dra1'; principalId = $ids.Synced; roleDefinitionId = $ga; principal = (& $principalOf $ids.Synced) }, @{ id = 'dra2'; principalId = $ids.SpApp; roleDefinitionId = $pra; principal = $servicePrincipals[0] })
    })
Save 'identity/directoryRoleEligibilitySchedules' @()
Save 'subscription/lighthouseRegistrationAssignments' @(@{ id = "$subScope/providers/Microsoft.ManagedServices/registrationAssignments/la1"; properties = @{ registrationDefinition = @{ properties = @{ managedByTenantName = 'Partner'; managedByTenantId = '80000000-0000-0000-0000-000000000001'; registrationDefinitionName = 'Managed services'; authorizations = @(@{ principalId = 'p'; principalIdDisplayName = 'Partner admins'; roleDefinitionId = (Pick $roles.Reader $roles.Contributor) }); eligibleAuthorizations = @(@{ principalId = 'p'; principalIdDisplayName = 'Partner admins'; roleDefinitionId = $roles.Contributor }) } } } })

#endregion

#region governance, Defender, subscription logging

$mcsb = "/providers/Microsoft.Authorization/policySetDefinitions/e3ec7e09-768c-4b64-882c-fcada3772047"
Save 'policy/policyAssignments' @(@{ id = "$subScope/providers/Microsoft.Authorization/policyAssignments/mcsb"; type = 'Microsoft.Authorization/policyAssignments'; properties = @{ displayName = 'MCSB v2'; policyDefinitionId = $mcsb; scope = $subScope; enforcementMode = 'Default'; parameters = (Pick @{} @{ storageAccountsShouldDisablePublicNetworkAccessEffect = @{ value = 'Disabled' } }) } })
Save 'policy/policyExemptions' @(@{ id = "$subScope/providers/Microsoft.Authorization/policyExemptions/ex1"; type = 'Microsoft.Authorization/policyExemptions'; properties = @{ displayName = 'Waiver'; exemptionCategory = 'Waiver'; expiresOn = (Pick (Iso 30) $null) } })
Save 'subscription/locks' (Pick @(
        @{ id = "$rgId/providers/Microsoft.Authorization/locks/protect"; properties = @{ level = 'CanNotDelete' } }
        @{ id = "$(ResId 'Microsoft.Storage/storageAccounts' 'stfixture')/providers/Microsoft.Authorization/locks/readonly"; properties = @{ level = 'ReadOnly' } }
    ) @())
Save 'subscription/blueprintAssignments' (Pick @() @(@{ id = "$subScope/providers/Microsoft.Blueprint/blueprintAssignments/bp1"; name = 'bp1'; properties = @{ blueprintId = '/providers/Microsoft.Blueprint/blueprints/legacy' } }))
Save 'subscription/deployments' @(@{ id = "$subScope/providers/Microsoft.Resources/deployments/dep1"; name = 'dep1'; properties = @{ timestamp = (Iso -1); parameters = (Pick @{ vmName = @{ type = 'String'; value = 'vm1' } } @{ adminPassword = @{ type = 'String'; value = 'Sup3rS3cretValue!' } }); outputs = @{} } })
$categories = Pick @('Administrative', 'Alert', 'Policy', 'Security') @('Administrative')
Save 'subscription/diagnosticSettings' @(@{ name = 'activity'; properties = @{ workspaceId = '/la'; logs = @($categories | ForEach-Object { @{ category = $_; enabled = $true } }) } })

$planNames = 'CloudPosture', 'VirtualMachines', 'Containers', 'StorageAccounts', 'AppServices', 'CosmosDbs', 'OpenSourceRelationalDatabases', 'SqlServers', 'SqlServerVirtualMachines', 'KeyVaults', 'Arm', 'Api', 'AI'
Save 'defender/pricings' @(foreach ($plan in $planNames) {
        $p = @{ pricingTier = (Pick 'Standard' 'Free') }
        if ($plan -eq 'VirtualMachines') { $p.subPlan = (Pick 'P2' $null); $p.extensions = @(@{ name = 'AgentlessVmScanning'; isEnabled = (Pick 'True' 'False') }, @{ name = 'FileIntegrityMonitoring'; isEnabled = (Pick 'True' 'False') }) }
        if ($plan -eq 'StorageAccounts') { $p.extensions = @(@{ name = 'OnUploadMalwareScanning'; isEnabled = (Pick 'True' 'False') }, @{ name = 'SensitiveDataDiscovery'; isEnabled = (Pick 'True' 'False') }) }
        if ($plan -eq 'CloudPosture') { $p.extensions = @(@{ name = 'SensitiveDataDiscovery'; isEnabled = (Pick 'True' 'False') }) }
        @{ name = $plan; properties = $p }
    })
Save 'defender/settings' @(@{ name = 'WDATP'; properties = @{ enabled = $G } }, @{ name = 'Sentinel'; properties = @{ enabled = $false } })
Save 'defender/securityContacts' (Pick @(@{ name = 'default'; properties = @{ emails = 'soc@fixture.example'; isEnabled = $true; notificationsByRole = @{ state = 'On'; roles = @('Owner') }; notificationsSources = @(@{ sourceType = 'Alert'; minimalSeverity = 'Medium' }, @{ sourceType = 'AttackPath'; minimalRiskLevel = 'Critical' }) } }) @())
Save 'defender/alerts' (Pick @() @(@{ id = "$subScope/providers/Microsoft.Security/locations/westeurope/alerts/a1"; type = 'Microsoft.Security/locations/alerts'; properties = @{ severity = 'High'; status = 'Active'; alertDisplayName = 'Suspicious activity'; startTimeUtc = (Iso -1); compromisedEntity = 'vmfixture' } }))
Save 'defender/automations' (Pick @(@{ name = 'export'; properties = @{ isEnabled = $true; sources = @(@{ eventSource = 'Alerts' }) } }) @())
Save 'defender/serverVulnerabilityAssessmentsSettings' (Pick @(@{ properties = @{ selectedProvider = 'MdeTvm' } }) @())
Save 'defender/jitNetworkAccessPolicies' (Pick @(@{ id = "$subScope/providers/Microsoft.Security/locations/westeurope/jitNetworkAccessPolicies/default"; name = 'default'; properties = @{ virtualMachines = @(@{ id = (ResId 'Microsoft.Compute/virtualMachines' 'vmfixture'); ports = @(@{ number = 22; maxRequestAccessDuration = 'PT3H' }) }) } }) @())

#endregion

#region resources

#storage
function New-Storage {
    param([string]$Name, [string]$Bypass)
    $blobDiag = Pick $diag @()
    Add-Record 'Microsoft.Storage/storageAccounts' $Name @{
        kind = 'StorageV2'; sku = @{ name = (Pick 'Standard_GZRS' 'Standard_LRS') }
        properties = @{
            supportsHttpsTrafficOnly = $G; minimumTlsVersion = (Pick 'TLS1_2' 'TLS1_0'); allowBlobPublicAccess = (-not $G); allowSharedKeyAccess = (-not $G)
            publicNetworkAccess = (Pick 'Disabled' 'Enabled'); networkAcls = @{ defaultAction = (Pick 'Deny' $(if ($Bypass) { 'Deny' } else { 'Allow' })); bypass = (Pick 'AzureServices' 'None') }
            privateEndpointConnections = (Pick $approvedPe @()); allowCrossTenantReplication = (-not $G); defaultToOAuthAuthentication = $G
            keyPolicy = (Pick @{ keyExpirationPeriodInDays = 90 } $null); keyCreationTime = @{ key1 = (Iso (Pick -10 -400)); key2 = (Iso (Pick -10 -400)) }
            encryption = @{ requireInfrastructureEncryption = $G; keySource = (Pick 'Microsoft.Keyvault' 'Microsoft.Storage') }
            isSftpEnabled = $true; sasPolicy = (Pick @{ sasExpirationPeriod = '1.00:00:00'; expirationAction = 'Log' } $null)
            primaryEndpoints = @{ blob = "https://$Name.blob.core.windows.net/" }
        }
    } -Children @{
        'blobServices/default'                                                 = @{ properties = @{ deleteRetentionPolicy = @{ enabled = $G; days = 14 }; containerDeleteRetentionPolicy = @{ enabled = $G; days = 14 }; isVersioningEnabled = $G } }
        'blobServices/default/containers'                                      = @(@{ name = 'data'; properties = @{ publicAccess = (Pick 'None' 'Blob') } })
        'fileServices/default'                                                 = @{ properties = @{ shareDeleteRetentionPolicy = @{ enabled = $G; days = 14 }; protocolSettings = (Pick @{ smb = @{ versions = 'SMB3.1.1'; channelEncryption = 'AES-256-GCM' } } @{ smb = @{} }) } }
        'fileServices/default/shares'                                          = @(@{ name = 'share1'; properties = @{ enabledProtocols = 'SMB' } })
        'localUsers'                                                           = @(@{ name = 'sftpuser'; properties = @{ hasSshPassword = (-not $G); hasSshKey = $true } })
        'providers/Microsoft.Security/defenderForStorageSettings/current'      = @{ properties = @{ isEnabled = $G; overrideSubscriptionLevelSettings = (-not $G); malwareScanning = @{ onUpload = @{ isEnabled = $G } } } }
        'blobServices/default/providers/Microsoft.Insights/diagnosticSettings' = $blobDiag
        'fileServices/default/providers/Microsoft.Insights/diagnosticSettings' = $blobDiag
        'queueServices/default/providers/Microsoft.Insights/diagnosticSettings' = $blobDiag
        'tableServices/default/providers/Microsoft.Insights/diagnosticSettings' = $blobDiag
    } -Diagnostics @() | Out-Null
}
New-Storage 'stfixture'
if (-not $G) { New-Storage 'stfixturefw' -Bypass 'None' }

#key vault
$kvId = ResId 'Microsoft.KeyVault/vaults' 'kvfixture'
Add-Record 'Microsoft.KeyVault/vaults' 'kvfixture' @{ properties = @{
        enableSoftDelete = $true; enablePurgeProtection = (Pick $true $null); enableRbacAuthorization = $G; publicNetworkAccess = (Pick 'Disabled' 'Enabled'); networkAcls = @{ defaultAction = (Pick 'Deny' 'Allow') }
        privateEndpointConnections = (Pick $approvedPe @()); accessPolicies = (Pick @() @(@{ objectId = $ids.U1; permissions = @{ secrets = @('all'); keys = @('get') } }))
    }
} -Children @{
    keys    = @(@{ id = "$kvId/keys/k1"; name = 'k1'; properties = @{ attributes = @{ enabled = $true; exp = (Pick (Unix 100) $null) }; rotationPolicy = @{ lifetimeActions = @(@{ action = @{ type = (Pick 'Rotate' 'Notify') } }) } } })
    secrets = @(
        @{ id = "$kvId/secrets/s1"; name = 's1'; properties = @{ attributes = @{ enabled = $true; exp = (Pick (Unix 100) $null) } } }
        @{ id = "$kvId/secrets/cert1"; name = 'cert1'; properties = @{ contentType = 'application/x-pkcs12'; attributes = @{ enabled = $true; nbf = (Unix -10); exp = (Unix (Pick 355 720)) } } }
    )
} | Out-Null

#SQL
function New-SqlServer {
    param([string]$Name, [bool]$AuditToStorage)
    $auditing = @(@{ name = 'Default'; properties = @{ state = $(if ($G -or $AuditToStorage) { 'Enabled' } else { 'Disabled' }); storageEndpoint = 'https://staudit.blob.core.windows.net'; retentionDays = (Pick 120 30) } })
    Add-Record 'Microsoft.Sql/servers' $Name @{ properties = @{ minimalTlsVersion = (Pick '1.2' '1.0'); publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } -Children @{
        firewallRules                    = (Pick @() @(@{ name = 'AllowAllWindowsAzureIps'; properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } }, @{ name = 'Everyone'; properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '255.255.255.255' } }))
        administrators                   = (Pick @(@{ name = 'ActiveDirectory'; properties = @{ login = 'sql-admins' } }) @())
        azureADOnlyAuthentications       = @(@{ name = 'Default'; properties = @{ azureADOnlyAuthentication = $G } })
        auditingSettings                 = $auditing
        extendedAuditingSettings         = $auditing
        securityAlertPolicies            = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
        advancedThreatProtectionSettings = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
        sqlVulnerabilityAssessments      = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
        vulnerabilityAssessments         = @()
        encryptionProtector              = @(@{ properties = @{ serverKeyType = (Pick 'AzureKeyVault' 'ServiceManaged') } })
    } | Out-Null
}
New-SqlServer 'sqlfixture' $false
if (-not $G) { New-SqlServer 'sqlfixture2' $true }
Add-Record 'Microsoft.Sql/servers/databases' 'sqlfixture/appdb' @{ kind = 'v12.0,user'; properties = @{} } -Id "$(ResId 'Microsoft.Sql/servers' 'sqlfixture')/databases/appdb" -Children @{ transparentDataEncryption = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } }) } | Out-Null
Add-Record 'Microsoft.Sql/managedInstances' 'mifixture' @{ properties = @{ minimalTlsVersion = (Pick '1.2' '1.0'); publicDataEndpointEnabled = (-not $G) } } -Children @{
    administrators = (Pick @(@{ properties = @{ login = 'mi-admins' } }) @()); azureADOnlyAuthentications = @(@{ properties = @{ azureADOnlyAuthentication = $G } })
    encryptionProtector = @(@{ properties = @{ serverKeyType = (Pick 'AzureKeyVault' 'ServiceManaged') } }); sqlVulnerabilityAssessments = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
    vulnerabilityAssessments = @(); advancedThreatProtectionSettings = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
} | Out-Null

#open source databases, Cosmos DB, Redis
#sorted by name: hashtable order differs per process, and the fixture must be the same on every run
$config = { param([hashtable]$Values) @($Values.GetEnumerator() | Sort-Object Key | ForEach-Object { @{ name = $_.Key; properties = @{ value = $_.Value } } }) }
Add-Record 'Microsoft.DBforPostgreSQL/flexibleServers' 'pgfixture' @{ properties = @{ network = @{ publicNetworkAccess = (Pick 'Disabled' 'Enabled') }; authConfig = @{ activeDirectoryAuth = (Pick 'Enabled' 'Disabled'); passwordAuth = (Pick 'Disabled' 'Enabled') } } } -Children @{
    configurations = (& $config $(if ($G) { @{ require_secure_transport = 'on'; ssl_min_protocol_version = 'TLSv1.2'; log_connections = 'on'; log_disconnections = 'on'; log_checkpoints = 'on'; shared_preload_libraries = 'pg_stat_statements,pgaudit'; 'pgaudit.log' = 'ddl,role' } } else { @{ require_secure_transport = 'off'; ssl_min_protocol_version = 'TLSv1'; log_connections = 'off'; log_disconnections = 'off'; log_checkpoints = 'off'; shared_preload_libraries = 'pg_stat_statements'; 'pgaudit.log' = 'none' } }))
    administrators = (Pick @(@{ name = 'admin' }) @()); advancedThreatProtectionSettings = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
    firewallRules = (Pick @() @(@{ name = 'AllowAll'; properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '255.255.255.255' } }))
} | Out-Null
Add-Record 'Microsoft.DBforMySQL/flexibleServers' 'myfixture' @{ properties = @{ network = @{ publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } } -Children @{
    configurations = (& $config $(if ($G) { @{ require_secure_transport = 'ON'; tls_version = 'TLSv1.2,TLSv1.3'; audit_log_enabled = 'ON'; audit_log_events = 'CONNECTION,DDL'; aad_auth_only = 'ON' } } else { @{ require_secure_transport = 'OFF'; tls_version = 'TLSv1,TLSv1.1,TLSv1.2'; audit_log_enabled = 'OFF'; audit_log_events = 'DDL'; aad_auth_only = 'OFF' } }))
    administrators = (Pick @(@{ name = 'ActiveDirectory' }) @()); firewallRules = @()
} | Out-Null
if (-not $G) { Add-Record 'Microsoft.DBforPostgreSQL/servers' 'pgsingle' @{ properties = @{ publicNetworkAccess = 'Enabled' } } -Children @{ firewallRules = @() } | Out-Null }
Add-Record 'Microsoft.DocumentDB/databaseAccounts' 'cosfixture' @{ properties = @{ disableLocalAuth = $G; publicNetworkAccess = (Pick 'Disabled' 'Enabled'); disableKeyBasedMetadataWriteAccess = $G; minimalTlsVersion = (Pick 'Tls12' 'Tls'); ipRules = @(); isVirtualNetworkFilterEnabled = $false } } -Children @{ 'providers/Microsoft.Security/advancedThreatProtectionSettings/current' = @{ properties = @{ isEnabled = $G } } } | Out-Null
Add-Record 'Microsoft.Cache/Redis' 'redisfixture' @{ properties = @{ enableNonSslPort = (-not $G); disableAccessKeyAuthentication = $G; minimumTlsVersion = (Pick '1.2' '1.0'); publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } -Children @{ firewallRules = (Pick @() @(@{ name = 'all'; properties = @{ startIP = '0.0.0.0'; endIP = '255.255.255.255' } })) } | Out-Null

#App Service
function New-Site {
    param([string]$Name, [string]$Kind, [array]$Functions = @())
    Add-Record 'Microsoft.Web/sites' $Name @{ kind = $Kind; identity = (Pick @{ type = 'SystemAssigned' } $null); properties = @{ httpsOnly = $G; publicNetworkAccess = (Pick 'Disabled' 'Enabled'); defaultHostName = "$Name.azurewebsites.net"; hostNames = @("$Name.azurewebsites.net") } } -Children @{
        'config/web'                       = @{ properties = @{ minTlsVersion = (Pick '1.2' '1.0'); scmMinTlsVersion = (Pick '1.2' '1.0'); ftpsState = (Pick 'Disabled' 'AllAllowed'); remoteDebuggingEnabled = (-not $G); cors = @{ allowedOrigins = (Pick @('https://contoso.com') @('*')) }; ipSecurityRestrictions = @() } }
        'config/authsettingsV2'            = @{ properties = @{ platform = @{ enabled = $false } } }
        basicPublishingCredentialsPolicies = @(@{ name = 'ftp'; properties = @{ allow = (-not $G) } }, @{ name = 'scm'; properties = @{ allow = (-not $G) } })
        functions                          = $Functions
    } | Out-Null
}
New-Site 'appfixture' 'app'
New-Site 'funcfixture' 'functionapp,linux' @(@{ name = 'funcfixture/Api'; properties = @{ isDisabled = $false; config = @{ bindings = @(@{ type = 'httpTrigger'; authLevel = (Pick 'function' 'anonymous') }) } } })

#compute
$diskId = ResId 'Microsoft.Compute/disks' 'diskfixture'
$vmId = ResId 'Microsoft.Compute/virtualMachines' 'vmfixture'
$nicId = ResId 'Microsoft.Network/networkInterfaces' 'nicfixture'
$extension = { param([string]$Publisher, [string]$Type, [hashtable]$Settings = @{}) @{ name = $Type; properties = @{ publisher = $Publisher; type = $Type; settings = $Settings } } }
$goodExtensions = @((& $extension 'Microsoft.Azure.AzureDefenderForServers' 'MDE.Linux'), (& $extension 'Microsoft.GuestConfiguration' 'ConfigurationForLinux'), (& $extension 'Microsoft.Azure.Monitor' 'AzureMonitorLinuxAgent'))
$badExtensions = @(& $extension 'Microsoft.EnterpriseCloud.Monitoring' 'OmsAgentForLinux' @{ adminPassword = 'Sup3rS3cretValue!' })
$security = Pick @{ encryptionAtHost = $true; securityType = 'TrustedLaunch'; uefiSettings = @{ secureBootEnabled = $true; vTpmEnabled = $true } } @{ securityType = 'Standard' }
$linux = @{ disablePasswordAuthentication = $G; patchSettings = @{ assessmentMode = (Pick 'AutomaticByPlatform' 'ImageDefault') } }
$b64 = { param([string]$Text) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)) }
#userData: clean cloud-init when Good, a private key when Bad (AZ-SEC-004 decodes and scans it)
$userData = Pick (& $b64 "#cloud-config`npackages:`n  - nginx`n") (& $b64 "#!/bin/bash`n-----BEGIN RSA PRIVATE KEY-----`nMIIEpAIBAAKCAQEAexampledeadbeef`n-----END RSA PRIVATE KEY-----`n")
Add-Record 'Microsoft.Compute/virtualMachines' 'vmfixture' @{ identity = (Pick @{ type = 'SystemAssigned' } $null); properties = @{
        storageProfile = @{ osDisk = (Pick @{ osType = 'Linux'; managedDisk = @{ id = $diskId } } @{ osType = 'Linux'; vhd = @{ uri = 'https://st.blob.core.windows.net/vhds/os.vhd' } }) }
        securityProfile = $security; osProfile = @{ linuxConfiguration = $linux }; networkProfile = @{ networkInterfaces = @(@{ id = $nicId }) }; userData = $userData
    }
} -Children @{ extensions = (Pick $goodExtensions $badExtensions); instanceView = @{} } | Out-Null
Add-Record 'Microsoft.Compute/virtualMachineScaleSets' 'vmssfixture' @{ properties = @{ virtualMachineProfile = @{ storageProfile = @{ osDisk = @{ osType = 'Linux' } }; securityProfile = $security; osProfile = @{ linuxConfiguration = $linux }; userData = $userData; extensionProfile = @{ extensions = (Pick $goodExtensions $badExtensions) } } } } -Children @{ extensions = @() } | Out-Null
Add-Record 'Microsoft.HybridCompute/machines' 'arcfixture' @{ properties = @{ osType = 'linux' } } -Children @{ extensions = (Pick $goodExtensions $badExtensions) } | Out-Null
Add-Record 'Microsoft.Compute/disks' 'diskfixture' @{ properties = @{ diskState = (Pick 'Attached' 'Unattached'); networkAccessPolicy = (Pick 'DenyAll' 'AllowAll'); publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } | Out-Null
Add-Record 'Microsoft.Compute/snapshots' 'snapfixture' @{ properties = @{ diskState = (Pick 'Reserved' 'ActiveSAS'); networkAccessPolicy = (Pick 'DenyAll' 'AllowAll'); publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } | Out-Null
Add-Record 'Microsoft.SqlVirtualMachine/sqlVirtualMachines' 'sqlvmfixture' @{ properties = @{} } | Out-Null
Add-Record 'Microsoft.ManagedIdentity/userAssignedIdentities' 'uamifixture' @{ properties = @{ clientId = '31000000-0000-0000-0000-000000000003' } } -Children @{ federatedIdentityCredentials = @(@{ name = 'gh'; properties = @{ issuer = 'https://token.actions.githubusercontent.com'; subject = (Pick 'repo:contoso/app:environment:production' 'repo:contoso/app:*'); audiences = @('api://AzureADTokenExchange') } }) } | Out-Null

#network
$nsgId = ResId 'Microsoft.Network/networkSecurityGroups' 'nsgfixture'
$vnetId = ResId 'Microsoft.Network/virtualNetworks' 'vnetfixture'
$defaultRules = @(
    @{ name = 'AllowVnetInBound'; properties = @{ priority = 65000; direction = 'Inbound'; access = 'Allow'; protocol = '*'; sourceAddressPrefix = 'VirtualNetwork'; destinationPortRange = '*' } }
    @{ name = 'AllowAzureLoadBalancerInBound'; properties = @{ priority = 65001; direction = 'Inbound'; access = 'Allow'; protocol = '*'; sourceAddressPrefix = 'AzureLoadBalancer'; destinationPortRange = '*' } }
    @{ name = 'DenyAllInBound'; properties = @{ priority = 65500; direction = 'Inbound'; access = 'Deny'; protocol = '*'; sourceAddressPrefix = '*'; destinationPortRange = '*' } }
)
$rule = Pick @{ name = 'allow-https-office'; properties = @{ priority = 100; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'; sourceAddressPrefix = '203.0.113.10'; destinationPortRange = '443' } } @{ name = 'allow-all'; properties = @{ priority = 100; direction = 'Inbound'; access = 'Allow'; protocol = '*'; sourceAddressPrefix = '*'; destinationPortRange = '*' } }
Add-Record 'Microsoft.Network/networkSecurityGroups' 'nsgfixture' @{ properties = @{ securityRules = @($rule); defaultSecurityRules = $defaultRules; subnets = @(@{ id = "$vnetId/subnets/app" }) } } | Out-Null
Add-Record 'Microsoft.Network/virtualNetworks' 'vnetfixture' @{ properties = @{
        enableDdosProtection = $G; ddosProtectionPlan = (Pick @{ id = '/ddos' } $null)
        subnets = @(
            @{ id = "$vnetId/subnets/app"; name = 'app'; properties = @{ networkSecurityGroup = (Pick @{ id = $nsgId } $null); defaultOutboundAccess = (-not $G) } }
            @{ id = "$vnetId/subnets/GatewaySubnet"; name = 'GatewaySubnet'; properties = @{ defaultOutboundAccess = $true } }
        )
    }
} | Out-Null
Add-Record 'Microsoft.Network/networkInterfaces' 'nicfixture' @{ properties = @{ enableIPForwarding = (-not $G); networkSecurityGroup = @{ id = $nsgId }; ipConfigurations = @(@{ properties = @{ subnet = @{ id = "$vnetId/subnets/app" }; publicIPAddress = (Pick $null @{ id = (ResId 'Microsoft.Network/publicIPAddresses' 'pip-nic') }) } }); virtualMachine = @{ id = $vmId } } } | Out-Null
Add-Record 'Microsoft.Network/publicIPAddresses' 'pipfixture' @{ properties = @{ ipAddress = '198.51.100.1'; ipConfiguration = (Pick @{ id = "$(ResId 'Microsoft.Network/applicationGateways' 'agwfixture')/frontendIPConfigurations/fe" } $null) } } | Out-Null
if ($G) { Add-Record 'Microsoft.Network/bastionHosts' 'bastionfixture' @{ properties = @{} } | Out-Null }
Add-Record 'Microsoft.Network/applicationGateways' 'agwfixture' @{ properties = @{ sku = @{ tier = (Pick 'WAF_v2' 'Standard_v2') }; firewallPolicy = (Pick @{ id = '/waf' } $null); sslPolicy = @{ policyType = 'Predefined'; policyName = (Pick 'AppGwSslPolicy20220101' 'AppGwSslPolicy20150501') }; enableHttp2 = $G } } | Out-Null
Add-Record 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies' 'wafagw' @{ properties = @{ policySettings = @{ state = 'Enabled'; mode = (Pick 'Prevention' 'Detection'); requestBodyCheck = $G }; managedRules = @{ managedRuleSets = (Pick @(@{ ruleSetType = 'OWASP' }, @{ ruleSetType = 'Microsoft_BotManagerRuleSet' }) @(@{ ruleSetType = 'OWASP' })) } } } | Out-Null
Add-Record 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies' 'waffd' @{ properties = @{ policySettings = @{ enabledState = (Pick 'Enabled' 'Disabled'); mode = (Pick 'Prevention' 'Detection'); requestBodyCheck = (Pick 'Enabled' 'Disabled') }; managedRules = @{ managedRuleSets = (Pick @(@{ ruleSetType = 'Microsoft_DefaultRuleSet' }, @{ ruleSetType = 'Microsoft_BotManagerRuleSet' }) @(@{ ruleSetType = 'Microsoft_DefaultRuleSet' })) } } } | Out-Null
Add-Record 'Microsoft.Cdn/profiles' 'afdfixture' @{ sku = @{ name = 'Premium_AzureFrontDoor' }; properties = @{} } -Children @{ securityPolicies = (Pick @(@{ name = 'waf'; properties = @{ parameters = @{ type = 'WebApplicationFirewall' } } }) @()); afdEndpoints = @(@{ properties = @{ hostName = 'fixture.azurefd.net' } }) } | Out-Null
Add-Record 'Microsoft.Network/firewallPolicies' 'fwpolicy' @{ properties = @{ sku = @{ tier = (Pick 'Premium' 'Standard') }; threatIntelMode = (Pick 'Deny' 'Alert'); intrusionDetection = (Pick @{ mode = 'Deny' } $null) } } | Out-Null
Add-Record 'Microsoft.Network/virtualNetworkGateways' 'vpnfixture' @{ properties = @{ vpnClientConfiguration = @{ vpnClientAddressPool = @{ addressPrefixes = @('172.16.0.0/24') }; vpnAuthenticationTypes = @((Pick 'AAD' 'Certificate')) } } } | Out-Null
$zoneId = ResId 'Microsoft.Network/dnszones' 'fixture.example'
Add-Record 'Microsoft.Network/dnszones' 'fixture.example' @{ location = 'global'; properties = @{} } -Children @{ recordsets = @(
        @{ id = "$zoneId/CNAME/www"; type = 'Microsoft.Network/dnszones/CNAME'; properties = @{ fqdn = 'www.fixture.example.'; CNAMERecord = @{ cname = (Pick 'appfixture.azurewebsites.net' 'gone-app.azurewebsites.net') } } }
        @{ id = "$zoneId/A/alias"; type = 'Microsoft.Network/dnszones/A'; properties = @{ fqdn = 'alias.fixture.example.'; targetResource = @{ id = (Pick (ResId 'Microsoft.Network/publicIPAddresses' 'pipfixture') (ResId 'Microsoft.Network/publicIPAddresses' 'pip-deleted')) } } }
    )
} | Out-Null
$newFlowLog = {
    param([string]$Name, [string]$Target, [bool]$Enabled)
    @{ id = "$(ResId 'Microsoft.Network/networkWatchers' 'nwfixture')/flowLogs/$Name"; type = 'Microsoft.Network/networkWatchers/flowLogs'; name = $Name; properties = @{
            enabled = $Enabled; targetResourceId = $Target; retentionPolicy = @{ enabled = $true; days = (Pick 90 30) }
            flowAnalyticsConfiguration = @{ networkWatcherFlowAnalyticsConfiguration = @{ enabled = $G } }
        }
    }
}
$flowLogs = @(
    (& $newFlowLog 'fl-vnet' $vnetId $G)
    (& $newFlowLog 'fl-nsg' $nsgId $true)
)
Add-Record 'Microsoft.Network/networkWatchers' 'nwfixture' @{ location = (Pick $location 'northeurope'); properties = @{} } -Children @{ flowLogs = $flowLogs } | Out-Null

#Defender assessments of the virtual machine
$assessmentKeys = 'dc5357d0-3858-4d17-a1a3-072840bff5be', 'e1145ab1-eb4f-43d8-911b-36ddf771d13f', '1195afff-c881-495e-9bc5-1486211ae03f', '1f655fb7-63ca-4980-91a3-56dbc2b715c6'
Save 'defender/assessments' @(foreach ($key in $assessmentKeys) { @{ id = "$vmId/providers/Microsoft.Security/assessments/$key"; name = $key; properties = @{ status = @{ code = (Pick 'Healthy' 'Unhealthy') }; resourceDetails = @{ Source = 'Azure'; Id = $vmId } } } })

#monitoring
if ($G) { Add-Record 'Microsoft.Insights/components' 'appifixture' @{ properties = @{ DisableLocalAuth = $true; publicNetworkAccessForIngestion = 'Disabled'; publicNetworkAccessForQuery = 'Disabled' } } | Out-Null }
Add-Record 'Microsoft.OperationalInsights/workspaces' 'lafixture' @{ properties = @{ retentionInDays = (Pick 90 30); features = @{ disableLocalAuth = $G }; publicNetworkAccessForIngestion = (Pick 'Disabled' 'Enabled'); publicNetworkAccessForQuery = (Pick 'Disabled' 'Enabled') } } | Out-Null
if ($G) {
    $alertOps = @('Microsoft.Authorization/policyAssignments/write', 'Microsoft.Authorization/policyAssignments/delete', 'Microsoft.Network/networkSecurityGroups/write', 'Microsoft.Network/networkSecurityGroups/delete', 'Microsoft.Security/securitySolutions/write', 'Microsoft.Security/securitySolutions/delete', 'Microsoft.Sql/servers/firewallRules/write', 'Microsoft.Sql/servers/firewallRules/delete', 'Microsoft.Network/publicIPAddresses/write', 'Microsoft.Network/publicIPAddresses/delete')
    $n = 0
    foreach ($operation in $alertOps) {
        $n++
        $category = if ($operation -like 'Microsoft.Security/*') { 'Security' } else { 'Administrative' }
        Add-Record 'Microsoft.Insights/activityLogAlerts' "alert$n" @{ location = 'global'; properties = @{ enabled = $true; scopes = @($subScope); condition = @{ allOf = @(@{ field = 'category'; equals = $category }, @{ field = 'operationName'; equals = $operation }) }; actions = @{ actionGroups = @(@{ actionGroupId = '/ag' }) } } } | Out-Null
    }
    Add-Record 'Microsoft.Insights/activityLogAlerts' 'servicehealth' @{ location = 'global'; properties = @{ enabled = $true; scopes = @($subScope); condition = @{ allOf = @(@{ field = 'category'; equals = 'ServiceHealth' }) }; actions = @{ actionGroups = @(@{ actionGroupId = '/ag' }) } } } | Out-Null
}

#containers
Add-Record 'Microsoft.ContainerService/managedClusters' 'aksfixture' @{ identity = (Pick @{ type = 'SystemAssigned' } $null); properties = @{
        disableLocalAccounts = $G; aadProfile = (Pick @{ managed = $true; enableAzureRBAC = $true } $null); apiServerAccessProfile = @{ enablePrivateCluster = $G; disableRunCommand = $G }
        addonProfiles = @{ azurepolicy = @{ enabled = $G } }; autoUpgradeProfile = @{ upgradeChannel = (Pick 'stable' 'none'); nodeOSUpgradeChannel = (Pick 'NodeImage' 'None') }
        networkProfile = @{ networkPlugin = 'azure'; networkPolicy = (Pick 'cilium' 'none') }; securityProfile = @{ azureKeyVaultKms = @{ enabled = $G } }; servicePrincipalProfile = (Pick $null @{ clientId = 'abc' })
    }
} | Out-Null
Add-Record 'Microsoft.ContainerRegistry/registries' 'acrfixture' @{ sku = @{ name = 'Premium' }; properties = @{ adminUserEnabled = (-not $G); anonymousPullEnabled = (-not $G); publicNetworkAccess = (Pick 'Disabled' 'Enabled'); networkRuleSet = @{ defaultAction = (Pick 'Deny' 'Allow') }; policies = @{ azureADAuthenticationAsArmPolicy = @{ status = (Pick 'disabled' 'enabled') } } } } -Children @{ tokens = (Pick @() @(@{ name = 'ci'; properties = @{ status = 'enabled' } })) } | Out-Null
Add-Record 'Microsoft.App/containerApps' 'capfixture' @{ properties = @{ configuration = @{ ingress = @{ external = (-not $G); allowInsecure = (-not $G); ipSecurityRestrictions = @() } }; template = @{ containers = @(@{ name = 'app'; env = @((Pick @{ name = 'DB_PASSWORD'; secretRef = 'db-password' } @{ name = 'DB_PASSWORD'; value = 'Sup3rS3cretValue!' })) }) } } } | Out-Null
Add-Record 'Microsoft.ContainerInstance/containerGroups' 'acifixture' @{ properties = @{ ipAddress = @{ type = (Pick 'Private' 'Public'); ports = @(@{ protocol = 'TCP'; port = 80 }) }; containers = @(@{ name = 'c1'; properties = @{ environmentVariables = @((Pick @{ name = 'API_KEY' } @{ name = 'API_KEY'; value = 'abcdefghijklmnop1234' })) } }) } } | Out-Null

#messaging and integration
foreach ($type in 'Microsoft.ServiceBus/namespaces', 'Microsoft.EventHub/namespaces') {
    Add-Record $type "$(($type -split '[./]')[1].ToLowerInvariant())fixture" @{ properties = @{ disableLocalAuth = $G; publicNetworkAccess = (Pick 'Disabled' 'Enabled'); minimumTlsVersion = (Pick '1.2' '1.0') } } -Children @{ authorizationRules = @(@{ name = 'RootManageSharedAccessKey'; properties = @{ rights = @('Listen', 'Send', 'Manage') } }) + (Pick @() @(@{ name = 'app-send'; properties = @{ rights = @('Send') } })) } | Out-Null
}
$apimId = ResId 'Microsoft.ApiManagement/service' 'apimfixture'
Add-Record 'Microsoft.ApiManagement/service' 'apimfixture' @{ properties = @{ publicNetworkAccess = (Pick 'Disabled' 'Enabled'); platformVersion = (Pick 'stv2' 'stv1'); customProperties = @{ 'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10' = (Pick 'False' 'True') } } } -Children @{
    'tenant/access' = @{ properties = @{ enabled = (-not $G) } }
    apis            = @(@{ name = 'orders'; properties = @{ protocols = (Pick @('https') @('http', 'https')) } })
    namedValues     = @(@{ name = 'nv1'; properties = @{ displayName = 'backend-key'; secret = $true; keyVault = (Pick @{ secretIdentifier = 'https://kv.vault.azure.net/secrets/x' } $null) } })
    subscriptions   = @(@{ name = 'master'; properties = @{ scope = "$apimId/apis"; state = 'active'; displayName = 'Built-in all-access' } }, @{ name = 's1'; properties = @{ scope = (Pick "$apimId/products/starter" "$apimId/apis"); state = 'active'; displayName = 'Partner' } })
    backends        = @(@{ name = 'be1'; properties = @{ tls = @{ validateCertificateChain = $G; validateCertificateName = $G } } })
} | Out-Null
$aaId = Add-Record 'Microsoft.Automation/automationAccounts' 'aafixture' @{ identity = (Pick @{ type = 'SystemAssigned' } $null); properties = @{ disableLocalAuth = $G; publicNetworkAccess = (-not $G) } } -Children @{
    variables = @(@{ name = 'v1'; properties = @{ isEncrypted = $G } }); certificates = @()
    connections = (Pick @() @(@{ name = 'AzureRunAsConnection'; properties = @{ connectionType = @{ name = 'AzureServicePrincipal' } } }))
}
Add-Record 'Microsoft.Automation/automationAccounts/runbooks' 'aafixture/rb1' @{ properties = @{ runbookType = 'PowerShell' } } -Id "$aaId/runbooks/rb1" -Diagnostics @() -Text @{ content = (Pick 'Connect-AzAccount -Identity' "`$password = `"Sup3rS3cretValue!`"`nConnect-Something") } | Out-Null

#AI
$aiId = ResId 'Microsoft.CognitiveServices/accounts' 'aifixture'
Add-Record 'Microsoft.CognitiveServices/accounts' 'aifixture' @{ kind = 'AIServices'; properties = @{ disableLocalAuth = $G; publicNetworkAccess = (Pick 'Disabled' 'Enabled'); networkAcls = @{ defaultAction = (Pick 'Deny' 'Allow') }; restrictOutboundNetworkAccess = $G; allowedFqdnList = @('contoso.com') } } -Children @{
    deployments = @(@{ id = "$aiId/deployments/gpt"; name = 'gpt'; properties = @{ model = @{ name = 'gpt-4o'; version = '2024-08-06' }; raiPolicyName = (Pick 'Microsoft.DefaultV2' 'weak') } })
    raiPolicies = (Pick @() @(@{ name = 'weak'; properties = @{ contentFilters = @(@{ name = 'Hate'; source = 'Prompt'; enabled = $false; blocking = $false }, @{ name = 'Jailbreak'; source = 'Prompt'; enabled = $false; blocking = $false }) } }))
} | Out-Null
$mlId = ResId 'Microsoft.MachineLearningServices/workspaces' 'mlfixture'
Add-Record 'Microsoft.MachineLearningServices/workspaces' 'mlfixture' @{ properties = @{ publicNetworkAccess = (Pick 'Disabled' 'Enabled'); managedNetwork = @{ isolationMode = (Pick 'AllowOnlyApprovedOutbound' 'AllowInternetOutbound') } } } -Children @{
    computes = @(@{ id = "$mlId/computes/ci1"; name = 'ci1'; properties = @{ computeType = 'ComputeInstance'; disableLocalAuth = $G; properties = @{ sshSettings = @{ sshPublicAccess = (Pick 'Disabled' 'Enabled') }; enableNodePublicIp = (-not $G) } } })
} | Out-Null

#backup
Add-Record 'Microsoft.RecoveryServices/vaults' 'rsvfixture' @{ properties = @{
        securitySettings = @{ softDeleteSettings = @{ softDeleteState = (Pick 'AlwaysON' 'Disabled') }; immutabilitySettings = @{ state = (Pick 'Locked' 'Disabled') } }; publicNetworkAccess = (Pick 'Disabled' 'Enabled')
        restoreSettings = @{ crossSubscriptionRestoreSettings = @{ crossSubscriptionRestoreState = (Pick 'Disabled' 'Enabled') } }; monitoringSettings = @{ azureMonitorAlertSettings = @{ alertsForAllJobFailures = (Pick 'Enabled' 'Disabled') } }
    }
} -Children @{
    'backupconfig/vaultconfig' = @{ properties = @{ softDeleteFeatureState = (Pick 'AlwaysON' 'Disabled') } }; 'backupstorageconfig/vaultstorageconfig' = @{ properties = @{ storageModelType = (Pick 'GeoRedundant' 'LocallyRedundant') } }
    backupResourceGuardProxies = (Pick @(@{ properties = @{ resourceGuardResourceId = '/guard' } }) @()); backupProtectedItems = (Pick @(@{ properties = @{ sourceResourceId = $vmId; virtualMachineId = $vmId } }) @())
} | Out-Null
Add-Record 'Microsoft.DataProtection/backupVaults' 'bvfixture' @{ properties = @{
        securitySettings = @{ softDeleteSettings = @{ state = (Pick 'AlwaysOn' 'Off') }; immutabilitySettings = @{ state = (Pick 'Unlocked' 'Disabled') } }; storageSettings = @(@{ type = (Pick 'GeoRedundant' 'LocallyRedundant'); datastoreType = 'VaultStore' })
        featureSettings = @{ crossSubscriptionRestoreSettings = @{ state = (Pick 'Disabled' 'Enabled') } }; monitoringSettings = @{ azureMonitorAlertSettings = @{ alertsForAllJobFailures = (Pick 'Enabled' 'Disabled') } }
    }
} -Children @{ backupResourceGuardProxies = (Pick @(@{ properties = @{ resourceGuardResourceId = '/guard' } }) @()) } | Out-Null

#data and analytics
$databricksProperties = {
    param($VnetId)
    @{ properties = @{
            parameters = @{ customVirtualNetworkId = @{ value = $VnetId }; customPublicSubnetName = @{ value = 'app' }; customPrivateSubnetName = @{ value = 'app' }; enableNoPublicIp = @{ value = $G } }
            publicNetworkAccess = (Pick 'Disabled' 'Enabled'); privateEndpointConnections = (Pick @(@{ id = '/pe1'; properties = @{ privateLinkServiceConnectionState = @{ status = 'Approved' } } }) @())
        }
    }
}
Add-Record 'Microsoft.Databricks/workspaces' 'dbxfixture' (& $databricksProperties (Pick $vnetId $null)) | Out-Null
if (-not $G) { Add-Record 'Microsoft.Databricks/workspaces' 'dbxvnetfixture' (& $databricksProperties $vnetId) | Out-Null }
Add-Record 'Microsoft.Synapse/workspaces' 'synfixture' @{ properties = @{ managedVirtualNetwork = (Pick 'default' $null); managedVirtualNetworkSettings = @{ preventDataExfiltration = $G }; publicNetworkAccess = (Pick 'Disabled' 'Enabled') } } -Children @{
    firewallRules = (Pick @() @(@{ name = 'all'; properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '255.255.255.255' } })); 'sqlAdministrators/activeDirectory' = (Pick @{ properties = @{ login = 'syn-admins' } } @{ properties = @{} })
    azureADOnlyAuthentications = @(@{ properties = @{ azureADOnlyAuthentication = $G } }); securityAlertPolicies = @(@{ properties = @{ state = (Pick 'Enabled' 'Disabled') } })
} | Out-Null
Add-Record 'Microsoft.DataFactory/factories' 'adffixture' @{ properties = @{ publicNetworkAccess = (Pick 'Disabled' 'Enabled'); repoConfiguration = (Pick @{ type = 'FactoryGitHubConfiguration' } $null) } } -Children @{
    linkedservices = @(@{ name = 'ls1'; properties = @{ typeProperties = @{ url = 'https://contoso.com'; password = (Pick @{ type = 'AzureKeyVaultSecret'; secretName = 'pw' } @{ type = 'SecureString'; value = '**********' }) } } })
} | Out-Null

#endregion

Save 'resourceGraph/policyresources' @(
    @{ id = "$subScope/providers/Microsoft.PolicyInsights/policyStates/ps1"; type = 'microsoft.policyinsights/policystates'; properties = @{ complianceState = (Pick 'Compliant' 'NonCompliant'); policyDefinitionId = '/providers/microsoft.authorization/policydefinitions/404c3081-a854-4457-ae30-26a93ef643f9'; policyAssignmentName = 'SecurityCenterBuiltIn'; resourceId = (ResId 'Microsoft.Storage/storageAccounts' 'stfixture') } }
)
Save 'resourceGraph/advisorresources' (Pick @() @(
        @{ id = "$rgId/providers/Microsoft.Advisor/recommendations/rec1"; type = 'microsoft.advisor/recommendations'; properties = @{ category = 'Security'; impact = 'High'; impactedField = 'Microsoft.Storage/storageAccounts'; impactedValue = 'stfixture'; shortDescription = @{ problem = 'Secure transfer to storage accounts should be enabled'; solution = 'Enable secure transfer' } } }
    ))
Save 'subscription/resources' $resourceList
$index.Add([ordered]@{ id = $rgId; type = 'resourceGroup'; file = 'resourceGroups/rg-fixture.json'; status = 'ok' })
Save 'resourceGroups/rg-fixture' @{ id = $rgId; deployments = @(); deploymentStacks = @(); lighthouseRegistrationAssignments = @() }
Save 'index' $index
Save 'manifest' ([ordered]@{
        schemaVersion = 1; scriptVersion = 'fixture'; status = 'completed'; startedAt = $reference.ToString('yyyy-MM-ddTHH:mm:ssZ')
        subscription = @{ id = $sub; displayName = "Fixture ($Mode)"; tenantId = $tenant; state = 'Enabled' }
        sections = @{ 'identity/users' = @{ status = 'ok'; signInActivity = $true } }
    })
