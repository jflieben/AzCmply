#Requires -Version 7.2
<#
    .SYNOPSIS
    Collects all security relevant data of an Azure subscription into a folder of JSON files for offline analysis.
    .DESCRIPTION
    Uses REST only (no Az modules) and only read operations; no keys or secrets are listed. Collects:
    - Subscription, resource groups, providers, locks, deployments (incl. parameters/outputs), deployment stacks, Lighthouse delegations
    - RBAC: role assignments/definitions, deny assignments, classic administrators, PIM schedules, requests and policies
    - Azure Policy: assignments, definitions, initiatives, exemptions, compliance summary, attestations, remediations
    - Defender for Cloud: plans, contacts, settings, assessments, alerts, secure score, JIT policies, workflow automations,
      multicloud security connectors, governance rules, alert suppression rules, API security collections,
      regulatory compliance standards, custom security standards/assignments/recommendations and assessment metadata
    - Every resource: full GET at the latest stable API version, diagnostic settings and security relevant child resources ($childResourceMap)
    - Azure Resource Graph tables scoped to the subscription (incl. change history, patch and guest configuration state)
    - Activity log
    - Entra ID: every principal referenced by the above, group members and owners, service principal/application credentials,
      owners, API permissions and federated credentials, directory role assignments, Conditional Access policies and security defaults

    Output can contain sensitive values (deployment outputs, unencrypted automation variables, container environment variables, etc).
    .PARAMETER SubscriptionId
    Subscription to collect.
    .PARAMETER TenantId
    Tenant of the service principal. Optional with -ManagedIdentity.
    .PARAMETER ClientId
    Application (client) id of the service principal, or of a user assigned managed identity.
    .PARAMETER ClientSecret
    Client secret of the service principal.
    .PARAMETER CertificateThumbprint
    Thumbprint of a certificate with private key in the CurrentUser or LocalMachine 'My' store.
    .PARAMETER CertificatePath
    Path to a .pfx or .pem file containing certificate and private key.
    .PARAMETER CertificatePassword
    Password of the .pfx file.
    .PARAMETER ManagedIdentity
    Use the managed identity of the host (VM, App Service, Functions, Automation, Container Apps, Arc). Add -ClientId for a user assigned identity.
    .PARAMETER Environment
    Azure cloud. Default AzureCloud.
    .PARAMETER OutputPath
    Folder in which the run folder is created. Default .\AzureIngest
    .PARAMETER FolderName
    Name of the run folder. Default <subscriptionId>_<yyyyMMdd-HHmmss> (UTC).
    .PARAMETER Compress
    Zips the run folder to <run folder>.zip and removes the folder.
    .PARAMETER CompactJson
    Writes JSON without indentation (smaller files).
    .PARAMETER ActivityLogDays
    Days of activity log to collect, 0 to skip. Default 90 (the maximum retention).
    .PARAMETER SkipGraph
    Skips Entra ID enrichment.
    .PARAMETER SkipResourceGraph
    Skips the Azure Resource Graph table export.
    .PARAMETER ThrottleLimit
    Parallel threads for per resource collection. Default 8.
    .EXAMPLE
    .\Invoke-AzureIngest.ps1 -SubscriptionId $sub -TenantId $tenant -ClientId $appId -ClientSecret (Read-Host -AsSecureString)
    .EXAMPLE
    .\Invoke-AzureIngest.ps1 -SubscriptionId $sub -TenantId $tenant -ClientId $appId -CertificateThumbprint 'A1B2...' -OutputPath D:\Ingest -Compress
    .EXAMPLE
    .\Invoke-AzureIngest.ps1 -SubscriptionId $sub -ManagedIdentity -ActivityLogDays 30
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.jsolve.nl
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html

    Required permissions:
    - Azure: Reader on the subscription
    - Graph (application): Directory.Read.All
      Optional: RoleManagement.Read.Directory (eligible directory roles), AuditLog.Read.All (sign-in activity),
      Policy.Read.All (Conditional Access policies and security defaults)
    Missing permissions do not stop the run; every failed call is listed in failures.json.
    Output layout: see README.md
#>

[CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
Param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateFile')]
    [Parameter(ParameterSetName = 'ManagedIdentity')]
    [string]$TenantId,
    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateFile')]
    [Parameter(ParameterSetName = 'ManagedIdentity')]
    [Alias('ApplicationId', 'ServicePrincipalId')][string]$ClientId,
    [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')][SecureString]$ClientSecret,
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')][string]$CertificateThumbprint,
    [Parameter(Mandatory = $true, ParameterSetName = 'CertificateFile')][string]$CertificatePath,
    [Parameter(ParameterSetName = 'CertificateFile')][SecureString]$CertificatePassword,
    [Parameter(Mandatory = $true, ParameterSetName = 'ManagedIdentity')][switch]$ManagedIdentity,
    [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud')][string]$Environment = 'AzureCloud',
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath 'AzureIngest'),
    [string]$FolderName,
    [switch]$Compress,
    [switch]$CompactJson,
    [ValidateRange(0, 90)][int]$ActivityLogDays = 90,
    [switch]$SkipGraph,
    [switch]$SkipResourceGraph,
    [ValidateRange(1, 32)][int]$ThrottleLimit = 8
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$scriptVersion = '1.0.0'
$schemaVersion = 1
$authMethod = $PSCmdlet.ParameterSetName

$cloudEndpoints = @{
    AzureCloud        = @{ Login = 'https://login.microsoftonline.com'; Arm = 'https://management.azure.com'; Graph = 'https://graph.microsoft.com' }
    AzureUSGovernment = @{ Login = 'https://login.microsoftonline.us'; Arm = 'https://management.usgovcloudapi.net'; Graph = 'https://graph.microsoft.us' }
    AzureChinaCloud   = @{ Login = 'https://login.chinacloudapi.cn'; Arm = 'https://management.chinacloudapi.cn'; Graph = 'https://microsoftgraph.chinacloudapi.cn' }
}[$Environment]

#region collection maps
#Data only: Web/Convert-AzCmplyToWeb.ps1 extracts this region for the browser ingestion, so keep it free of logic.

#api versions of the calls that are not made per resource type
$coreApiVersions = [ordered]@{
    subscription       = '2022-12-01'
    providers          = '2021-04-01'
    resourceGroups     = '2021-04-01'
    resources          = '2021-04-01'
    diagnosticSettings = '2021-05-01-preview'
    resourceGraph      = '2022-10-01'
    activityLog        = '2015-04-01'
}
$resourceListExpand = 'createdTime,changedTime,provisioningState'

#Microsoft Graph properties read per kind of object, and the tenant wide exports (file name, path): directory roles,
#Conditional Access policies and security defaults
$graphSelect = [ordered]@{
    member = 'id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,appId,servicePrincipalType,appOwnerOrganizationId'
    user   = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,creationType,externalUserState,onPremisesSyncEnabled,onPremisesSamAccountName,createdDateTime,lastPasswordChangeDateTime'
    owner  = 'id,displayName,userPrincipalName,appId'
    api    = 'id,appId,displayName,appRoles,oauth2PermissionScopes'
}
$graphDirectoryExports = @(
    ,@('directoryRoleDefinitions', '/v1.0/roleManagement/directory/roleDefinitions')
    ,@('directoryRoleAssignments', '/v1.0/roleManagement/directory/roleAssignments?$expand=principal')
    ,@('directoryRoleEligibilitySchedules', '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal')
    ,@('conditionalAccessPolicies', '/v1.0/identity/conditionalAccess/policies')
    ,@('securityDefaults', '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy')
)

#subscription scoped endpoints: output folder, file name, path below /subscriptions/{id}/, api version, method
$subscriptionEndpoints = @(
    ,@('subscription', 'locks', 'providers/Microsoft.Authorization/locks', '2020-05-01')
    ,@('subscription', 'deployments', 'providers/Microsoft.Resources/deployments', '2026-06-01')
    ,@('subscription', 'deploymentStacks', 'providers/Microsoft.Resources/deploymentStacks', '2025-07-01')
    ,@('subscription', 'lighthouseRegistrationDefinitions', 'providers/Microsoft.ManagedServices/registrationDefinitions', '2022-10-01')
    ,@('subscription', 'lighthouseRegistrationAssignments', 'providers/Microsoft.ManagedServices/registrationAssignments?$expandRegistrationDefinition=true', '2022-10-01')
    ,@('subscription', 'blueprintAssignments', 'providers/Microsoft.Blueprint/blueprintAssignments', '2018-11-01-preview')
    ,@('subscription', 'diagnosticSettings', 'providers/Microsoft.Insights/diagnosticSettings', '2021-05-01-preview')
    ,@('subscription', 'logProfiles', 'providers/Microsoft.Insights/logProfiles', '2016-03-01')
    ,@('subscription', 'eventGridSubscriptions', 'providers/Microsoft.EventGrid/eventSubscriptions', '2025-02-15')
    ,@('subscription', 'networkManagerConnections', 'providers/Microsoft.Network/networkManagerConnections', '2026-03-01')
    ,@('rbac', 'roleAssignments', 'providers/Microsoft.Authorization/roleAssignments', '2022-04-01')
    ,@('rbac', 'roleDefinitions', 'providers/Microsoft.Authorization/roleDefinitions', '2022-04-01')
    ,@('rbac', 'denyAssignments', 'providers/Microsoft.Authorization/denyAssignments', '2022-04-01')
    ,@('rbac', 'roleEligibilitySchedules', 'providers/Microsoft.Authorization/roleEligibilitySchedules', '2020-10-01')
    ,@('rbac', 'roleEligibilityScheduleInstances', 'providers/Microsoft.Authorization/roleEligibilityScheduleInstances', '2020-10-01')
    ,@('rbac', 'roleEligibilityScheduleRequests', 'providers/Microsoft.Authorization/roleEligibilityScheduleRequests', '2020-10-01')
    ,@('rbac', 'roleAssignmentSchedules', 'providers/Microsoft.Authorization/roleAssignmentSchedules', '2020-10-01')
    ,@('rbac', 'roleAssignmentScheduleInstances', 'providers/Microsoft.Authorization/roleAssignmentScheduleInstances', '2020-10-01')
    ,@('rbac', 'roleAssignmentScheduleRequests', 'providers/Microsoft.Authorization/roleAssignmentScheduleRequests', '2020-10-01')
    ,@('rbac', 'roleManagementPolicies', 'providers/Microsoft.Authorization/roleManagementPolicies', '2020-10-01')
    ,@('rbac', 'roleManagementPolicyAssignments', 'providers/Microsoft.Authorization/roleManagementPolicyAssignments', '2020-10-01')
    ,@('policy', 'policyAssignments', 'providers/Microsoft.Authorization/policyAssignments', '2026-06-01')
    ,@('policy', 'policyDefinitions', 'providers/Microsoft.Authorization/policyDefinitions', '2026-06-01')
    ,@('policy', 'policySetDefinitions', 'providers/Microsoft.Authorization/policySetDefinitions', '2026-06-01')
    ,@('policy', 'policyExemptions', 'providers/Microsoft.Authorization/policyExemptions', '2022-07-01-preview')
    ,@('policy', 'policyStatesSummary', 'providers/Microsoft.PolicyInsights/policyStates/latest/summarize', '2024-10-01', 'POST')
    ,@('policy', 'attestations', 'providers/Microsoft.PolicyInsights/attestations', '2024-10-01')
    ,@('policy', 'remediations', 'providers/Microsoft.PolicyInsights/remediations', '2024-10-01')
    ,@('defender', 'pricings', 'providers/Microsoft.Security/pricings', '2024-01-01')
    ,@('defender', 'securityContacts', 'providers/Microsoft.Security/securityContacts', '2023-12-01-preview')
    ,@('defender', 'autoProvisioningSettings', 'providers/Microsoft.Security/autoProvisioningSettings', '2019-01-01')
    ,@('defender', 'settings', 'providers/Microsoft.Security/settings', '2022-05-01')
    ,@('defender', 'workspaceSettings', 'providers/Microsoft.Security/workspaceSettings', '2019-01-01')
    ,@('defender', 'serverVulnerabilityAssessmentsSettings', 'providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings', '2023-05-01')
    ,@('defender', 'assessments', 'providers/Microsoft.Security/assessments', '2025-05-04')
    ,@('defender', 'secureScores', 'providers/Microsoft.Security/secureScores', '2020-01-01')
    ,@('defender', 'secureScoreControls', 'providers/Microsoft.Security/secureScoreControls', '2020-01-01')
    ,@('defender', 'alerts', 'providers/Microsoft.Security/alerts', '2022-01-01')
    ,@('defender', 'jitNetworkAccessPolicies', 'providers/Microsoft.Security/jitNetworkAccessPolicies', '2020-01-01')
    ,@('defender', 'automations', 'providers/Microsoft.Security/automations', '2019-01-01-preview')
    ,@('defender', 'alertsSuppressionRules', 'providers/Microsoft.Security/alertsSuppressionRules', '2019-01-01-preview')
    ,@('defender', 'securityConnectors', 'providers/Microsoft.Security/securityConnectors', '2023-10-01-preview')
    ,@('defender', 'governanceRules', 'providers/Microsoft.Security/governanceRules', '2022-01-01-preview')
    ,@('defender', 'apiCollections', 'providers/Microsoft.Security/apiCollections', '2023-11-15')
    ,@('defender', 'regulatoryComplianceStandards', 'providers/Microsoft.Security/regulatoryComplianceStandards', '2019-01-01-preview')
    ,@('defender', 'securityStandards', 'providers/Microsoft.Security/securityStandards', '2024-08-01')
    ,@('defender', 'standardAssignments', 'providers/Microsoft.Security/standardAssignments', '2024-08-01')
    ,@('defender', 'customRecommendations', 'providers/Microsoft.Security/customRecommendations', '2024-08-01')
    ,@('defender', 'assessmentMetadata', 'providers/Microsoft.Security/assessmentMetadata', '2025-05-04')
)

#resource group scoped endpoints: property name, path below the resource group id, api version
$resourceGroupEndpoints = @(
    ,@('deployments', 'providers/Microsoft.Resources/deployments', '2021-04-01')
    ,@('deploymentStacks', 'providers/Microsoft.Resources/deploymentStacks', '2024-03-01')
    ,@('lighthouseRegistrationAssignments', 'providers/Microsoft.ManagedServices/registrationAssignments?$expandRegistrationDefinition=true', '2022-10-01')
)

#child resources per resource type (lowercase), relative to the resource id. 'path@apiVersion' pins a version, otherwise the
#latest stable version of the child type is used. 'a/*/b' lists collection a, then b below each item of a.
$diagnosticSettingsPath = 'providers/Microsoft.Insights/diagnosticSettings@2021-05-01-preview'
$threatProtectionPath = 'providers/Microsoft.Security/advancedThreatProtectionSettings/current@2019-01-01'
$kubernetesConfigPaths = @('providers/Microsoft.KubernetesConfiguration/extensions@2023-05-01', 'providers/Microsoft.KubernetesConfiguration/fluxConfigurations@2023-05-01')
$webSiteChildren = @('config/web', 'config/authsettingsV2', 'config/logs', 'basicPublishingCredentialsPolicies', 'hostNameBindings', 'virtualNetworkConnections', 'privateEndpointConnections', 'sourcecontrols/web', 'functions')
$serviceBusLikeChildren = @('authorizationRules', 'networkRuleSets/default', 'disasterRecoveryConfigs', 'privateEndpointConnections')
$flexibleServerChildren = @('firewallRules', 'administrators', 'configurations', 'databases', 'advancedThreatProtectionSettings', 'privateEndpointConnections')
$singleServerChildren = @('firewallRules', 'virtualNetworkRules', 'administrators', 'configurations', 'securityAlertPolicies')
$signalRChildren = @('customDomains', 'sharedPrivateLinkResources', 'privateEndpointConnections')

$childResourceMap = @{
    'microsoft.storage/storageaccounts'                = @(
        'blobServices/default', 'blobServices/default/containers', 'fileServices/default', 'fileServices/default/shares',
        'queueServices/default', 'tableServices/default', 'managementPolicies/default', 'encryptionScopes', 'localUsers', 'objectReplicationPolicies',
        "blobServices/default/$diagnosticSettingsPath", "fileServices/default/$diagnosticSettingsPath",
        "queueServices/default/$diagnosticSettingsPath", "tableServices/default/$diagnosticSettingsPath",
        'providers/Microsoft.Security/defenderForStorageSettings/current@2025-01-01', $threatProtectionPath
    )
    'microsoft.keyvault/vaults'                        = @('keys', 'secrets')
    'microsoft.sql/servers'                            = @(
        'firewallRules', 'ipv6FirewallRules', 'virtualNetworkRules', 'outboundFirewallRules', 'administrators', 'azureADOnlyAuthentications',
        'auditingSettings', 'extendedAuditingSettings', 'devOpsAuditingSettings', 'securityAlertPolicies', 'advancedThreatProtectionSettings',
        'vulnerabilityAssessments', 'sqlVulnerabilityAssessments', 'encryptionProtector', 'keys', 'connectionPolicies', 'failoverGroups', 'privateEndpointConnections'
    )
    'microsoft.sql/servers/databases'                  = @(
        'transparentDataEncryption', 'auditingSettings', 'extendedAuditingSettings', 'securityAlertPolicies', 'advancedThreatProtectionSettings',
        'vulnerabilityAssessments', 'dataMaskingPolicies/Default', 'backupShortTermRetentionPolicies', 'backupLongTermRetentionPolicies', 'ledgerDigestUploads'
    )
    'microsoft.sql/managedinstances'                   = @(
        'administrators', 'azureADOnlyAuthentications', 'encryptionProtector', 'keys', 'securityAlertPolicies', 'advancedThreatProtectionSettings',
        'vulnerabilityAssessments', 'serverTrustCertificates', 'privateEndpointConnections'
    )
    'microsoft.sql/managedinstances/databases'         = @('transparentDataEncryption', 'securityAlertPolicies', 'advancedThreatProtectionSettings', 'vulnerabilityAssessments', 'backupShortTermRetentionPolicies')
    'microsoft.web/sites'                              = $webSiteChildren
    'microsoft.web/sites/slots'                        = $webSiteChildren
    'microsoft.web/staticsites'                        = @('customDomains', 'basicAuth', 'linkedBackends', 'userProvidedFunctionApps', 'privateEndpointConnections')
    'microsoft.web/hostingenvironments'                = @('configurations/networking')
    'microsoft.documentdb/databaseaccounts'            = @('sqlRoleDefinitions', 'sqlRoleAssignments', 'mongodbRoleDefinitions', 'mongodbUserDefinitions', 'privateEndpointConnections', $threatProtectionPath)
    'microsoft.containerservice/managedclusters'       = @('agentPools', 'trustedAccessRoleBindings', 'maintenanceConfigurations', 'privateEndpointConnections', 'upgradeProfiles/default') + $kubernetesConfigPaths
    'microsoft.kubernetes/connectedclusters'           = $kubernetesConfigPaths
    'microsoft.containerregistry/registries'           = @('scopeMaps', 'tokens', 'webhooks', 'replications', 'credentialSets', 'cacheRules', 'connectedRegistries', 'tasks', 'privateEndpointConnections')
    'microsoft.servicebus/namespaces'                  = $serviceBusLikeChildren + @('queues', 'topics', 'queues/*/authorizationRules', 'topics/*/authorizationRules')
    'microsoft.eventhub/namespaces'                    = $serviceBusLikeChildren + @('eventhubs', 'eventhubs/*/authorizationRules', 'applicationGroups')
    'microsoft.relay/namespaces'                       = @('authorizationRules', 'networkRuleSets/default', 'privateEndpointConnections', 'hybridConnections', 'hybridConnections/*/authorizationRules', 'wcfRelays', 'wcfRelays/*/authorizationRules')
    'microsoft.notificationhubs/namespaces'            = @('authorizationRules', 'notificationHubs', 'notificationHubs/*/authorizationRules')
    'microsoft.eventgrid/topics'                       = @('eventSubscriptions', 'privateEndpointConnections')
    'microsoft.eventgrid/systemtopics'                 = @('eventSubscriptions')
    'microsoft.eventgrid/domains'                      = @('topics', 'topics/*/eventSubscriptions', 'privateEndpointConnections')
    'microsoft.eventgrid/namespaces'                   = @('topics', 'topics/*/eventSubscriptions', 'clients', 'clientGroups', 'permissionBindings', 'topicSpaces', 'caCertificates', 'privateEndpointConnections')
    'microsoft.automation/automationaccounts'          = @(
        'runbooks', 'credentials', 'variables', 'connections', 'certificates', 'hybridRunbookWorkerGroups', 'hybridRunbookWorkerGroups/*/hybridRunbookWorkers',
        'webhooks', 'schedules', 'jobSchedules', 'sourceControls', 'privateEndpointConnections'
    )
    'microsoft.logic/workflows'                        = @('triggers')
    'microsoft.apimanagement/service'                  = @(
        'apis', 'apis/*/policies', 'products', 'products/*/policies', 'policies', 'subscriptions', 'namedValues', 'backends', 'identityProviders',
        'authorizationServers', 'openidConnectProviders', 'certificates', 'portalsettings', 'tenant/access', 'gateways', 'loggers', 'authorizationProviders', 'privateEndpointConnections'
    )
    'microsoft.cognitiveservices/accounts'             = @('deployments', 'raiPolicies', 'projects', 'connections', 'defenderForAISettings', 'privateEndpointConnections')
    'microsoft.machinelearningservices/workspaces'     = @('computes', 'connections', 'datastores', 'outboundRules', 'onlineEndpoints', 'serverlessEndpoints', 'privateEndpointConnections')
    'microsoft.search/searchservices'                  = @('sharedPrivateLinkResources', 'privateEndpointConnections')
    'microsoft.cache/redis'                            = @('firewallRules', 'accessPolicies', 'accessPolicyAssignments', 'linkedServers', 'privateEndpointConnections')
    'microsoft.cache/redisenterprise'                  = @('databases', 'privateEndpointConnections')
    'microsoft.dbforpostgresql/flexibleservers'        = $flexibleServerChildren
    'microsoft.dbformysql/flexibleservers'             = $flexibleServerChildren
    'microsoft.dbforpostgresql/servers'                = $singleServerChildren
    'microsoft.dbformysql/servers'                     = $singleServerChildren
    'microsoft.compute/virtualmachines'                = @('instanceView', 'extensions')
    'microsoft.hybridcompute/machines'                 = @('extensions')
    'microsoft.compute/virtualmachinescalesets'        = @('extensions', 'virtualMachines')
    'microsoft.network/firewallpolicies'               = @('ruleCollectionGroups')
    'microsoft.network/dnszones'                       = @('recordsets')
    'microsoft.network/privatednszones'                = @('virtualNetworkLinks', 'ALL')
    'microsoft.network/expressroutecircuits'           = @('authorizations', 'peerings')
    'microsoft.network/virtualhubs'                    = @('hubVirtualNetworkConnections', 'routingIntent', 'hubRouteTables')
    'microsoft.network/networkmanagers'                = @('networkGroups', 'connectivityConfigurations', 'securityAdminConfigurations', 'securityAdminConfigurations/*/ruleCollections', 'securityAdminConfigurations/*/ruleCollections/*/rules')
    'microsoft.network/networksecurityperimeters'      = @('profiles', 'profiles/*/accessRules', 'resourceAssociations')
    'microsoft.network/networkwatchers'                = @('flowLogs')
    'microsoft.cdn/profiles'                           = @(
        'afdEndpoints', 'afdEndpoints/*/routes', 'customDomains', 'originGroups', 'originGroups/*/origins', 'securityPolicies', 'secrets', 'ruleSets',
        'endpoints', 'endpoints/*/customDomains', 'endpoints/*/origins'
    )
    'microsoft.recoveryservices/vaults'                = @(
        'backupconfig/vaultconfig@2023-04-01', 'backupstorageconfig/vaultstorageconfig@2023-04-01', 'backupEncryptionConfigs/backupResourceEncryptionConfig@2023-04-01',
        'backupPolicies@2023-04-01', 'backupProtectedItems@2023-04-01', 'backupResourceGuardProxies@2023-04-01', 'replicationProtectedItems@2025-01-01', 'privateEndpointConnections'
    )
    'microsoft.dataprotection/backupvaults'            = @('backupPolicies', 'backupInstances', 'backupResourceGuardProxies')
    'microsoft.operationalinsights/workspaces'         = @(
        'dataExports', 'linkedServices', 'linkedStorageAccounts', 'tables',
        'providers/Microsoft.SecurityInsights/onboardingStates@2024-03-01', 'providers/Microsoft.SecurityInsights/dataConnectors@2024-03-01',
        'providers/Microsoft.SecurityInsights/alertRules@2024-03-01', 'providers/Microsoft.SecurityInsights/automationRules@2024-03-01'
    )
    'microsoft.insights/components'                    = @('ApiKeys@2015-05-01')
    'microsoft.datafactory/factories'                  = @('linkedservices', 'integrationRuntimes', 'managedVirtualNetworks', 'managedVirtualNetworks/*/managedPrivateEndpoints', 'credentials', 'pipelines', 'triggers', 'privateEndPointConnections')
    'microsoft.synapse/workspaces'                     = @(
        'firewallRules', 'administrators/activeDirectory', 'sqlAdministrators/activeDirectory', 'azureADOnlyAuthentications', 'managedIdentitySqlControlSettings/default',
        'integrationRuntimes', 'securityAlertPolicies', 'vulnerabilityAssessments', 'auditingSettings', 'extendedAuditingSettings', 'encryptionProtector', 'keys', 'privateEndpointConnections'
    )
    'microsoft.databricks/workspaces'                  = @('virtualNetworkPeerings', 'privateEndpointConnections')
    'microsoft.kusto/clusters'                         = @('principalAssignments', 'databases', 'databases/*/principalAssignments', 'managedPrivateEndpoints', 'privateEndpointConnections')
    'microsoft.managedidentity/userassignedidentities' = @('federatedIdentityCredentials')
    'microsoft.signalrservice/signalr'                 = $signalRChildren
    'microsoft.signalrservice/webpubsub'               = $signalRChildren
    'microsoft.app/containerapps'                      = @('authConfigs')
    'microsoft.app/managedenvironments'                = @('daprComponents', 'certificates', 'managedCertificates')
    'microsoft.batch/batchaccounts'                    = @('pools', 'privateEndpointConnections')
    'microsoft.devices/iothubs'                        = @('certificates', 'privateEndpointConnections')
    'microsoft.devices/provisioningservices'           = @('certificates')
    'microsoft.appconfiguration/configurationstores'   = @('replicas', 'privateEndpointConnections')
    'microsoft.desktopvirtualization/hostpools'        = @('sessionHosts', 'privateEndpointConnections')
    'microsoft.desktopvirtualization/applicationgroups' = @('applications')
}

#non JSON content per resource type (source code), stored as text in the resource file
$textContentMap = @{
    'microsoft.automation/automationaccounts/runbooks' = @('content')
}

#extra query parameters on the full GET of a type; userData is only returned when explicitly expanded
$resourceExpandMap = @{
    'microsoft.compute/virtualmachines'         = '$expand=userData'
    'microsoft.compute/virtualmachinescalesets' = '$expand=userData'
}

#child resource types that also support diagnostic settings (all top level types are tried)
$diagnosticSettingsChildTypes = @(
    'microsoft.sql/servers/databases', 'microsoft.sql/managedinstances/databases', 'microsoft.web/sites/slots',
    'microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces/bigdatapools'
)

#Azure Resource Graph tables, unknown tables are skipped
$resourceGraphTables = @(
    'resources', 'resourcecontainers', 'authorizationresources', 'securityresources', 'policyresources', 'advisorresources', 'healthresources',
    'patchassessmentresources', 'patchinstallationresources', 'guestconfigurationresources', 'recoveryservicesresources', 'networkresources',
    'appserviceresources', 'kubernetesconfigurationresources', 'desktopvirtualizationresources', 'extensibilityresources', 'insightsresources',
    'maintenanceresources', 'iotsecurityresources', 'servicehealthresources', 'computeresources', 'dnsresources',
    'resourcechanges', 'resourcecontainerchanges', 'healthresourcechanges'
)

#endregion

#region shared helpers
#These also run in the parallel workers and read these variables from the caller's scope:
#$cloudEndpoints, $RequestFailures, $CompactJson, $apiVersions, $childResourceMap, $resourceExpandMap, $textContentMap, $diagnosticSettingsChildTypes,
#$resourceGroupEndpoints, $coreApiVersions and a Get-AccessToken function.

function Write-Log {
    param([string]$Message, [switch]$Warning)
    $line = "$([DateTime]::UtcNow.ToString('HH:mm:ss')) $Message"
    if ($Warning) { Write-Warning $line } else { Write-Host $line }
}

function ConvertTo-JsonElement {
    #parses JSON text into a standalone JsonElement; values (dates etc) stay exactly as received
    param([Parameter(Mandatory = $true)][string]$Json)
    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try { return $document.RootElement.Clone() } finally { $document.Dispose() }
}

function Get-JsonProperty {
    #returns a single property of a JsonElement (case insensitive) as string/number/bool, or JsonElement for objects and arrays
    param($Element, [Parameter(Mandatory = $true)][string]$Name)
    if ($Element -isnot [System.Text.Json.JsonElement] -or $Element.ValueKind -ne 'Object') { return $null }
    $value = [System.Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$value)) {
        $found = $false
        foreach ($property in $Element.EnumerateObject()) {
            if ($property.Name -eq $Name) { $value = $property.Value; $found = $true; break }
        }
        if (-not $found) { return $null }
    }
    switch ($value.ValueKind) {
        'String' { return $value.GetString() }
        'Number' { return $value.GetDouble() }
        'True' { return $true }
        'False' { return $false }
        'Object' { return $value }
        'Array' { return $value }
        default { return $null }
    }
}

function Get-JsonProp {
    #Get-JsonProperty for a dotted path, e.g. 'properties.principalId'
    param($Element, [Parameter(Mandatory = $true)][string]$Path)
    $current = $Element
    foreach ($segment in $Path.Split('.')) {
        $current = Get-JsonProperty -Element $current -Name $segment
        if ($null -eq $current) { return $null }
    }
    return $current
}

function Get-JsonArrayItems {
    #returns the items of a JSON array element as a list (empty when not an array)
    param($Element)
    $items = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
    if ($Element -is [System.Text.Json.JsonElement] -and $Element.ValueKind -eq 'Array') {
        foreach ($item in $Element.EnumerateArray()) { $items.Add($item) }
    }
    return , $items
}

function Write-JsonValue {
    #serializes PowerShell values, JsonElements are written unchanged
    param([Parameter(Mandatory = $true)][System.Text.Json.Utf8JsonWriter]$Writer, $Value)
    if ($null -eq $Value) { $Writer.WriteNullValue(); return }
    if ($Value -is [System.Text.Json.JsonElement]) { $Value.WriteTo($Writer); return }
    if ($Value -is [string] -or $Value -is [guid] -or $Value -is [enum]) { $Writer.WriteStringValue([string]$Value); return }
    if ($Value -is [bool] -or $Value -is [switch]) { $Writer.WriteBooleanValue([bool]$Value); return }
    if ($Value -is [datetime]) { $Writer.WriteStringValue($Value.ToUniversalTime().ToString('o')); return }
    if ($Value -is [int] -or $Value -is [long]) { $Writer.WriteNumberValue([long]$Value); return }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { $Writer.WriteNumberValue([double]$Value); return }
    if ($Value -is [System.Collections.IDictionary]) {
        #GetEnumerator, not .Keys: PowerShell resolves .Keys to an entry named 'keys' when one exists
        $Writer.WriteStartObject()
        foreach ($entry in $Value.GetEnumerator()) {
            $Writer.WritePropertyName([string]$entry.Key)
            Write-JsonValue -Writer $Writer -Value $entry.Value
        }
        $Writer.WriteEndObject()
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $Writer.WriteStartObject()
        foreach ($property in $Value.PSObject.Properties) {
            $Writer.WritePropertyName($property.Name)
            Write-JsonValue -Writer $Writer -Value $property.Value
        }
        $Writer.WriteEndObject()
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $Writer.WriteStartArray()
        foreach ($item in $Value) { Write-JsonValue -Writer $Writer -Value $item }
        $Writer.WriteEndArray()
        return
    }
    $Writer.WriteStringValue($Value.ToString())
}

function New-JsonWriter {
    #opens a UTF-8 JSON writer on a new file, close with Close-JsonWriter
    param([Parameter(Mandatory = $true)][string]$Path, [bool]$Compact = [bool]$CompactJson)
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($directory)) { $null = [System.IO.Directory]::CreateDirectory($directory) }
    $options = [System.Text.Json.JsonWriterOptions]@{ Indented = -not $Compact; Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping }
    $stream = [System.IO.File]::Create($Path)
    return [pscustomobject]@{ Stream = $stream; Writer = [System.Text.Json.Utf8JsonWriter]::new($stream, $options) }
}

function Close-JsonWriter {
    param([Parameter(Mandatory = $true)]$Handle)
    try { $Handle.Writer.Flush(); $Handle.Writer.Dispose() } finally { $Handle.Stream.Dispose() }
}

function Write-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path, $Value)
    $handle = New-JsonWriter -Path $Path
    try { Write-JsonValue -Writer $handle.Writer -Value $Value } finally { Close-JsonWriter -Handle $handle }
}

function Add-RequestFailure {
    param([string]$Uri, [string]$Method, [int]$StatusCode, [string]$ErrorCode, [string]$Message, [string]$Context)
    $category = if ($StatusCode -eq 0) { 'network' }
    elseif ($StatusCode -in 401, 403) { 'accessDenied' }
    elseif ($StatusCode -eq 404) { 'notFound' }
    elseif ($StatusCode -eq 429) { 'throttled' }
    elseif ($StatusCode -ge 500) { 'serverError' }
    elseif ($StatusCode -ge 400) { 'badRequest' }
    else { 'other' }
    if ($Message -and $Message.Length -gt 2000) { $Message = $Message.Substring(0, 2000) }
    $RequestFailures.Enqueue([ordered]@{
            time       = [DateTime]::UtcNow.ToString('o')
            category   = $category
            statusCode = $StatusCode
            errorCode  = $ErrorCode
            message    = $Message
            method     = $Method
            uri        = $Uri
            context    = $Context
        })
}

function Invoke-AzRest {
    #one REST call with retries on throttling and transient errors; never throws on HTTP errors.
    #Failures are added to $RequestFailures unless their status is in -ExpectedStatus.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('Arm', 'Graph')][string]$Resource = 'Arm',
        [string]$Method = 'GET',
        [string]$Body,
        [string]$Context,
        [int[]]$ExpectedStatus = @(),
        [int]$MaxTransientRetries = 5
    )
    if ($Uri -notmatch '^https?://') { $Uri = $cloudEndpoints[$Resource] + $Uri }
    $attempt = 0
    while ($true) {
        $attempt++
        $statusCode = 0
        $content = $null
        $retryAfter = $null
        $request = @{
            Uri                = $Uri
            Method             = $Method
            Headers            = @{ Authorization = "Bearer $(Get-AccessToken -Resource $Resource)" }
            SkipHttpErrorCheck = $true
            TimeoutSec         = 180
        }
        if ($Method -ne 'GET') {
            $request.ContentType = 'application/json; charset=utf-8'
            $request.Body = [string]$Body
        }
        try {
            $response = Invoke-WebRequest @request
            $statusCode = [int]$response.StatusCode
            $content = $response.Content
            if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
            if ($response.Headers.ContainsKey('Retry-After')) { $retryAfter = [string]($response.Headers['Retry-After'] | Select-Object -First 1) }
        } catch {
            $content = $_.Exception.Message
        }
        #throttling is always retried, timeouts and server errors up to -MaxTransientRetries times. A server error that
        #denies access is final (Resource Graph backed endpoints such as Microsoft.Security/apiCollections answer 502
        #with AccessDenied details)
        $transient = ($statusCode -in 0, 408 -or $statusCode -ge 500) -and [string]$content -notmatch '"code"\s*:\s*"(AccessDenied|AuthorizationFailed|LinkedAuthorizationFailed|Forbidden)"'
        if (($statusCode -eq 429 -and $attempt -le 6) -or ($transient -and $attempt -le $MaxTransientRetries)) {
            $delay = [math]::Pow(2, $attempt)
            $seconds = 0
            if ($retryAfter -and [int]::TryParse($retryAfter, [ref]$seconds)) { $delay = [math]::Max(1, [math]::Min(120, $seconds)) }
            Start-Sleep -Seconds $delay
            continue
        }
        break
    }

    $json = $null
    if ($content -and $content.TrimStart() -match '^[\{\[]') {
        try { $json = ConvertTo-JsonElement -Json $content } catch { $json = $null }
    }
    $result = [pscustomobject]@{ Uri = $Uri; StatusCode = $statusCode; Json = $json; Text = if ($null -eq $json) { [string]$content } else { $null }; ErrorCode = $null; ErrorMessage = $null }
    if ($statusCode -lt 200 -or $statusCode -ge 300) {
        $result.ErrorCode = Get-JsonProp -Element $json -Path 'error.code'
        $result.ErrorMessage = Get-JsonProp -Element $json -Path 'error.message'
        foreach ($detail in (Get-JsonArrayItems -Element (Get-JsonProp -Element $json -Path 'error.details'))) {
            $result.ErrorMessage += " | $(Get-JsonProperty -Element $detail -Name 'code'): $(Get-JsonProperty -Element $detail -Name 'message')"
        }
        if (-not $result.ErrorMessage) { $result.ErrorMessage = [string]$content }
        if ($statusCode -notin $ExpectedStatus) {
            Add-RequestFailure -Uri $Uri -Method $Method -StatusCode $statusCode -ErrorCode $result.ErrorCode -Message $result.ErrorMessage -Context $Context
        }
    }
    return $result
}

function Invoke-AzPaged {
    #follows nextLink/@odata.nextLink paging. Items are streamed to -Writer when given, otherwise collected in .Items.
    #A non collection response is returned in .Single
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('Arm', 'Graph')][string]$Resource = 'Arm',
        [string]$Method = 'GET',
        [string]$Body,
        [string]$Context,
        [int[]]$ExpectedStatus = @(),
        [int]$MaxTransientRetries = 5,
        [System.Text.Json.Utf8JsonWriter]$Writer,
        #skips items whose -IdProperty value is already in -SeenIds
        [System.Collections.Generic.HashSet[string]]$SeenIds,
        [string]$IdProperty = 'id'
    )
    $result = [pscustomobject]@{
        StatusCode   = 0
        ErrorCode    = $null
        IsCollection = $false
        Items        = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
        Single       = $null
        Count        = 0
        Duplicates   = 0
        Complete     = $true
    }
    $next = $Uri
    $page = 0
    while ($next) {
        $page++
        $response = Invoke-AzRest -Uri $next -Resource $Resource -Method $Method -Body $Body -Context $Context -ExpectedStatus $ExpectedStatus -MaxTransientRetries $MaxTransientRetries
        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            if ($page -eq 1) {
                $result.StatusCode = $response.StatusCode
                $result.ErrorCode = $response.ErrorCode
            } else {
                $result.Complete = $false
            }
            break
        }
        if ($page -eq 1) { $result.StatusCode = $response.StatusCode }
        $value = Get-JsonProperty -Element $response.Json -Name 'value'
        if ($value -is [System.Text.Json.JsonElement] -and $value.ValueKind -eq 'Array') {
            $result.IsCollection = $true
            foreach ($item in $value.EnumerateArray()) {
                if ($null -ne $SeenIds) {
                    $itemId = Get-JsonProperty -Element $item -Name $IdProperty
                    if ($itemId -and -not $SeenIds.Add($itemId)) { $result.Duplicates++; continue }
                }
                if ($Writer) { $item.WriteTo($Writer) } else { $result.Items.Add($item) }
                $result.Count++
            }
        } else {
            if ($page -eq 1) { $result.Single = $response.Json }
            break
        }
        $next = $null
        foreach ($linkName in 'nextLink', '@odata.nextLink', 'odata.nextLink') {
            $link = Get-JsonProperty -Element $response.Json -Name $linkName
            if ($link -is [string] -and $link) { $next = $link; break }
        }
    }
    return $result
}

function Test-Success {
    param($Result)
    return ($Result.StatusCode -ge 200 -and $Result.StatusCode -lt 300)
}

function Find-PrincipalIds {
    #adds object ids referenced as principalId/objectId/sid/adminGroupObjectIDs in the given JSON elements to -Target
    param($Elements, [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Target)
    $propertyPattern = '"(?:principalId|principalIds|objectId|sid|adminGroupObjectIDs)"\s*:\s*(\[[^\]]*\]|"[^"]*")'
    $guidPattern = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    foreach ($element in $Elements) {
        if ($element -isnot [System.Text.Json.JsonElement]) { continue }
        foreach ($match in [regex]::Matches($element.GetRawText(), $propertyPattern, 'IgnoreCase')) {
            foreach ($guid in [regex]::Matches($match.Groups[1].Value, $guidPattern)) {
                if ($guid.Value -ne '00000000-0000-0000-0000-000000000000') { $null = $Target.Add($guid.Value.ToLowerInvariant()) }
            }
        }
    }
}

#endregion

#region per resource collection (runs in parallel workers)

function Get-ChildTypeSegments {
    #'blobServices/default/containers' -> 'blobServices/containers'
    param([string]$Path)
    $segments = $Path.Split('/')
    return ((0..($segments.Count - 1) | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { $segments[$_] }) -join '/')
}

function Get-ChildResource {
    #resolves a child path below a resource; returns a JsonElement, a list of JsonElements, or $null on failure
    param(
        [Parameter(Mandatory = $true)][string]$ParentId,
        [Parameter(Mandatory = $true)][string]$ParentType,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ApiVersion,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable]$Cache,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Failures
    )
    $starIndex = $Path.IndexOf('/*/')
    if ($starIndex -gt 0) {
        $prefix = $Path.Substring(0, $starIndex)
        $rest = $Path.Substring($starIndex + 3)
        $parents = Get-ChildResource -ParentId $ParentId -ParentType $ParentType -Path $prefix -ApiVersion $ApiVersion -Cache $Cache -Failures $Failures
        $combined = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
        if ($null -eq $parents) { return , $combined }
        $childParentType = "$ParentType/$(Get-ChildTypeSegments -Path $prefix)"
        foreach ($parent in $parents) {
            $parentItemId = Get-JsonProperty -Element $parent -Name 'id'
            if (-not $parentItemId) { continue }
            $children = Get-ChildResource -ParentId $parentItemId -ParentType $childParentType -Path $rest -ApiVersion $ApiVersion -Cache $Cache -Failures $Failures
            if ($children -is [System.Text.Json.JsonElement]) { $combined.Add($children) }
            elseif ($null -ne $children) { $combined.AddRange($children) }
        }
        return , $combined
    }

    $cacheKey = "$ParentId/$Path".ToLowerInvariant()
    if ($Cache.ContainsKey($cacheKey)) { return , $Cache[$cacheKey] }
    if (-not $ApiVersion) {
        $candidates = $apiVersions["$ParentType/$(Get-ChildTypeSegments -Path $Path)".ToLowerInvariant()]
        if (-not $candidates) { $candidates = $apiVersions[$ParentType.ToLowerInvariant()] }
        $ApiVersion = $candidates | Select-Object -First 1
    }
    $separator = if ($Path.Contains('?')) { '&' } else { '?' }
    $result = Invoke-AzPaged -Uri "$ParentId/$Path$($separator)api-version=$ApiVersion" -Context $ParentId -ExpectedStatus 400, 404, 405, 409 -MaxTransientRetries 1
    $value = $null
    if (Test-Success $result) {
        #assigned per branch: 'if' as an expression would unroll the list
        if ($result.IsCollection) { $value = $result.Items } else { $value = $result.Single }
    } else {
        $Failures.Add([ordered]@{ path = "$ParentId/$Path"; apiVersion = $ApiVersion; statusCode = $result.StatusCode; errorCode = $result.ErrorCode })
    }
    $Cache[$cacheKey] = $value
    return , $value
}

function Export-ResourceDetail {
    #full GET, diagnostic settings and mapped child resources of one resource, written to $Item.File
    param([Parameter(Mandatory = $true)]$Item)
    $typeKey = $Item.Type.ToLowerInvariant()
    $failures = [System.Collections.Generic.List[object]]::new()
    $record = [ordered]@{
        id                 = $Item.Id
        type               = $Item.Type
        apiVersion         = $null
        collectedAt        = [DateTime]::UtcNow.ToString('o')
        resource           = $null
        diagnosticSettings = $null
        children           = [ordered]@{}
        textContent        = [ordered]@{}
        failures           = $failures
    }

    $candidates = @($apiVersions[$typeKey])
    if (-not $candidates -or -not $candidates[0]) {
        $failures.Add([ordered]@{ path = $Item.Id; apiVersion = $null; statusCode = 0; errorCode = 'NoApiVersionForType' })
    }
    $expand = $resourceExpandMap[$typeKey]
    foreach ($apiVersion in $candidates) {
        if (-not $apiVersion) { continue }
        $query = "api-version=$apiVersion$(if ($expand) { "&$expand" })"
        $response = Invoke-AzRest -Uri "$($Item.Id)?$query" -Context $Item.Id
        if (Test-Success $response) {
            $record.resource = $response.Json
            $record.apiVersion = $apiVersion
            break
        }
        $failures.Add([ordered]@{ path = $Item.Id; apiVersion = $apiVersion; statusCode = $response.StatusCode; errorCode = $response.ErrorCode })
        if ($response.StatusCode -ne 400) { break }
    }

    if ($null -ne $record.resource) {
        if ($Item.Type.Split('/').Count -eq 2 -or $diagnosticSettingsChildTypes -contains $typeKey) {
            $diagnostics = Invoke-AzPaged -Uri "$($Item.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=$($coreApiVersions.diagnosticSettings)" -Context $Item.Id -ExpectedStatus 400, 404, 405, 409 -MaxTransientRetries 1
            if (Test-Success $diagnostics) { $record.diagnosticSettings = $diagnostics.Items }
            else { $failures.Add([ordered]@{ path = "$($Item.Id)/providers/Microsoft.Insights/diagnosticSettings"; apiVersion = $coreApiVersions.diagnosticSettings; statusCode = $diagnostics.StatusCode; errorCode = $diagnostics.ErrorCode }) }
        }
        $cache = @{}
        foreach ($entry in $childResourceMap[$typeKey]) {
            $path, $pinnedVersion = $entry.Split('@', 2)
            #the master database does not support data masking and answers with a 500
            if ($typeKey -eq 'microsoft.sql/servers/databases' -and $Item.Id -match '/databases/master$' -and $path -like 'dataMaskingPolicies*') { continue }
            $record.children[$path] = Get-ChildResource -ParentId $Item.Id -ParentType $Item.Type -Path $path -ApiVersion $pinnedVersion -Cache $cache -Failures $failures
        }
        foreach ($path in $textContentMap[$typeKey]) {
            $response = Invoke-AzRest -Uri "$($Item.Id)/$($path)?api-version=$($record.apiVersion)" -Context $Item.Id -ExpectedStatus 400, 404 -MaxTransientRetries 1
            if (Test-Success $response) {
                if ($null -ne $response.Json) { $record.textContent[$path] = $response.Json.GetRawText() } else { $record.textContent[$path] = $response.Text }
            } else {
                $failures.Add([ordered]@{ path = "$($Item.Id)/$path"; apiVersion = $record.apiVersion; statusCode = $response.StatusCode; errorCode = $response.ErrorCode })
            }
        }
    }

    Write-JsonFile -Path $Item.FullPath -Value $record

    $principalIds = [System.Collections.Generic.HashSet[string]]::new()
    Find-PrincipalIds -Elements @($record.resource) -Target $principalIds
    foreach ($child in $record.children.get_Values()) { Find-PrincipalIds -Elements $child -Target $principalIds }
    return [pscustomobject]@{
        Id           = $Item.Id
        Type         = $Item.Type
        File         = $Item.File
        ApiVersion   = $record.apiVersion
        Status       = if ($null -ne $record.resource) { 'ok' } else { 'failed' }
        FailureCount = $failures.Count
        PrincipalIds = [string[]]@($principalIds)
    }
}

function Export-ResourceGroupDetail {
    #deployments, deployment stacks and Lighthouse assignments of one resource group, written to $Item.File
    param([Parameter(Mandatory = $true)]$Item)
    $failures = [System.Collections.Generic.List[object]]::new()
    $record = [ordered]@{ id = $Item.Id; collectedAt = [DateTime]::UtcNow.ToString('o') }
    foreach ($endpoint in $resourceGroupEndpoints) {
        $name, $path, $apiVersion = $endpoint
        $separator = if ($path.Contains('?')) { '&' } else { '?' }
        $result = Invoke-AzPaged -Uri "$($Item.Id)/$path$($separator)api-version=$apiVersion" -Context $Item.Id -ExpectedStatus 400, 404
        if (Test-Success $result) { $record[$name] = $result.Items }
        else {
            $record[$name] = $null
            $failures.Add([ordered]@{ path = "$($Item.Id)/$path"; apiVersion = $apiVersion; statusCode = $result.StatusCode; errorCode = $result.ErrorCode })
        }
    }
    $record.failures = $failures
    Write-JsonFile -Path $Item.FullPath -Value $record
    return [pscustomobject]@{ Id = $Item.Id; Type = 'resourceGroup'; File = $Item.File; ApiVersion = $null; Status = 'ok'; FailureCount = $failures.Count; PrincipalIds = [string[]]@() }
}

#endregion

#region authentication

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TokenClaims {
    param([Parameter(Mandatory = $true)][string]$Token)
    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

function Get-SigningCertificate {
    if ($authMethod -eq 'CertificateFile') {
        $resolvedPath = (Resolve-Path -Path $CertificatePath).Path
        if ($resolvedPath -match '\.pem$') {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($resolvedPath)
        } else {
            $password = if ($CertificatePassword) { $CertificatePassword } else { [securestring]::new() }
            $flags = if ($IsMacOS) { 'DefaultKeySet' } else { 'EphemeralKeySet' }
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedPath, $password, $flags)
        }
    } else {
        $thumbprint = $CertificateThumbprint -replace '[^0-9a-fA-F]', ''
        $certificate = $null
        foreach ($location in 'CurrentUser', 'LocalMachine') {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
            try {
                $store.Open('ReadOnly')
                $found = $store.Certificates.Find('FindByThumbprint', $thumbprint, $false)
                if ($found.Count -gt 0) { $certificate = $found[0]; break }
            } catch {
                #LocalMachine store is not available on every platform
            } finally {
                $store.Close()
            }
        }
        if (-not $certificate) { throw "Certificate $thumbprint not found in the CurrentUser or LocalMachine My store" }
    }
    if (-not $certificate.HasPrivateKey) { throw "Certificate $($certificate.Thumbprint) has no private key" }
    return $certificate
}

function New-ClientAssertion {
    #signed JWT for certificate based client credentials
    $now = [DateTimeOffset]::UtcNow
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url -Bytes $script:signingCertificate.GetCertHash()) } | ConvertTo-Json -Compress
    $claims = @{
        aud = "$($cloudEndpoints.Login)/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($claims)))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($script:signingCertificate)
    $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return "$unsigned.$(ConvertTo-Base64Url -Bytes $signature)"
}

function Get-ManagedIdentityToken {
    param([Parameter(Mandatory = $true)][string]$Audience)
    $resourceParameter = "resource=$([uri]::EscapeDataString($Audience))"
    $clientParameter = if ($ClientId) { "&client_id=$ClientId" } else { '' }
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
        #App Service, Functions, Automation, Container Apps
        return Invoke-RestMethod -Uri "$($env:IDENTITY_ENDPOINT)?$resourceParameter&api-version=2019-08-01$clientParameter" -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; Metadata = 'true' }
    }
    if ($env:IDENTITY_ENDPOINT -and $env:IMDS_ENDPOINT) {
        #Azure Arc: the challenge response names a key file readable by administrators only
        $uri = "$($env:IDENTITY_ENDPOINT)?$resourceParameter&api-version=2020-06-01"
        $challenge = Invoke-WebRequest -Uri $uri -Headers @{ Metadata = 'true' } -SkipHttpErrorCheck
        $keyPath = ([string]($challenge.Headers['WWW-Authenticate'] | Select-Object -First 1)) -replace '^Basic realm=', ''
        $key = (Get-Content -Path $keyPath -Raw).Trim()
        return Invoke-RestMethod -Uri $uri -Headers @{ Metadata = 'true'; Authorization = "Basic $key" }
    }
    #VM / VMSS instance metadata service
    return Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&$resourceParameter$clientParameter" -Headers @{ Metadata = 'true' }
}

$script:tokenCache = @{}
function Get-AccessToken {
    #cached token for ARM or Graph, renewed when it expires within -MinValidMinutes
    param([ValidateSet('Arm', 'Graph')][string]$Resource = 'Arm', [int]$MinValidMinutes = 5)
    $cached = $script:tokenCache[$Resource]
    if ($cached -and $cached.ExpiresOn -gt [DateTime]::UtcNow.AddMinutes($MinValidMinutes)) { return $cached.Token }
    $audience = $cloudEndpoints[$Resource]
    try {
        if ($authMethod -eq 'ManagedIdentity') {
            $response = Get-ManagedIdentityToken -Audience "$audience/"
        } else {
            $body = @{ client_id = $ClientId; scope = "$audience/.default"; grant_type = 'client_credentials' }
            if ($authMethod -eq 'ClientSecret') {
                $body.client_secret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
            } else {
                $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                $body.client_assertion = New-ClientAssertion
            }
            $response = Invoke-RestMethod -Method POST -Uri "$($cloudEndpoints.Login)/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
        }
    } catch {
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Failed to acquire a $Resource token: $detail"
    }
    $expiresOn = if ($response.expires_in) { [DateTime]::UtcNow.AddSeconds([int]$response.expires_in) }
    elseif ($response.expires_on) { [DateTimeOffset]::FromUnixTimeSeconds([long]$response.expires_on).UtcDateTime }
    else { [DateTime]::UtcNow.AddMinutes(30) }
    $script:tokenCache[$Resource] = @{ Token = $response.access_token; ExpiresOn = $expiresOn }
    return $response.access_token
}

#endregion

#region subscription level, Resource Graph and Graph exports (main thread)

function Export-Endpoint {
    #GETs (or POSTs) a collection or object and writes it to $Path; returns a section status
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = 'GET',
        [ValidateSet('Arm', 'Graph')][string]$Resource = 'Arm',
        [System.Collections.Generic.HashSet[string]]$PrincipalTarget
    )
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-AzPaged -Uri $Uri -Method $Method -Resource $Resource -Context $Path
    if (-not (Test-Success $result)) {
        return [ordered]@{ status = 'failed'; statusCode = $result.StatusCode; errorCode = $result.ErrorCode; seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1) }
    }
    #assigned per branch: 'if' as an expression would unroll the list
    if ($result.IsCollection) { $value = $result.Items } elseif ($null -ne $result.Single) { $value = $result.Single } else { $value = [object[]]@() }
    Write-JsonFile -Path $Path -Value $value
    if ($PrincipalTarget) { Find-PrincipalIds -Elements $value -Target $PrincipalTarget }
    return [ordered]@{ status = if ($result.Complete) { 'ok' } else { 'partial' }; count = if ($result.IsCollection) { $result.Count } else { 1 }; seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1) }
}

function Export-ResourceGraphTable {
    #streams all rows of a Resource Graph table for the subscription to a JSON array file; returns a section status
    param([Parameter(Mandatory = $true)][string]$Table, [Parameter(Mandatory = $true)][string]$Path)
    $options = [ordered]@{ resultFormat = 'objectArray'; '$top' = 1000 }
    $count = 0
    $status = [ordered]@{ status = 'ok'; count = 0 }
    $handle = New-JsonWriter -Path $Path
    try {
        $handle.Writer.WriteStartArray()
        while ($true) {
            $body = [ordered]@{ subscriptions = @($SubscriptionId); query = $Table; options = $options } | ConvertTo-Json -Depth 5 -Compress
            $response = Invoke-AzRest -Uri "/providers/Microsoft.ResourceGraph/resources?api-version=$($coreApiVersions.resourceGraph)" -Method POST -Body $body -Context "resourceGraph/$Table" -ExpectedStatus 400
            if (-not (Test-Success $response)) {
                $status = [ordered]@{ status = if ($count -gt 0) { 'partial' } else { 'unavailable' }; statusCode = $response.StatusCode; errorCode = $response.ErrorCode; message = $response.ErrorMessage }
                break
            }
            foreach ($row in (Get-JsonArrayItems -Element (Get-JsonProperty -Element $response.Json -Name 'data'))) {
                $row.WriteTo($handle.Writer)
                $count++
            }
            $skipToken = Get-JsonProperty -Element $response.Json -Name '$skipToken'
            if (-not $skipToken) { break }
            $options['$skipToken'] = $skipToken
        }
        $handle.Writer.WriteEndArray()
    } finally {
        Close-JsonWriter -Handle $handle
    }
    $status.count = $count
    if ($status.status -eq 'unavailable') { Remove-Item -Path $Path -Force }
    return $status
}

function Invoke-GraphBatch {
    #runs relative Graph v1.0 GET requests through $batch (20 per call) including paging; returns key -> result
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Requests, [int[]]$ExpectedStatus = @())
    $results = @{}
    $attempts = @{}
    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($key in $Requests.Keys) { $pending.Enqueue($key) }
    while ($pending.Count -gt 0) {
        $batchKeys = [System.Collections.Generic.List[string]]::new()
        while ($pending.Count -gt 0 -and $batchKeys.Count -lt 20) { $batchKeys.Add($pending.Dequeue()) }
        $batchRequests = for ($i = 0; $i -lt $batchKeys.Count; $i++) { [ordered]@{ id = [string]$i; method = 'GET'; url = $Requests[$batchKeys[$i]] } }
        $body = @{ requests = @($batchRequests) } | ConvertTo-Json -Depth 5 -Compress
        $response = Invoke-AzRest -Uri '/v1.0/$batch' -Resource Graph -Method POST -Body $body -Context 'graph batch'
        if (-not (Test-Success $response)) {
            foreach ($key in $batchKeys) { $results[$key] = [pscustomobject]@{ StatusCode = $response.StatusCode; ErrorCode = $response.ErrorCode; Items = $null; Single = $null } }
            continue
        }
        $delay = 0
        foreach ($item in (Get-JsonArrayItems -Element (Get-JsonProperty -Element $response.Json -Name 'responses'))) {
            $key = $batchKeys[[int](Get-JsonProperty -Element $item -Name 'id')]
            $status = [int](Get-JsonProperty -Element $item -Name 'status')
            $itemBody = Get-JsonProperty -Element $item -Name 'body'
            if (($status -eq 429 -or $status -ge 500) -and $attempts[$key] -lt 5) {
                $attempts[$key]++
                $retryAfter = 0
                if (-not [int]::TryParse([string](Get-JsonProp -Element $item -Path 'headers.Retry-After'), [ref]$retryAfter)) { $retryAfter = 5 }
                $delay = [math]::Max($delay, [math]::Min(120, $retryAfter))
                $pending.Enqueue($key)
                continue
            }
            $result = [pscustomobject]@{ StatusCode = $status; ErrorCode = $null; Items = $null; Single = $null }
            if ($status -ge 200 -and $status -lt 300) {
                $value = Get-JsonProperty -Element $itemBody -Name 'value'
                if ($value -is [System.Text.Json.JsonElement] -and $value.ValueKind -eq 'Array') {
                    $result.Items = Get-JsonArrayItems -Element $value
                    $nextLink = Get-JsonProperty -Element $itemBody -Name '@odata.nextLink'
                    if ($nextLink) {
                        $more = Invoke-AzPaged -Uri $nextLink -Resource Graph -Context $Requests[$key]
                        if (Test-Success $more) { $result.Items.AddRange($more.Items) }
                    }
                } else {
                    $result.Single = $itemBody
                }
            } else {
                $result.ErrorCode = Get-JsonProp -Element $itemBody -Path 'error.code'
                if ($status -notin $ExpectedStatus) { Add-RequestFailure -Uri "$($cloudEndpoints.Graph)/v1.0$($Requests[$key])" -Method 'GET' -StatusCode $status -ErrorCode $result.ErrorCode -Message (Get-JsonProp -Element $itemBody -Path 'error.message') -Context 'graph batch item' }
            }
            $results[$key] = $result
        }
        if ($delay -gt 0) { Start-Sleep -Seconds $delay }
    }
    return $results
}

function Get-DirectoryObjectsByIds {
    #resolves object ids of any type through directoryObjects/getByIds
    param([Parameter(Mandatory = $true)][string[]]$Ids)
    $lookup = [pscustomobject]@{ Objects = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new(); Failed = $false }
    for ($i = 0; $i -lt $Ids.Count; $i += 1000) {
        $chunk = $Ids[$i..([math]::Min($i + 999, $Ids.Count - 1))]
        $body = @{ ids = @($chunk) } | ConvertTo-Json -Compress
        $result = Invoke-AzPaged -Uri '/v1.0/directoryObjects/getByIds' -Resource Graph -Method POST -Body $body -Context 'directoryObjects/getByIds'
        if (Test-Success $result) { $lookup.Objects.AddRange($result.Items) } else { $lookup.Failed = $true }
    }
    return $lookup
}

function Export-EntraData {
    #resolves the principals referenced by the Azure data and exports their identity context; returns section statuses
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$PrincipalIds, [Parameter(Mandatory = $true)][string]$Folder)
    $sections = [ordered]@{}
    $directoryObjects = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
    $objectsById = @{}
    $userIds = [System.Collections.Generic.HashSet[string]]::new()
    $groupIds = [System.Collections.Generic.HashSet[string]]::new()
    $servicePrincipalIds = [System.Collections.Generic.HashSet[string]]::new()

    $sections.organization = Export-Endpoint -Uri '/v1.0/organization' -Resource Graph -Path (Join-Path $Folder 'organization.json')

    #adds resolved objects to the type sets
    $addObjects = {
        param($Objects)
        foreach ($object in $Objects) {
            $id = Get-JsonProperty -Element $object -Name 'id'
            if (-not $id -or $objectsById.ContainsKey($id)) { continue }
            $objectsById[$id] = $object
            $directoryObjects.Add($object)
            switch (Get-JsonProperty -Element $object -Name '@odata.type') {
                '#microsoft.graph.user' { $null = $userIds.Add($id) }
                '#microsoft.graph.group' { $null = $groupIds.Add($id) }
                '#microsoft.graph.servicePrincipal' { $null = $servicePrincipalIds.Add($id) }
            }
        }
    }
    $lookupFailed = $false
    if ($PrincipalIds.Count -gt 0) {
        $lookup = Get-DirectoryObjectsByIds -Ids @($PrincipalIds)
        $lookupFailed = $lookup.Failed
        . $addObjects $lookup.Objects
    }

    #groups: transitive members and owners; service principal members and owners are enriched below as well
    Write-Log "Graph: $($groupIds.Count) groups"
    $memberSelect = "`$select=$($graphSelect.member)"
    $groupRequests = [ordered]@{}
    foreach ($id in $groupIds) {
        $groupRequests["members|$id"] = "/groups/$id/transitiveMembers?$memberSelect&`$top=999"
        $groupRequests["owners|$id"] = "/groups/$id/owners?$memberSelect"
    }
    $groupResults = if ($groupRequests.Count) { Invoke-GraphBatch -Requests $groupRequests } else { @{} }
    $groupRecords = [System.Collections.Generic.List[object]]::new()
    $additionalIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($id in @($groupIds)) {
        $members = $groupResults["members|$id"]
        $owners = $groupResults["owners|$id"]
        foreach ($related in @($members.Items) + @($owners.Items)) {
            if ($related -isnot [System.Text.Json.JsonElement]) { continue }
            $relatedId = Get-JsonProperty -Element $related -Name 'id'
            switch (Get-JsonProperty -Element $related -Name '@odata.type') {
                '#microsoft.graph.user' { $null = $userIds.Add($relatedId) }
                '#microsoft.graph.servicePrincipal' { if (-not $objectsById.ContainsKey($relatedId)) { $null = $additionalIds.Add($relatedId) } }
            }
        }
        $groupRecords.Add([ordered]@{
                id                     = $id
                transitiveMembers      = $members.Items
                transitiveMembersError = if ($members.StatusCode -ge 300) { $members.StatusCode } else { $null }
                owners                 = $owners.Items
            })
    }
    Write-JsonFile -Path (Join-Path $Folder 'groups.json') -Value $groupRecords
    $sections.groups = [ordered]@{ status = 'ok'; count = $groupRecords.Count }
    if ($additionalIds.Count -gt 0) {
        $lookup = Get-DirectoryObjectsByIds -Ids @($additionalIds)
        $lookupFailed = $lookupFailed -or $lookup.Failed
        . $addObjects $lookup.Objects
    }

    #unresolved ids are deleted principals (orphaned assignments) or principals from other tenants, unless the lookup failed.
    #Soft deleted ones (30 days) can still be named from the recycle bin
    $unresolved = @($PrincipalIds | Where-Object { -not $objectsById.ContainsKey($_) })
    Write-JsonFile -Path (Join-Path $Folder 'directoryObjects.json') -Value $directoryObjects
    Write-JsonFile -Path (Join-Path $Folder 'unresolvedPrincipalIds.json') -Value $unresolved
    $deletedPrincipals = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
    if ($unresolved.Count -gt 0 -and -not $lookupFailed) {
        $deletedRequests = [ordered]@{}
        foreach ($id in $unresolved) { $deletedRequests[$id] = "/directory/deletedItems/$id" }
        foreach ($result in (Invoke-GraphBatch -Requests $deletedRequests -ExpectedStatus 404).get_Values()) {
            if ($null -ne $result.Single) { $deletedPrincipals.Add($result.Single) }
        }
    }
    Write-JsonFile -Path (Join-Path $Folder 'deletedPrincipals.json') -Value $deletedPrincipals
    $sections.deletedPrincipals = [ordered]@{ status = 'ok'; count = $deletedPrincipals.Count }
    $sections.directoryObjects = [ordered]@{ status = if ($lookupFailed) { 'failed' } else { 'ok' }; count = $directoryObjects.Count; unresolved = $unresolved.Count }

    #users: security relevant properties, sign-in activity when permitted
    Write-Log "Graph: $($userIds.Count) users"
    $userSelect = $graphSelect.user
    $userIdList = @($userIds)
    $signInActivity = $false
    if ($userIdList.Count -gt 0) {
        $probe = Invoke-AzRest -Uri "/v1.0/users/$($userIdList[0])?`$select=id,signInActivity" -Resource Graph -Context 'signInActivity probe' -ExpectedStatus 400, 403, 404
        if (Test-Success $probe) { $signInActivity = $true; $userSelect += ',signInActivity' }
    }
    $userRequests = [ordered]@{}
    for ($i = 0; $i -lt $userIdList.Count; $i += 15) {
        $filter = "id in ('" + ($userIdList[$i..([math]::Min($i + 14, $userIdList.Count - 1))] -join "','") + "')"
        $userRequests["users|$i"] = "/users?`$filter=$([uri]::EscapeDataString($filter))&`$select=$userSelect"
    }
    $users = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
    if ($userRequests.Count) {
        foreach ($result in (Invoke-GraphBatch -Requests $userRequests).Values) { if ($result.Items) { $users.AddRange($result.Items) } }
    }
    Write-JsonFile -Path (Join-Path $Folder 'users.json') -Value $users
    $sections.users = [ordered]@{ status = 'ok'; count = $users.Count; signInActivity = $signInActivity }

    #service principals: API permissions, delegated grants, owners, backing application with credentials and federated credentials
    Write-Log "Graph: $($servicePrincipalIds.Count) service principals"
    $tenant = (Get-TokenClaims -Token (Get-AccessToken -Resource Graph)).tid
    $spRequests = [ordered]@{}
    foreach ($id in $servicePrincipalIds) {
        $spRequests["appRoleAssignments|$id"] = "/servicePrincipals/$id/appRoleAssignments"
        $spRequests["oauth2PermissionGrants|$id"] = "/servicePrincipals/$id/oauth2PermissionGrants"
        $spRequests["owners|$id"] = "/servicePrincipals/$id/owners?`$select=$($graphSelect.owner)"
        $servicePrincipal = $objectsById[$id]
        $appId = Get-JsonProperty -Element $servicePrincipal -Name 'appId'
        if ((Get-JsonProperty -Element $servicePrincipal -Name 'servicePrincipalType') -eq 'Application' -and (Get-JsonProperty -Element $servicePrincipal -Name 'appOwnerOrganizationId') -eq $tenant -and $appId) {
            $spRequests["application|$id"] = "/applications(appId='$appId')"
        }
    }
    $spResults = if ($spRequests.Count) { Invoke-GraphBatch -Requests $spRequests } else { @{} }
    $appRequests = [ordered]@{}
    foreach ($id in $servicePrincipalIds) {
        $application = $spResults["application|$id"].Single
        $applicationObjectId = Get-JsonProperty -Element $application -Name 'id'
        if ($applicationObjectId) {
            $appRequests["owners|$id"] = "/applications/$applicationObjectId/owners?`$select=$($graphSelect.owner)"
            $appRequests["federatedIdentityCredentials|$id"] = "/applications/$applicationObjectId/federatedIdentityCredentials"
        }
    }
    $appResults = if ($appRequests.Count) { Invoke-GraphBatch -Requests $appRequests } else { @{} }
    $apiIds = [System.Collections.Generic.HashSet[string]]::new()
    $spRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $servicePrincipalIds) {
        $appRoleAssignments = $spResults["appRoleAssignments|$id"].Items
        $grants = $spResults["oauth2PermissionGrants|$id"].Items
        foreach ($assignment in @($appRoleAssignments) + @($grants)) {
            $apiId = Get-JsonProperty -Element $assignment -Name 'resourceId'
            if ($apiId) { $null = $apiIds.Add($apiId) }
        }
        $spRecords.Add([ordered]@{
                id                                     = $id
                appRoleAssignments                     = $appRoleAssignments
                oauth2PermissionGrants                 = $grants
                owners                                 = $spResults["owners|$id"].Items
                application                            = $spResults["application|$id"].Single
                applicationOwners                      = $appResults["owners|$id"].Items
                applicationFederatedIdentityCredentials = $appResults["federatedIdentityCredentials|$id"].Items
            })
    }
    Write-JsonFile -Path (Join-Path $Folder 'servicePrincipals.json') -Value $spRecords
    $sections.servicePrincipals = [ordered]@{ status = 'ok'; count = $spRecords.Count }

    #APIs the service principals hold permissions on, to translate app role ids into names
    $apiRequests = [ordered]@{}
    foreach ($apiId in $apiIds) { $apiRequests[$apiId] = "/servicePrincipals/$apiId`?`$select=$($graphSelect.api)" }
    $apis = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
    if ($apiRequests.Count) {
        foreach ($result in (Invoke-GraphBatch -Requests $apiRequests).Values) { if ($null -ne $result.Single) { $apis.Add($result.Single) } }
    }
    Write-JsonFile -Path (Join-Path $Folder 'apiServicePrincipals.json') -Value $apis
    $sections.apiServicePrincipals = [ordered]@{ status = 'ok'; count = $apis.Count }

    #directory roles: tenant wide, relevant because e.g. Global Administrators can elevate to User Access Administrator on all subscriptions
    foreach ($export in $graphDirectoryExports) {
        $name, $uri = $export
        $sections[$name] = Export-Endpoint -Uri $uri -Resource Graph -Path (Join-Path $Folder "$name.json")
    }
    return $sections
}

#endregion

function Get-SafeFileName {
    #file system safe and unique: <sanitized name>_<first 8 hex chars of the id hash>
    param([string]$Name, [Parameter(Mandatory = $true)][string]$Id)
    $safeName = [string]$Name -replace '[^A-Za-z0-9._-]', '_'
    if ($safeName.Length -gt 60) { $safeName = $safeName.Substring(0, 60) }
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Id.ToLowerInvariant()))
    return "$($safeName)_$([Convert]::ToHexString($hash, 0, 4).ToLowerInvariant())"
}

#region main

$startTime = [DateTime]::UtcNow
$RequestFailures = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$principalIds = [System.Collections.Generic.HashSet[string]]::new()
$sections = [ordered]@{}
$counts = [ordered]@{}
$caller = [ordered]@{}
$subscriptionInfo = $null
$runStatus = 'failed'
$fatalError = $null

if (-not $FolderName) { $FolderName = "$($SubscriptionId)_$($startTime.ToString('yyyyMMdd-HHmmss'))" }
$runFolder = Join-Path -Path $OutputPath -ChildPath $FolderName
if ((Test-Path -Path $runFolder) -and (Get-ChildItem -Path $runFolder -Force | Select-Object -First 1)) { throw "Output folder $runFolder already exists and is not empty" }
$runFolder = (New-Item -Path $runFolder -ItemType Directory -Force).FullName
Write-Log "Output folder: $runFolder"

try {
    if ($authMethod -in 'CertificateThumbprint', 'CertificateFile') { $script:signingCertificate = Get-SigningCertificate }
    Write-Log "Authenticating ($authMethod)"
    $armClaims = Get-TokenClaims -Token (Get-AccessToken -Resource Arm)
    if (-not $TenantId) { $TenantId = $armClaims.tid }
    $caller = [ordered]@{ tenantId = $armClaims.tid; objectId = $armClaims.oid; appId = $armClaims.appid; identityType = $armClaims.idtyp }

    $subscriptionResponse = Invoke-AzRest -Uri "/subscriptions/$SubscriptionId`?api-version=$($coreApiVersions.subscription)" -Context 'subscription'
    if (-not (Test-Success $subscriptionResponse)) {
        throw "Cannot read subscription $SubscriptionId ($($subscriptionResponse.StatusCode) $($subscriptionResponse.ErrorCode)): $($subscriptionResponse.ErrorMessage)"
    }
    $subscriptionInfo = $subscriptionResponse.Json
    Write-JsonFile -Path (Join-Path $runFolder 'subscription/subscription.json') -Value $subscriptionInfo
    Write-Log "Subscription: $(Get-JsonProperty -Element $subscriptionInfo -Name 'displayName') ($(Get-JsonProperty -Element $subscriptionInfo -Name 'state'))"

    #providers give the api versions for every resource type: latest two stable plus latest preview as fallbacks
    $providers = Invoke-AzPaged -Uri "/subscriptions/$SubscriptionId/providers?api-version=$($coreApiVersions.providers)" -Context 'providers'
    if (-not (Test-Success $providers)) { throw "Cannot list resource providers ($($providers.StatusCode) $($providers.ErrorCode))" }
    Write-JsonFile -Path (Join-Path $runFolder 'subscription/providers.json') -Value $providers.Items
    $apiVersions = @{}
    foreach ($provider in $providers.Items) {
        $namespace = Get-JsonProperty -Element $provider -Name 'namespace'
        foreach ($resourceType in (Get-JsonArrayItems -Element (Get-JsonProperty -Element $provider -Name 'resourceTypes'))) {
            $versions = foreach ($version in (Get-JsonArrayItems -Element (Get-JsonProperty -Element $resourceType -Name 'apiVersions'))) { $version.GetString() }
            $stable = @($versions | Where-Object { $_ -notmatch '(?i)preview|alpha|beta' } | Sort-Object -Descending | Select-Object -First 2)
            $preview = @($versions | Where-Object { $_ -match '(?i)preview|alpha|beta' } | Sort-Object -Descending | Select-Object -First 1)
            $apiVersions["$namespace/$(Get-JsonProperty -Element $resourceType -Name 'resourceType')".ToLowerInvariant()] = @($stable + $preview)
        }
    }

    Write-Log 'Subscription settings, RBAC, policy and Defender for Cloud'
    foreach ($endpoint in $subscriptionEndpoints) {
        $folder, $name, $path, $apiVersion, $method = $endpoint
        $separator = if ($path.Contains('?')) { '&' } else { '?' }
        $sections["$folder/$name"] = Export-Endpoint -Uri "/subscriptions/$SubscriptionId/$path$($separator)api-version=$apiVersion" -Method ($method ?? 'GET') -Path (Join-Path $runFolder "$folder/$name.json") -PrincipalTarget $principalIds
    }

    $resourceGroups = Invoke-AzPaged -Uri "/subscriptions/$SubscriptionId/resourcegroups?api-version=$($coreApiVersions.resourceGroups)" -Context 'resourceGroups'
    $resources = Invoke-AzPaged -Uri "/subscriptions/$SubscriptionId/resources?`$expand=$resourceListExpand&api-version=$($coreApiVersions.resources)" -Context 'resources'
    if (-not (Test-Success $resourceGroups) -or -not (Test-Success $resources)) { throw 'Cannot list resource groups or resources' }
    Write-JsonFile -Path (Join-Path $runFolder 'subscription/resourceGroups.json') -Value $resourceGroups.Items
    Write-JsonFile -Path (Join-Path $runFolder 'subscription/resources.json') -Value $resources.Items
    $counts.resourceGroups = $resourceGroups.Count
    $counts.resources = $resources.Count

    $workItems = [System.Collections.Generic.List[object]]::new()
    foreach ($resourceGroup in $resourceGroups.Items) {
        $id = Get-JsonProperty -Element $resourceGroup -Name 'id'
        $file = "resourceGroups/$(Get-SafeFileName -Name (Get-JsonProperty -Element $resourceGroup -Name 'name') -Id $id).json"
        $workItems.Add([pscustomobject]@{ Kind = 'ResourceGroup'; Id = $id; Type = 'Microsoft.Resources/resourceGroups'; File = $file; FullPath = (Join-Path $runFolder $file) })
    }
    foreach ($resource in $resources.Items) {
        $id = Get-JsonProperty -Element $resource -Name 'id'
        $type = Get-JsonProperty -Element $resource -Name 'type'
        $namespace, $typeName = $type.Split('/', 2)
        $file = "resources/$namespace/$($typeName.Replace('/', '.'))/$(Get-SafeFileName -Name (Get-JsonProperty -Element $resource -Name 'name') -Id $id).json"
        $workItems.Add([pscustomobject]@{ Kind = 'Resource'; Id = $id; Type = $type; File = $file; FullPath = (Join-Path $runFolder $file) })
    }

    #per item collection in parallel; functions and read-only state are handed to each runspace, the ARM token is renewed per chunk
    $workerFunctionNames = @(
        'ConvertTo-JsonElement', 'Get-JsonProperty', 'Get-JsonProp', 'Get-JsonArrayItems', 'Write-JsonValue', 'New-JsonWriter', 'Close-JsonWriter',
        'Write-JsonFile', 'Add-RequestFailure', 'Invoke-AzRest', 'Invoke-AzPaged', 'Test-Success', 'Find-PrincipalIds', 'Get-ChildTypeSegments',
        'Get-ChildResource', 'Export-ResourceDetail', 'Export-ResourceGroupDetail'
    )
    $workerFunctions = @{}
    foreach ($functionName in $workerFunctionNames) { $workerFunctions[$functionName] = (Get-Command -Name $functionName -CommandType Function).ScriptBlock.ToString() }
    $itemResults = [System.Collections.Generic.List[object]]::new()
    $chunkSize = 200
    Write-Log "Collecting $($resourceGroups.Count) resource groups and $($resources.Count) resources ($ThrottleLimit threads)"
    for ($offset = 0; $offset -lt $workItems.Count; $offset += $chunkSize) {
        $chunk = $workItems.GetRange($offset, [math]::Min($chunkSize, $workItems.Count - $offset))
        $workerToken = Get-AccessToken -Resource Arm -MinValidMinutes 30
        $chunkResults = $chunk | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            foreach ($definition in ($using:workerFunctions).GetEnumerator()) {
                Set-Item -Path "function:$($definition.Key)" -Value ([scriptblock]::Create($definition.Value))
            }
            $workerToken = $using:workerToken
            function Get-AccessToken { param($Resource, $MinValidMinutes) return $workerToken }
            $cloudEndpoints = $using:cloudEndpoints
            $RequestFailures = $using:RequestFailures
            $CompactJson = $using:CompactJson
            $apiVersions = $using:apiVersions
            $childResourceMap = $using:childResourceMap
            $resourceExpandMap = $using:resourceExpandMap
            $coreApiVersions = $using:coreApiVersions
            $diagnosticSettingsChildTypes = $using:diagnosticSettingsChildTypes
            $resourceGroupEndpoints = $using:resourceGroupEndpoints
            $textContentMap = $using:textContentMap
            $item = $_
            try {
                if ($item.Kind -eq 'ResourceGroup') { Export-ResourceGroupDetail -Item $item } else { Export-ResourceDetail -Item $item }
            } catch {
                [pscustomobject]@{ Id = $item.Id; Type = $item.Type; File = $null; ApiVersion = $null; Status = "error: $($_.Exception.Message)"; FailureCount = 0; PrincipalIds = [string[]]@() }
            }
        }
        foreach ($chunkResult in $chunkResults) {
            $itemResults.Add($chunkResult)
            foreach ($principalId in $chunkResult.PrincipalIds) { $null = $principalIds.Add($principalId) }
        }
        Write-Log "  $([math]::Min($offset + $chunkSize, $workItems.Count))/$($workItems.Count)"
    }
    $index = foreach ($itemResult in $itemResults) {
        [ordered]@{ id = $itemResult.Id; type = $itemResult.Type; file = $itemResult.File; apiVersion = $itemResult.ApiVersion; status = $itemResult.Status; failureCount = $itemResult.FailureCount }
    }
    Write-JsonFile -Path (Join-Path $runFolder 'index.json') -Value @($index)
    $counts.itemsFailed = @($itemResults | Where-Object { $_.Status -ne 'ok' }).Count
    foreach ($errorResult in ($itemResults | Where-Object { $_.Status -like 'error:*' })) { Write-Log "$($errorResult.Id): $($errorResult.Status)" -Warning }

    if (-not $SkipResourceGraph) {
        Write-Log 'Resource Graph tables'
        foreach ($table in $resourceGraphTables) {
            $sections["resourceGraph/$table"] = Export-ResourceGraphTable -Table $table -Path (Join-Path $runFolder "resourceGraph/$table.json")
        }
    }

    if ($ActivityLogDays -gt 0) {
        #queried per day to keep responses small; windows do not overlap. The API returns some events twice, identical, so they are deduplicated
        Write-Log "Activity log ($ActivityLogDays days)"
        $eventCount = 0
        $duplicateCount = 0
        $failedDays = 0
        $seenEventIds = [System.Collections.Generic.HashSet[string]]::new()
        $handle = New-JsonWriter -Path (Join-Path $runFolder 'activityLog/activityLog.json')
        try {
            $handle.Writer.WriteStartArray()
            $windowEnd = $startTime
            for ($day = 0; $day -lt $ActivityLogDays; $day++) {
                $windowStart = $windowEnd.AddDays(-1)
                $filter = "eventTimestamp ge '$($windowStart.ToString('o'))' and eventTimestamp le '$($windowEnd.ToString('o'))'"
                $result = Invoke-AzPaged -Uri "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/eventtypes/management/values?api-version=$($coreApiVersions.activityLog)&`$filter=$([uri]::EscapeDataString($filter))" -Context 'activityLog' -Writer $handle.Writer -SeenIds $seenEventIds -IdProperty 'eventDataId'
                if (-not (Test-Success $result) -or -not $result.Complete) { $failedDays++ }
                $eventCount += $result.Count
                $duplicateCount += $result.Duplicates
                $windowEnd = $windowStart.AddTicks(-1)
            }
            $handle.Writer.WriteEndArray()
        } finally {
            Close-JsonWriter -Handle $handle
        }
        $sections['activityLog/activityLog'] = [ordered]@{ status = if ($failedDays -eq 0) { 'ok' } elseif ($failedDays -lt $ActivityLogDays) { 'partial' } else { 'failed' }; count = $eventCount; duplicatesSkipped = $duplicateCount; days = $ActivityLogDays; failedDays = $failedDays }
    }

    $counts.referencedPrincipals = $principalIds.Count
    if (-not $SkipGraph) {
        Write-Log "Entra ID ($($principalIds.Count) referenced principals)"
        try {
            $caller.graphRoles = @((Get-TokenClaims -Token (Get-AccessToken -Resource Graph)).roles | Where-Object { $_ })
            $identitySections = Export-EntraData -PrincipalIds $principalIds -Folder (Join-Path $runFolder 'identity')
            foreach ($entry in $identitySections.GetEnumerator()) { $sections["identity/$($entry.Key)"] = $entry.Value }
        } catch {
            Write-Log "Entra ID collection failed: $($_.Exception.Message)" -Warning
            $sections['identity'] = [ordered]@{ status = 'failed'; message = $_.Exception.Message }
        }
    }
    $runStatus = 'completed'
} catch {
    $fatalError = "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    Write-Log "Run failed: $fatalError" -Warning
} finally {
    $endTime = [DateTime]::UtcNow
    $failureList = @($RequestFailures.ToArray())
    $failuresByCategory = [ordered]@{}
    foreach ($group in ($failureList | Group-Object -Property { $_.category } | Sort-Object -Property Name)) { $failuresByCategory[$group.Name] = $group.Count }
    Write-JsonFile -Path (Join-Path $runFolder 'failures.json') -Value $failureList
    Write-JsonFile -Path (Join-Path $runFolder 'manifest.json') -Value ([ordered]@{
            schemaVersion   = $schemaVersion
            scriptVersion   = $scriptVersion
            status          = $runStatus
            error           = $fatalError
            startedAt       = $startTime
            completedAt     = $endTime
            durationSeconds = [int]($endTime - $startTime).TotalSeconds
            environment     = $Environment
            subscription    = [ordered]@{
                id          = $SubscriptionId
                displayName = Get-JsonProperty -Element $subscriptionInfo -Name 'displayName'
                state       = Get-JsonProperty -Element $subscriptionInfo -Name 'state'
                tenantId    = $TenantId
            }
            authentication  = [ordered]@{ method = $authMethod; clientId = $ClientId; caller = $caller }
            parameters      = [ordered]@{ activityLogDays = $ActivityLogDays; skipGraph = [bool]$SkipGraph; skipResourceGraph = [bool]$SkipResourceGraph; throttleLimit = $ThrottleLimit; compactJson = [bool]$CompactJson }
            counts          = $counts
            sections        = $sections
            failures        = [ordered]@{ total = $failureList.Count; byCategory = $failuresByCategory }
            host            = [ordered]@{ powerShell = $PSVersionTable.PSVersion.ToString(); os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription }
        })
}

if ($runStatus -ne 'completed') { throw "Ingestion failed: $fatalError (partial output in $runFolder)" }

$outputLocation = $runFolder
if ($Compress) {
    Add-Type -AssemblyName System.IO.Compression.ZipFile
    $outputLocation = "$runFolder.zip"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($runFolder, $outputLocation, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    Remove-Item -Path $runFolder -Recurse -Force
}
$failureSummary = ($failuresByCategory.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
Write-Log "Done in $([int]($endTime - $startTime).TotalMinutes) min. Failed requests: $($failureList.Count) ($failureSummary). Output: $outputLocation"
[pscustomobject]@{ Path = $outputLocation; Resources = $counts.resources; FailedRequests = $failureList.Count }

#endregion
