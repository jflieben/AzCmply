#Generic PaaS settings for resource types without a dedicated test: public network access, local authentication, minimum TLS.
#Types listed in the exclusions are evaluated by a service specific test, so no resource is evaluated twice for the same setting.

$genericPublicExclusions = @(
    'Microsoft.Storage/storageAccounts', 'Microsoft.KeyVault/vaults', 'Microsoft.KeyVault/managedHSMs', 'Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances',
    'Microsoft.DocumentDB/databaseAccounts', 'Microsoft.ContainerRegistry/registries', 'Microsoft.CognitiveServices/accounts',
    'Microsoft.MachineLearningServices/workspaces', 'Microsoft.Databricks/workspaces', 'Microsoft.Web/sites', 'Microsoft.Web/sites/slots',
    'Microsoft.Compute/disks', 'Microsoft.Compute/snapshots', 'Microsoft.ContainerService/managedClusters', 'Microsoft.BotService/botServices', 'Microsoft.Kusto/clusters',
    'Microsoft.DesktopVirtualization/hostPools', 'Microsoft.DesktopVirtualization/workspaces'
)
$genericLocalAuthExclusions = @('Microsoft.DocumentDB/databaseAccounts', 'Microsoft.CognitiveServices/accounts', 'Microsoft.MachineLearningServices/workspaces/computes', 'Microsoft.BotService/botServices')
$genericTlsExclusions = @('Microsoft.Storage/storageAccounts', 'Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances', 'Microsoft.Web/sites', 'Microsoft.Web/sites/slots', 'Microsoft.Network/applicationGateways')

function Get-PropertyCaseInsensitive {
    #value of a property by name regardless of casing; returns [pscustomobject]@{ Found; Value }
    param($Object, [string]$Name)
    if ($null -eq $Object) { return [pscustomobject]@{ Found = $false; Value = $null } }
    $property = $Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($property) { return [pscustomobject]@{ Found = $true; Value = $property.Value } }
    return [pscustomobject]@{ Found = $false; Value = $null }
}

function Test-TypeExcluded {
    param($Record, [string[]]$Exclusions)
    return ($Record.type.ToLowerInvariant() -in @($Exclusions | ForEach-Object { $_.ToLowerInvariant() }))
}

Add-AzTest @{
    Id          = 'AZ-PAAS-001'
    Title       = 'PaaS services disable public network access'
    Category    = 'Network security'
    Service     = 'Multiple'
    Severity    = 'Medium'
    Description = 'For every other resource type that exposes a publicNetworkAccess setting (for example Service Bus, Event Hubs, Event Grid, Redis, PostgreSQL and MySQL flexible server, AI Search, App Configuration, SignalR, IoT Hub, Automation, Data Factory, Synapse, Recovery Services, API Management, Log Analytics and Application Insights), checks that public network access is disabled.'
    Rationale   = 'Publicly reachable PaaS endpoints depend on keys and tokens alone; private endpoints remove Internet exposure and data exfiltration paths.'
    Remediation = 'Create private endpoints (with private DNS zones) and set public network access to Disabled, or secure the resource with a network security perimeter.'
    References  = @('https://learn.microsoft.com/azure/private-link/private-endpoint-overview')
    Run         = {
        foreach ($record in (Get-AzResourceRecords)) {
            if (Test-TypeExcluded $record $genericPublicExclusions) { continue }
            $p = $record.resource.properties
            $settings = [ordered]@{}
            foreach ($name in 'publicNetworkAccess', 'publicNetworkAccessForIngestion', 'publicNetworkAccessForQuery') {
                $value = Get-PropertyCaseInsensitive $p $name
                if ($value.Found) { $settings[$name] = $value.Value }
            }
            $network = Get-PropertyCaseInsensitive (Get-PropertyCaseInsensitive $p 'network').Value 'publicNetworkAccess'
            if ($network.Found) { $settings['network.publicNetworkAccess'] = $network.Value }
            if (-not $settings.Count) { continue }
            $open = @($settings.Keys | Where-Object { $settings[$_] -ne $false -and [string]$settings[$_] -notin 'Disabled', 'SecuredByPerimeter' })
            $evidence = [ordered]@{}
            foreach ($key in $settings.Keys) { $evidence[$key] = $settings[$key] }
            $result = if ($open) { New-Fail "Public network access enabled ($(($open | ForEach-Object { "$_ = $(if ($null -eq $settings[$_]) { 'default' } else { $settings[$_] })" }) -join ', '))" $evidence } else { New-Pass 'Public network access disabled' $evidence }
            New-Finding -Record $record -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-PAAS-002'
    Title       = 'PaaS services disable local (key and SAS) authentication'
    Category    = 'Identity management'
    Service     = 'Multiple'
    Severity    = 'Medium'
    Description = 'For every other resource type with a disableLocalAuth setting (for example Service Bus, Event Hubs, Relay, Event Grid, App Configuration, SignalR, Web PubSub, AI Search, IoT Hub, Automation, Application Insights, Log Analytics) and Batch accounts, checks that key or SAS based authentication is disabled.'
    Rationale   = 'Access keys and SAS tokens are shared secrets that are not tied to an identity, bypass RBAC and Conditional Access and are hard to rotate or trace.'
    Remediation = 'Move clients to Microsoft Entra ID (managed identities with data plane RBAC roles), then disable local authentication on the resource.'
    References  = @('https://learn.microsoft.com/azure/service-bus-messaging/disable-local-authentication')
    Run         = {
        foreach ($record in (Get-AzResourceRecords)) {
            if (Test-TypeExcluded $record $genericLocalAuthExclusions) { continue }
            $p = $record.resource.properties
            if ($record.type -eq 'Microsoft.Batch/batchAccounts') {
                $modes = @($p.allowedAuthenticationModes)
                $evidence = [ordered]@{ allowedAuthenticationModes = $modes }
                $result = if ($modes -contains 'SharedKey') { New-Fail 'Shared key authentication allowed' $evidence } else { New-Pass 'Shared key authentication disabled' $evidence }
                New-Finding -Record $record -Result $result
                continue
            }
            $setting = Get-PropertyCaseInsensitive $p 'disableLocalAuth'
            if (-not $setting.Found) { $setting = Get-PropertyCaseInsensitive (Get-PropertyCaseInsensitive $p 'features').Value 'disableLocalAuth' }
            if (-not $setting.Found) { continue }
            $evidence = [ordered]@{ disableLocalAuth = $setting.Value }
            $result = if ($setting.Value -eq $true) { New-Pass 'Local authentication disabled' $evidence } else { New-Fail 'Local (key/SAS) authentication enabled' $evidence }
            New-Finding -Record $record -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-PAAS-003'
    Title       = 'PaaS services require TLS 1.2 or higher'
    Category    = 'Data protection'
    Service     = 'Multiple'
    Severity    = 'Medium'
    Description = 'For every other resource type with a minimum TLS setting (for example Service Bus, Event Hubs, Relay, Redis, Event Grid, IoT Hub, Cosmos DB), checks that the minimum is TLS 1.2 or higher.'
    Rationale   = 'TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure; the minimum version should be enforced on every endpoint.'
    Remediation = 'Set the minimum TLS version of the resource to 1.2 (or 1.3 where supported).'
    References  = @('https://learn.microsoft.com/azure/security/fundamentals/encryption-overview')
    Run         = {
        foreach ($record in (Get-AzResourceRecords)) {
            if (Test-TypeExcluded $record $genericTlsExclusions) { continue }
            $p = $record.resource.properties
            $setting = $null
            foreach ($name in 'minimumTlsVersion', 'minimalTlsVersion', 'minTlsVersion', 'minimumTlsVersionAllowed') {
                $candidate = Get-PropertyCaseInsensitive $p $name
                if ($candidate.Found) { $setting = [pscustomobject]@{ Name = $name; Value = $candidate.Value }; break }
            }
            if (-not $setting) { continue }
            $evidence = [ordered]@{ $setting.Name = $setting.Value }
            $result = if (Test-VersionAtLeast $setting.Value '1.2') { New-Pass "Minimum TLS $($setting.Value)" $evidence } else { New-Fail "Minimum TLS $(if ($setting.Value) { $setting.Value } else { 'not set' })" $evidence }
            New-Finding -Record $record -Result $result
        }
    }
}
