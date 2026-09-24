#Logging and monitoring: activity log, activity log alerts, resource logs, flow logs, Network Watcher, retention

function Get-ActivityLogSettings {
    return @(Get-IngestData 'subscription/diagnosticSettings' | Where-Object { $_ -and ($_.properties.workspaceId -or $_.properties.storageAccountId -or $_.properties.eventHubAuthorizationRuleId -or $_.properties.marketplacePartnerId) })
}

Add-AzTest @{
    Id          = 'AZ-LOG-001'
    Title       = 'The activity log is exported with a diagnostic setting'
    Category    = 'Logging and threat detection'
    Service     = 'Azure Monitor'
    Severity    = 'High'
    Description = 'Checks that the subscription has a diagnostic setting that sends the activity log to Log Analytics, a storage account, an event hub or a partner solution.'
    Rationale   = 'The activity log keeps control plane operations for only 90 days and cannot be queried together with other logs. Exporting it enables long term retention, correlation and alerting in a SIEM.'
    Remediation = 'Create a subscription diagnostic setting that sends all activity log categories to a central Log Analytics workspace (Monitor > Activity log > Export activity logs).'
    References  = @('https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log')
    Frameworks  = @{ MCSB = @('LT-3', 'LT-5'); CIS = '6.1.1.1'; WAF = 'SE:10'; ALZ = 'Deploy-AzActivity-Log' }
    Requires    = @('subscription/diagnosticSettings')
    Run         = {
        $settings = @(Get-ActivityLogSettings)
        $evidence = [ordered]@{ settings = @($settings | ForEach-Object name | Sort-Object) }
        if ($settings) { return New-SubscriptionFinding (New-Pass "Activity log exported by $($settings.Count) diagnostic setting(s)" $evidence) }
        New-SubscriptionFinding (New-Fail 'The activity log is not exported' $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-LOG-002'
    Title       = 'The activity log export includes the security relevant categories'
    Category    = 'Logging and threat detection'
    Service     = 'Azure Monitor'
    Severity    = 'Medium'
    Description = 'Checks that a subscription diagnostic setting exports the Administrative, Alert, Policy and Security categories.'
    Rationale   = 'These categories record configuration changes, alerts, policy decisions and Defender for Cloud events, which investigations depend on.'
    Remediation = 'Edit the subscription diagnostic setting and select at least Administrative, Alert, Policy and Security (or all categories).'
    References  = @('https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log-schema')
    Frameworks  = @{ MCSB = 'LT-3'; CIS = '6.1.1.2' }
    Requires    = @('subscription/diagnosticSettings')
    Run         = {
        $settings = @(Get-ActivityLogSettings)
        if (-not $settings) { return New-SubscriptionFinding (New-NotApplicable 'No activity log export (see AZ-LOG-001)') }
        $required = @('Administrative', 'Alert', 'Policy', 'Security')
        $best = $null
        foreach ($setting in $settings) {
            $enabled = @($setting.properties.logs | Where-Object { $_.enabled } | ForEach-Object { if ($_.category) { $_.category } else { $_.categoryGroup } })
            $missing = @($required | Where-Object { $_ -notin $enabled -and 'allLogs' -notin $enabled })
            if (-not $best -or $missing.Count -lt $best.Missing.Count) { $best = [pscustomobject]@{ Name = $setting.name; Missing = $missing; Enabled = $enabled } }
        }
        $evidence = [ordered]@{ setting = $best.Name; enabledCategories = @($best.Enabled | Sort-Object); missingCategories = @($best.Missing) }
        if ($best.Missing) { return New-SubscriptionFinding (New-Fail "Missing categories: $($best.Missing -join ', ')" $evidence) }
        New-SubscriptionFinding (New-Pass 'All required categories are exported' $evidence)
    }
}

function Get-ConditionValues {
    #field -> values of an activity log alert condition, including anyOf branches
    param($Condition)
    $values = @{}
    $leaves = @($Condition.allOf) | Where-Object { $_ }
    foreach ($leaf in $leaves) {
        $items = if ($leaf.anyOf) { @($leaf.anyOf) } else { @($leaf) }
        foreach ($item in $items) {
            if (-not $item.field) { continue }
            $key = $item.field.ToLowerInvariant()
            if (-not $values.ContainsKey($key)) { $values[$key] = [System.Collections.Generic.List[string]]::new() }
            if ($item.equals) { $values[$key].Add(([string]$item.equals).ToLowerInvariant()) }
            foreach ($value in @($item.containsAny)) { if ($value) { $values[$key].Add(([string]$value).ToLowerInvariant()) } }
        }
    }
    return $values
}

$activityAlerts = @(
    @{ Id = 'AZ-LOG-003'; Cis = '6.1.2.1'; Operation = 'Microsoft.Authorization/policyAssignments/write'; Label = 'Create policy assignment'; Category = 'Administrative'; Policy = @{ 'c5447c04-a4d7-4ba8-a263-c9ee321a6858' = 'An activity log alert should exist for specific Policy operations' } }
    @{ Id = 'AZ-LOG-004'; Cis = '6.1.2.2'; Operation = 'Microsoft.Authorization/policyAssignments/delete'; Label = 'Delete policy assignment'; Category = 'Administrative'; Policy = @{ 'c5447c04-a4d7-4ba8-a263-c9ee321a6858' = 'An activity log alert should exist for specific Policy operations' } }
    @{ Id = 'AZ-LOG-005'; Cis = '6.1.2.3'; Operation = 'Microsoft.Network/networkSecurityGroups/write'; Label = 'Create or update network security group'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
    @{ Id = 'AZ-LOG-006'; Cis = '6.1.2.4'; Operation = 'Microsoft.Network/networkSecurityGroups/delete'; Label = 'Delete network security group'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
    @{ Id = 'AZ-LOG-007'; Cis = '6.1.2.5'; Operation = 'Microsoft.Security/securitySolutions/write'; Label = 'Create or update security solution'; Category = 'Security'; Policy = @{ '3b980d31-7904-4bb7-8575-5665739a8052' = 'An activity log alert should exist for specific Security operations' } }
    @{ Id = 'AZ-LOG-008'; Cis = '6.1.2.6'; Operation = 'Microsoft.Security/securitySolutions/delete'; Label = 'Delete security solution'; Category = 'Security'; Policy = @{ '3b980d31-7904-4bb7-8575-5665739a8052' = 'An activity log alert should exist for specific Security operations' } }
    @{ Id = 'AZ-LOG-009'; Cis = '6.1.2.7'; Operation = 'Microsoft.Sql/servers/firewallRules/write'; Label = 'Create or update SQL server firewall rule'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
    @{ Id = 'AZ-LOG-010'; Cis = '6.1.2.8'; Operation = 'Microsoft.Sql/servers/firewallRules/delete'; Label = 'Delete SQL server firewall rule'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
    @{ Id = 'AZ-LOG-011'; Cis = '6.1.2.9'; Operation = 'Microsoft.Network/publicIPAddresses/write'; Label = 'Create or update public IP address'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
    @{ Id = 'AZ-LOG-012'; Cis = '6.1.2.10'; Operation = 'Microsoft.Network/publicIPAddresses/delete'; Label = 'Delete public IP address'; Category = 'Administrative'; Policy = @{ 'b954148f-4c11-4c38-8221-be76711e194a' = 'An activity log alert should exist for specific Administrative operations' } }
)

function Test-ActivityAlert {
    #matching enabled activity log alerts scoped to the subscription; -Operation $null matches on category only
    param([string]$Category, [string]$Operation)
    $scope = (Get-SubscriptionScope).ToLowerInvariant()
    foreach ($record in (Get-AzResourceRecords -Type 'Microsoft.Insights/activityLogAlerts')) {
        $p = $record.resource.properties
        if (-not $p.enabled) { continue }
        if (-not (@($p.scopes) | Where-Object { $_ -and $_.ToLowerInvariant() -eq $scope })) { continue }
        $values = Get-ConditionValues $p.condition
        if ($values['category'] -notcontains $Category.ToLowerInvariant()) { continue }
        if ($Operation -and $values['operationname'] -notcontains $Operation.ToLowerInvariant()) { continue }
        [pscustomobject]@{ Record = $record; ActionGroups = @($p.actions.actionGroups | Where-Object { $_ }).Count }
    }
}

foreach ($alert in $activityAlerts) {
    Add-AzTest @{
        Id          = $alert.Id
        Title       = "An activity log alert exists for '$($alert.Label)'"
        Category    = 'Logging and threat detection'
        Service     = 'Azure Monitor'
        Severity    = 'Low'
        Description = "Checks for an enabled activity log alert on the subscription for operation $($alert.Operation) that notifies an action group."
        Rationale   = 'Alerting on security relevant control plane changes shortens the time to detect unauthorized or accidental changes that weaken the security posture.'
        Remediation = "Create an activity log alert on the subscription with category $($alert.Category) and operation name $($alert.Operation), and attach an action group that reaches the security team."
        References  = @('https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule')
        Frameworks  = @{ MCSB = 'LT-3'; CIS = $alert.Cis }
        Policy      = $alert.Policy
        Config      = $alert
        Run         = {
            param($Test)
            $alertRules = @(Test-ActivityAlert -Category $Test.Config.Category -Operation $Test.Config.Operation)
            $notifying = @($alertRules | Where-Object { $_.ActionGroups -gt 0 })
            $evidence = [ordered]@{ alertRules = @($alertRules | ForEach-Object { $_.Record.resource.name } | Sort-Object); withActionGroup = @($notifying | ForEach-Object { $_.Record.resource.name } | Sort-Object) }
            if ($notifying) { return New-SubscriptionFinding (New-Pass "Alert rule(s): $($evidence.withActionGroup -join ', ')" $evidence) }
            if ($alertRules) { return New-SubscriptionFinding (New-Fail 'An alert rule exists but has no action group' $evidence) }
            New-SubscriptionFinding (New-Fail "No enabled activity log alert for $($Test.Config.Operation)" $evidence)
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-LOG-013'
    Title       = 'An activity log alert exists for Service Health'
    Category    = 'Incident response'
    Service     = 'Azure Monitor'
    Severity    = 'Low'
    Description = 'Checks for an enabled activity log alert on the subscription for the ServiceHealth category that notifies an action group.'
    Rationale   = 'Service Health notifies about platform incidents, planned maintenance and security advisories (for example about compromised or deprecated components) affecting your resources.'
    Remediation = 'Create a Service Health alert for the subscription (Service Health > Health alerts) with an action group that reaches the operations and security teams.'
    References  = @('https://learn.microsoft.com/azure/service-health/alerts-activity-log-service-notifications-portal')
    Frameworks  = @{ MCSB = 'IR-2'; CIS = '6.1.2.11'; ALZ = 'Deploy-SvcHealth-BuiltIn' }
    Run         = {
        $alertRules = @(Test-ActivityAlert -Category 'ServiceHealth')
        $notifying = @($alertRules | Where-Object { $_.ActionGroups -gt 0 })
        $evidence = [ordered]@{ alertRules = @($alertRules | ForEach-Object { $_.Record.resource.name } | Sort-Object) }
        if ($notifying) { return New-SubscriptionFinding (New-Pass "Service Health alert rule(s): $($evidence.alertRules -join ', ')" $evidence) }
        if ($alertRules) { return New-SubscriptionFinding (New-Fail 'A Service Health alert exists but has no action group' $evidence) }
        New-SubscriptionFinding (New-Fail 'No Service Health alert for the subscription' $evidence)
    }
}

Add-AzTest @{
    Id            = 'AZ-LOG-014'
    Title         = 'Key Vault audit logging is enabled'
    Category      = 'Logging and threat detection'
    Service       = 'Key Vault'
    Severity      = 'High'
    Description   = 'Checks that each key vault and managed HSM has a diagnostic setting that sends the AuditEvent category (or the audit/allLogs group) to a destination.'
    Rationale     = 'Key Vault audit logs record every access to secrets, keys and certificates. Without them, theft of secrets cannot be detected or investigated.'
    Remediation   = 'Add a diagnostic setting with the audit category group to a Log Analytics workspace (az monitor diagnostic-settings create --resource <vault id> --workspace <id> --logs "[{categoryGroup:audit,enabled:true}]").'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/logging')
    Frameworks    = @{ MCSB = @('LT-3', 'DP-8'); CIS = '6.1.1.4'; WAF = 'SE:10'; ALZ = 'Deploy-Diag-LogsCat' }
    Policy        = @{ 'cf820ca0-f99e-4f3e-84fb-66e913812d21' = 'Resource logs in Key Vault should be enabled'; 'a2a5b911-5617-447e-a49e-59dbe0e0434b' = 'Resource logs in Azure Key Vault Managed HSM should be enabled' }
    ResourceTypes = @('Microsoft.KeyVault/vaults', 'Microsoft.KeyVault/managedHSMs')
    Evaluate      = {
        param($Record)
        if ($null -eq $Record.diagnosticSettings) { return New-Unknown 'Diagnostic settings could not be read' }
        $evidence = [ordered]@{ diagnosticSettings = @($Record.diagnosticSettings | ForEach-Object name | Sort-Object) }
        if (Test-DiagnosticLogsEnabled -Settings $Record.diagnosticSettings -RequiredCategories 'AuditEvent') { return New-Pass 'AuditEvent logs are exported' $evidence }
        New-Fail 'AuditEvent logs are not exported' $evidence
    }
}

#resource types with security relevant resource log categories; Key Vault (AZ-LOG-014) and Databricks (AZ-DBX-005) have their own tests
$resourceLogTypes = @(
    'Microsoft.Web/sites', 'Microsoft.Web/sites/slots', 'Microsoft.Sql/servers/databases', 'Microsoft.Sql/managedInstances', 'Microsoft.Network/networkSecurityGroups',
    'Microsoft.Network/applicationGateways', 'Microsoft.Network/azureFirewalls', 'Microsoft.Network/bastionHosts', 'Microsoft.Network/publicIPAddresses',
    'Microsoft.Network/virtualNetworkGateways', 'Microsoft.Network/frontDoors', 'Microsoft.Cdn/profiles', 'Microsoft.ContainerService/managedClusters',
    'Microsoft.ContainerRegistry/registries', 'Microsoft.DocumentDB/databaseAccounts', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers',
    'Microsoft.Cache/redis', 'Microsoft.ServiceBus/namespaces', 'Microsoft.EventHub/namespaces', 'Microsoft.EventGrid/topics', 'Microsoft.EventGrid/domains',
    'Microsoft.EventGrid/systemTopics', 'Microsoft.EventGrid/namespaces', 'Microsoft.Logic/workflows', 'Microsoft.ApiManagement/service',
    'Microsoft.Automation/automationAccounts', 'Microsoft.CognitiveServices/accounts', 'Microsoft.MachineLearningServices/workspaces', 'Microsoft.Search/searchServices',
    'Microsoft.DataFactory/factories', 'Microsoft.Synapse/workspaces', 'Microsoft.Kusto/clusters', 'Microsoft.RecoveryServices/vaults', 'Microsoft.DataProtection/backupVaults',
    'Microsoft.AppConfiguration/configurationStores', 'Microsoft.SignalRService/signalR', 'Microsoft.SignalRService/webPubSub', 'Microsoft.Devices/IotHubs',
    'Microsoft.Batch/batchAccounts', 'Microsoft.OperationalInsights/workspaces', 'Microsoft.App/managedEnvironments', 'Microsoft.DesktopVirtualization/hostPools',
    'Microsoft.DesktopVirtualization/workspaces', 'Microsoft.DesktopVirtualization/applicationGroups', 'Microsoft.Storage/storageAccounts'
)

Add-AzTest @{
    Id            = 'AZ-LOG-015'
    Title         = 'Resource logs are enabled for services that support them'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Monitor'
    Severity      = 'Medium'
    Description   = 'Checks that services with security relevant resource logs (web apps, databases, network security and gateways, messaging, AI, data and integration services, storage services) send logs through a diagnostic setting. For storage accounts the blob, file, queue and table services are checked.'
    Rationale     = 'Resource (data plane) logs record who accessed data and how services were used. They are needed to detect abuse and to investigate incidents, and are not collected unless configured.'
    Remediation   = 'Create diagnostic settings with the allLogs or audit category group to a central Log Analytics workspace, preferably enforced with the built-in "Enable logging by category group" policy initiatives.'
    References    = @('https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings')
    Frameworks    = @{ MCSB = 'LT-3'; CIS = '6.1.4'; WAF = 'SE:10'; ALZ = 'Deploy-Diag-LogsCat' }
    ResourceTypes = $resourceLogTypes
    Evaluate      = {
        param($Record)
        if ($Record.type -eq 'Microsoft.Storage/storageAccounts') {
            $services = [ordered]@{}
            foreach ($service in 'blobServices', 'fileServices', 'queueServices', 'tableServices') {
                $path = "$service/default/providers/Microsoft.Insights/diagnosticSettings"
                if (Test-ChildCollected $Record $path) { $services[$service] = Test-DiagnosticLogsEnabled -Settings (Get-Child $Record $path) }
            }
            if (-not $services.Count) { return New-Unknown 'Storage service diagnostic settings could not be read' }
            $missing = @($services.Keys | Where-Object { -not $services[$_] })
            $evidence = [ordered]@{ servicesWithLogs = @($services.Keys | Where-Object { $services[$_] }); servicesWithoutLogs = $missing }
            if ($missing) { return New-Fail "No resource logs for $($missing -join ', ')" $evidence }
            return New-Pass 'All storage services send resource logs' $evidence
        }
        if ($null -eq $Record.diagnosticSettings) { return New-Unknown 'Diagnostic settings could not be read or are not supported' }
        $evidence = [ordered]@{ diagnosticSettings = @($Record.diagnosticSettings | ForEach-Object name | Sort-Object) }
        if (Test-DiagnosticLogsEnabled -Settings $Record.diagnosticSettings) { return New-Pass 'Resource logs are exported' $evidence }
        New-Fail 'No diagnostic setting exports resource logs' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-LOG-021'
    Title       = 'Application Insights is configured for application workloads'
    Category    = 'Logging and threat detection'
    Service     = 'Application Insights'
    Severity    = 'Low'
    Description = 'Checks that the subscription contains Application Insights components when it hosts App Service or Container Apps workloads.'
    Rationale   = 'Application telemetry (requests, exceptions, dependencies) is needed to detect application layer attacks and to investigate incidents inside the application.'
    Remediation = 'Create a workspace based Application Insights component and connect the applications to it (preferably with Entra authenticated ingestion).'
    References  = @('https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview')
    Frameworks  = @{ MCSB = 'LT-3'; CIS = '6.1.3.1'; WAF = 'SE:10' }
    Requires    = @('subscription/resources')
    Run         = {
        $resources = @(Get-IngestData 'subscription/resources' | Where-Object { $_ })
        $apps = @($resources | Where-Object { $_.type -in 'Microsoft.Web/sites', 'Microsoft.App/containerApps' })
        $components = @($resources | Where-Object { $_.type -eq 'Microsoft.Insights/components' } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ applications = $apps.Count; components = $components }
        if (-not $apps) { return New-SubscriptionFinding (New-NotApplicable 'No App Service or Container Apps workloads' $evidence) }
        if ($components) { return New-SubscriptionFinding (New-Pass "$($components.Count) Application Insights component(s)" $evidence) }
        New-SubscriptionFinding (New-Fail 'No Application Insights components' $evidence)
    }
}

Add-AzTest @{
    Id            = 'AZ-LOG-016'
    Title         = 'Log Analytics workspaces retain data for at least 90 days'
    Category      = 'Logging and threat detection'
    Service       = 'Log Analytics'
    Severity      = 'Medium'
    Description   = 'Checks the default interactive retention of Log Analytics workspaces.'
    Rationale     = 'Attacks are often discovered weeks or months after the initial compromise. Short retention removes the evidence needed to scope and investigate them.'
    Remediation   = 'Set workspace retention to at least 90 days (or longer per policy; Microsoft Sentinel workspaces include 90 days), and use table level or long term retention for high value tables.'
    References    = @('https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-configure')
    Frameworks    = @{ MCSB = 'LT-6' }
    ResourceTypes = @('Microsoft.OperationalInsights/workspaces')
    Evaluate      = {
        param($Record)
        $days = [int]$Record.resource.properties.retentionInDays
        $evidence = [ordered]@{ retentionInDays = $days; sku = $Record.resource.properties.sku.name }
        if ($days -ge 90) { return New-Pass "$days days retention" $evidence }
        New-Fail "$days days retention" $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-LOG-017'
    Title       = 'Network Watcher is enabled in every region in use'
    Category    = 'Logging and threat detection'
    Service     = 'Network Watcher'
    Severity    = 'Low'
    Description = 'Compares the regions of network resources with the regions that have a Network Watcher.'
    Rationale   = 'Network Watcher provides flow logs, connection troubleshooting and packet capture; it must exist in a region before flow logs can be configured there.'
    Remediation = 'Enable Network Watcher in the missing regions (az network watcher configure --locations <region> --enabled true --resource-group NetworkWatcherRG).'
    References  = @('https://learn.microsoft.com/azure/network-watcher/network-watcher-create')
    Frameworks  = @{ MCSB = @('LT-4', 'IR-4'); CIS = '7.6' }
    Policy      = @{ 'b6e2945c-0b7b-40f5-9233-7a5323b5cdc6' = 'Network Watcher should be enabled' }
    Requires    = @('subscription/resources')
    Run         = {
        $normalize = { param($l) ([string]$l).ToLowerInvariant() -replace '\s', '' }
        $networkTypes = @('microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses')
        $used = @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.type.ToLowerInvariant() -in $networkTypes } | ForEach-Object { & $normalize $_.location } | Sort-Object -Unique)
        $watchers = @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.type -eq 'Microsoft.Network/networkWatchers' } | ForEach-Object { & $normalize $_.location } | Sort-Object -Unique)
        if (-not $used) { return New-SubscriptionFinding (New-NotApplicable 'No network resources') }
        foreach ($region in $used) {
            $result = if ($region -in $watchers) { New-Pass "Network Watcher exists in $region" } else { New-Fail "No Network Watcher in $region" }
            New-Finding -ResourceId "$(Get-SubscriptionScope)/locations/$region/networkWatcher" -ResourceType 'Microsoft.Network/networkWatchers' -ResourceName $region -Result $result
        }
    }
}

function Get-FlowLogs {
    #-Kind Nsg or Vnet selects flow logs by the resource they target, so a control about NSG flow logs
    #is never judged on virtual network flow logs and the other way round
    param([ValidateSet('All', 'Nsg', 'Vnet')][string]$Kind = 'All')
    $logs = foreach ($watcher in (Get-AzResourceRecords -Type 'Microsoft.Network/networkWatchers')) { @(Get-Child $watcher 'flowLogs') | Where-Object { $_ } }
    switch ($Kind) {
        'Nsg' { return @($logs | Where-Object { ([string]$_.properties.targetResourceId) -match '(?i)/networkSecurityGroups/' }) }
        'Vnet' { return @($logs | Where-Object { ([string]$_.properties.targetResourceId) -match '(?i)/virtualNetworks/' }) }
    }
    return @($logs)
}

function Test-FlowLogsCollected {
    #false when no network watcher returned its flow logs, so "no flow logs" cannot be concluded
    $watchers = @(Get-AzResourceRecords -Type 'Microsoft.Network/networkWatchers')
    if (-not $watchers) { return $true }
    return [bool](@($watchers | Where-Object { Test-ChildCollected $_ 'flowLogs' }).Count)
}

Add-AzTest @{
    Id            = 'AZ-LOG-018'
    Version       = 2
    Title         = 'Virtual network flow logs are enabled'
    Category      = 'Logging and threat detection'
    Service       = 'Network Watcher'
    Severity      = 'Medium'
    Description   = 'Checks that each virtual network is covered by an enabled virtual network flow log, or that all of its subnets have NSGs with enabled NSG flow logs (NSG flow logs retire on 30 September 2027 and can no longer be created).'
    Rationale     = 'Flow logs record which IP addresses communicated over which ports. They are essential to detect lateral movement and data exfiltration and to scope incidents.'
    Remediation   = 'Create virtual network flow logs (az network watcher flow-log create --vnet <id> ...) and migrate existing NSG flow logs to virtual network flow logs.'
    References    = @('https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview', 'https://learn.microsoft.com/azure/network-watcher/nsg-flow-logs-migrate')
    Frameworks    = @{ MCSB = 'LT-4'; CIS = '6.1.1.6'; WAF = 'SE:10' }
    Policy        = @{ '4c3c6c5f-0d47-4402-99b8-aa543dd8bcee' = 'Audit flow logs configuration for every virtual network'; '27960feb-a23c-4577-8d36-ef8b5f35e0be' = 'All flow log resources should be in enabled state' }
    ResourceTypes = @('Microsoft.Network/virtualNetworks')
    Evaluate      = {
        param($Record)
        if (-not (Test-FlowLogsCollected)) { return New-Unknown 'Flow logs could not be read from Network Watcher' }
        $flowLogs = @(Get-FlowLogs | Where-Object { $_.properties.enabled })
        $targets = @{}
        foreach ($flowLog in $flowLogs) { $targets[([string]$flowLog.properties.targetResourceId).ToLowerInvariant()] = $flowLog }
        $vnetId = $Record.id.ToLowerInvariant()
        if ($targets.ContainsKey($vnetId)) { return New-Pass 'Virtual network flow log enabled' ([ordered]@{ flowLog = $targets[$vnetId].name }) }
        $subnets = @($Record.resource.properties.subnets | Where-Object { $_ })
        if (-not $subnets) { return New-NotApplicable 'The virtual network has no subnets, so there is no traffic to log' ([ordered]@{ subnets = 0 }) }
        $uncovered = @($subnets | Where-Object {
                $subnetCovered = $targets.ContainsKey($_.id.ToLowerInvariant())
                $nsg = $_.properties.networkSecurityGroup.id
                -not ($subnetCovered -or ($nsg -and $targets.ContainsKey($nsg.ToLowerInvariant())))
            } | ForEach-Object name)
        $evidence = [ordered]@{ subnetsWithoutFlowLogs = $uncovered }
        if (-not $uncovered) { return New-Pass 'All subnets are covered by subnet or NSG flow logs' $evidence }
        New-Fail 'No virtual network flow log' $evidence
    }
}

#CIS numbers the two flow log kinds separately (retention 7.5 NSG / 7.8 virtual network, Log Analytics 6.1.1.5 / 6.1.1.6),
#so each kind gets its own test and a control is never judged on flow logs it does not cover
$flowLogKinds = @(
    @{ Kind = 'Vnet'; Label = 'Virtual network'; RetentionId = 'AZ-LOG-019'; RetentionCis = '7.8'; AnalyticsId = 'AZ-LOG-020'; AnalyticsCis = '6.1.1.6' }
    @{ Kind = 'Nsg'; Label = 'Network security group'; RetentionId = 'AZ-LOG-022'; RetentionCis = '7.5'; AnalyticsId = 'AZ-LOG-023'; AnalyticsCis = '6.1.1.5' }
)

foreach ($flow in $flowLogKinds) {
    Add-AzTest @{
        Id          = $flow.RetentionId
        Version     = 2
        Title       = "$($flow.Label) flow logs are retained for at least 90 days"
        Category    = 'Logging and threat detection'
        Service     = 'Network Watcher'
        Severity    = 'Low'
        Description = "Checks the storage retention policy of $($flow.Label.ToLowerInvariant()) flow logs (0 days means retained indefinitely)."
        Rationale   = 'Network evidence is needed for incidents that are detected long after the initial access.'
        Remediation = 'Set the flow log retention to 90 days or more (az network watcher flow-log update --retention 90 ...), or retain the data in Log Analytics through traffic analytics.'
        References  = @('https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-manage')
        Frameworks  = @{ MCSB = 'LT-6'; CIS = $flow.RetentionCis }
        Config      = $flow
        Run         = {
            param($Test)
            if (-not (Test-FlowLogsCollected)) { return New-SubscriptionFinding (New-Unknown 'Flow logs could not be read from Network Watcher') }
            $flowLogs = @(Get-FlowLogs -Kind $Test.Config.Kind)
            if (-not $flowLogs) { return New-SubscriptionFinding (New-NotApplicable "No $($Test.Config.Label.ToLowerInvariant()) flow logs") }
            foreach ($flowLog in $flowLogs) {
                $policy = $flowLog.properties.retentionPolicy
                $days = [int]$policy.days
                $evidence = [ordered]@{ target = $flowLog.properties.targetResourceId; retentionEnabled = [bool]$policy.enabled; days = $days }
                $result = if (-not $policy.enabled -or $days -eq 0 -or $days -ge 90) { New-Pass $(if (-not $policy.enabled -or $days -eq 0) { 'Retained indefinitely' } else { "$days days retention" }) $evidence } else { New-Fail "$days days retention" $evidence }
                New-Finding -ResourceId $flowLog.id -ResourceType $flowLog.type -ResourceName $flowLog.name -Result $result
            }
        }
    }

    Add-AzTest @{
        Id          = $flow.AnalyticsId
        Version     = 2
        Title       = "$($flow.Label) flow logs are sent to Log Analytics with traffic analytics"
        Category    = 'Logging and threat detection'
        Service     = 'Network Watcher'
        Severity    = 'Low'
        Description = "Checks that $($flow.Label.ToLowerInvariant()) flow logs have traffic analytics enabled, which sends processed flow data to a Log Analytics workspace."
        Rationale   = 'Flow logs in a storage account are hard to query during an incident. Traffic analytics makes flows searchable and highlights malicious and unusual traffic.'
        Remediation = 'Enable traffic analytics on each flow log with a Log Analytics workspace and a 10 minute processing interval.'
        References  = @('https://learn.microsoft.com/azure/network-watcher/traffic-analytics')
        Frameworks  = @{ MCSB = @('LT-4', 'LT-5'); CIS = $flow.AnalyticsCis }
        Policy      = @{ '2f080164-9f4d-497e-9db6-416dc9f7b48a' = 'Network Watcher flow logs should have traffic analytics enabled' }
        Config      = $flow
        Run         = {
            param($Test)
            if (-not (Test-FlowLogsCollected)) { return New-SubscriptionFinding (New-Unknown 'Flow logs could not be read from Network Watcher') }
            $flowLogs = @(Get-FlowLogs -Kind $Test.Config.Kind)
            if (-not $flowLogs) { return New-SubscriptionFinding (New-NotApplicable "No $($Test.Config.Label.ToLowerInvariant()) flow logs") }
            foreach ($flowLog in $flowLogs) {
                $analytics = $flowLog.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration
                $evidence = [ordered]@{ target = $flowLog.properties.targetResourceId; trafficAnalytics = [bool]$analytics.enabled; workspace = $analytics.workspaceResourceId }
                $result = if ($analytics.enabled) { New-Pass 'Traffic analytics enabled' $evidence } else { New-Fail 'Traffic analytics is not enabled' $evidence }
                New-Finding -ResourceId $flowLog.id -ResourceType $flowLog.type -ResourceName $flowLog.name -Result $result
            }
        }
    }
}

function Get-ActivityLogRetention {
    #how long one activity log destination keeps the log: Status Pass (365 days or more), Fail or Unknown, with a Detail
    param($Setting)
    $p = $Setting.properties
    $outcome = { param([string]$Status, [string]$Detail) [pscustomobject]@{ Setting = $Setting.name; Status = $Status; Detail = $Detail } }
    $results = @()
    if ($p.workspaceId) {
        $workspace = Get-AzResourceRecord -Id $p.workspaceId
        $name = Get-ResourceName $p.workspaceId
        if (-not $workspace) { $results += & $outcome 'Unknown' "workspace $name is not in this subscription or could not be read" }
        else {
            $days = [int]$workspace.resource.properties.retentionInDays
            if ($days -ge 365) { $results += & $outcome 'Pass' "workspace $name keeps $days days" }
            elseif (Test-ChildCollected $workspace 'tables') {
                $table = @(Get-Child $workspace 'tables' | Where-Object { $_ -and $_.name -eq 'AzureActivity' }) | Select-Object -First 1
                $total = if ($table.properties.totalRetentionInDays) { [int]$table.properties.totalRetentionInDays } else { $days }
                $status = if ($total -ge 365) { 'Pass' } else { 'Fail' }
                $results += & $outcome $status "the AzureActivity table in workspace $name keeps $total days"
            } else { $results += & $outcome 'Unknown' "workspace $name keeps $days days, and its table retention could not be read" }
        }
    }
    if ($p.storageAccountId) {
        $account = Get-AzResourceRecord -Id $p.storageAccountId
        $name = Get-ResourceName $p.storageAccountId
        if (-not $account) { $results += & $outcome 'Unknown' "storage account $name is not in this subscription or could not be read" }
        elseif (Test-ChildCollected $account 'managementPolicies/default') {
            #lifecycle rules that delete append blobs in the insights-activity-logs container
            $deleteAfter = @(foreach ($rule in @((Get-Child $account 'managementPolicies/default').properties.policy.rules | Where-Object { $_ -and $_.enabled -ne $false })) {
                    $filters = $rule.definition.filters
                    $types = @($filters.blobTypes | Where-Object { $_ })
                    if ($types -and 'appendBlob' -notin $types) { continue }
                    $prefixes = @($filters.prefixMatch | Where-Object { $_ })
                    if ($prefixes -and -not ($prefixes | Where-Object { 'insights-activity-logs/'.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) -or $_.StartsWith('insights-activity-logs/', [System.StringComparison]::OrdinalIgnoreCase) })) { continue }
                    $delete = $rule.definition.actions.baseBlob.delete
                    foreach ($value in @($delete.daysAfterModificationGreaterThan, $delete.daysAfterCreationGreaterThan)) { if ($null -ne $value) { [int]$value } }
                }) | Sort-Object
            if ($deleteAfter -and $deleteAfter[0] -lt 365) { $results += & $outcome 'Fail' "a lifecycle rule on storage account $name deletes it after $($deleteAfter[0]) days" }
            else { $results += & $outcome 'Pass' "storage account $name keeps it (no lifecycle rule deletes it within a year)" }
        } elseif ((Get-ChildFailure $account 'managementPolicies/default') -eq 404) { $results += & $outcome 'Pass' "storage account $name keeps it (no lifecycle management policy)" }
        else { $results += & $outcome 'Unknown' "the lifecycle management policy of storage account $name could not be read" }
    }
    if ($p.eventHubAuthorizationRuleId -or $p.marketplacePartnerId) { $results += & $outcome 'Unknown' 'an event hub or partner solution receives it; retention is set in the receiving system' }
    return $results
}

Add-AzTest @{
    Id          = 'AZ-LOG-024'
    Title       = 'The activity log is kept for at least a year'
    Category    = 'Logging and threat detection'
    Service     = 'Azure Monitor'
    Severity    = 'Low'
    Description = 'Follows the activity log diagnostic settings to their destinations and checks that at least one keeps the log for 365 days or more: the Log Analytics workspace (or its AzureActivity table), or the storage account and its lifecycle rules.'
    Rationale   = 'Azure keeps the activity log for 90 days. Investigating an incident found months later, and showing who changed what over a year, needs the control plane history kept longer.'
    Remediation = 'Keep the AzureActivity table for at least a year (workspace retention or table level total retention), or archive the activity log to a storage account without a lifecycle rule that deletes it earlier, ideally with an immutability policy.'
    References  = @('https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-configure', 'https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log')
    Frameworks  = @{ MCSB = 'LT-6' }
    Requires    = @('subscription/diagnosticSettings')
    Run         = {
        $settings = @(Get-ActivityLogSettings | Sort-Object name)
        if (-not $settings) { return New-SubscriptionFinding (New-Fail 'The activity log is not exported, so Azure keeps it for 90 days only') }
        $outcomes = @(foreach ($setting in $settings) { Get-ActivityLogRetention $setting })
        $evidence = [ordered]@{ destinations = @($outcomes | ForEach-Object { "$($_.Setting): $($_.Detail)" }) }
        $kept = @($outcomes | Where-Object Status -eq 'Pass') | Select-Object -First 1
        if ($kept) { return New-SubscriptionFinding (New-Pass "Kept for a year or more: $($kept.Detail)" $evidence) }
        $unknown = @($outcomes | Where-Object Status -eq 'Unknown') | Select-Object -First 1
        if ($unknown) { return New-SubscriptionFinding (New-Unknown "No destination is known to keep it for a year: $($unknown.Detail)" $evidence) }
        New-SubscriptionFinding (New-Fail "No destination keeps it for a year: $(@($outcomes | ForEach-Object Detail) -join '; ')" $evidence)
    }
}
