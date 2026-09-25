#Microsoft Defender for Cloud: plans, components, notifications and alerts

function Get-DefenderPricing {
    param([string]$Name)
    return @(Get-IngestData 'defender/pricings') | Where-Object { $_ -and $_.name -eq $Name } | Select-Object -First 1
}

function Get-PricingExtension {
    param($Pricing, [string]$Name)
    return @($Pricing.properties.extensions) | Where-Object { $_ -and $_.name -eq $Name } | Select-Object -First 1
}

#one test per plan; Override returns $true/$false when a resource enables or disables protection itself, $null when it follows the plan
$defenderPlans = @(
    @{ Id = 'AZ-DEF-001'; Plan = 'CloudPosture'; Name = 'Defender CSPM'; Severity = 'Medium'; Always = $true
        Policy = @{ '1f90fc71-a595-4066-8974-d4d0802e8ef0' = 'Microsoft Defender CSPM should be enabled' }
        Why = 'Defender CSPM adds attack path analysis, the cloud security explorer, agentless scanning and data security posture management on top of the free foundational posture.' }
    @{ Id = 'AZ-DEF-002'; Plan = 'VirtualMachines'; Name = 'Defender for Servers'; Severity = 'High'
        Types = @('Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets', 'Microsoft.HybridCompute/machines')
        Policy = @{ '4da35fc9-c9e7-4960-aec9-797fe7d9051d' = 'Azure Defender for servers should be enabled' }
        Why = 'Defender for Servers provides Microsoft Defender for Endpoint (EDR), vulnerability management and threat detection for virtual machines and Arc machines.' }
    @{ Id = 'AZ-DEF-003'; Plan = 'Containers'; Name = 'Defender for Containers'; Severity = 'High'; Legacy = @('KubernetesService', 'ContainerRegistry')
        Types = @('Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerRegistry/registries', 'Microsoft.Kubernetes/connectedClusters')
        Policy = @{ '1c988dd6-ade4-430f-a608-2a3e5b0a6d38' = 'Microsoft Defender for Containers should be enabled' }
        Why = 'Defender for Containers provides runtime threat detection for Kubernetes and vulnerability assessment of container images.' }
    @{ Id = 'AZ-DEF-004'; Plan = 'StorageAccounts'; Name = 'Defender for Storage'; Severity = 'High'
        Types = @('Microsoft.Storage/storageAccounts')
        Policy = @{ '640d2586-54d2-465f-877f-9ffc1d2109f4' = 'Microsoft Defender for Storage should be enabled' }
        Why = 'Defender for Storage detects unusual access, data exfiltration and malware uploads to storage accounts.'
        Override = {
            param($Record)
            $setting = Get-Child $Record 'providers/Microsoft.Security/defenderForStorageSettings/current'
            if ($setting -and $setting.properties.overrideSubscriptionLevelSettings) { return [bool]$setting.properties.isEnabled }
            return $null
        } }
    @{ Id = 'AZ-DEF-005'; Plan = 'AppServices'; Name = 'Defender for App Service'; Severity = 'Medium'
        Types = @('Microsoft.Web/sites')
        Policy = @{ '2913021d-f2fd-4f3d-b958-22354e2bdbcb' = 'Azure Defender for App Service should be enabled' }
        Why = 'Defender for App Service detects attacks against web applications and dangling DNS entries of decommissioned apps.' }
    @{ Id = 'AZ-DEF-006'; Plan = 'CosmosDbs'; Name = 'Defender for Azure Cosmos DB'; Severity = 'Medium'
        Types = @('Microsoft.DocumentDB/databaseAccounts')
        Policy = @{ 'adbe85b5-83e6-4350-ab58-bf3a4f736e5e' = 'Microsoft Defender for Azure Cosmos DB should be enabled' }
        Why = 'Defender for Azure Cosmos DB detects SQL injection, anomalous access and data exfiltration attempts.'
        Override = {
            param($Record)
            $setting = Get-Child $Record 'providers/Microsoft.Security/advancedThreatProtectionSettings/current'
            if ($setting -and $setting.properties.isEnabled) { return $true }
            return $null
        } }
    @{ Id = 'AZ-DEF-007'; Plan = 'OpenSourceRelationalDatabases'; Name = 'Defender for open-source relational databases'; Severity = 'Medium'
        Types = @('Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforPostgreSQL/servers', 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforMySQL/servers')
        Policy = @{ '0a9fbe0d-c5c4-4da8-87d8-f4fd77338835' = 'Azure Defender for open-source relational databases should be enabled' }
        Why = 'Defender for open-source relational databases detects brute force, anomalous access and suspicious queries on PostgreSQL and MySQL servers.'
        Override = {
            param($Record)
            $setting = @(Get-Child $Record 'advancedThreatProtectionSettings') | Where-Object { $_ } | Select-Object -First 1
            if ($setting -and $setting.properties.state -eq 'Enabled') { return $true }
            return $null
        } }
    @{ Id = 'AZ-DEF-008'; Plan = 'SqlServers'; Name = 'Defender for Azure SQL'; Severity = 'High'
        Types = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances', 'Microsoft.Synapse/workspaces')
        Policy = @{ '7fe3b40f-802b-4cdd-8bd4-fd799c948cc2' = 'Azure Defender for Azure SQL Database servers should be enabled'; 'abfb4388-5bf4-4ad7-ba82-2cd2f41ceae9' = 'Azure Defender for SQL should be enabled for unprotected Azure SQL servers'; 'abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9' = 'Azure Defender for SQL should be enabled for unprotected SQL Managed Instances' }
        Why = 'Defender for SQL provides vulnerability assessment and detects SQL injection, brute force and anomalous database access.'
        Override = {
            param($Record)
            $setting = @(Get-Child $Record 'advancedThreatProtectionSettings') + @(Get-Child $Record 'securityAlertPolicies') | Where-Object { $_ -and $_.properties.state -eq 'Enabled' } | Select-Object -First 1
            if ($setting) { return $true }
            return $null
        } }
    @{ Id = 'AZ-DEF-009'; Plan = 'SqlServerVirtualMachines'; Name = 'Defender for SQL servers on machines'; Severity = 'Medium'
        Types = @('Microsoft.SqlVirtualMachine/sqlVirtualMachines', 'Microsoft.AzureArcData/sqlServerInstances')
        Policy = @{ '6581d072-105e-4418-827f-bd446d56421b' = 'Azure Defender for SQL servers on machines should be enabled' }
        Why = 'Defender for SQL servers on machines protects SQL Server running on virtual machines and Arc enabled servers.' }
    @{ Id = 'AZ-DEF-010'; Plan = 'KeyVaults'; Name = 'Defender for Key Vault'; Severity = 'Medium'
        Types = @('Microsoft.KeyVault/vaults')
        Policy = @{ '0e6763cc-5078-4e64-889d-ff4d9a839047' = 'Azure Defender for Key Vault should be enabled' }
        Why = 'Defender for Key Vault detects unusual and potentially harmful access to secrets, keys and certificates.' }
    @{ Id = 'AZ-DEF-011'; Plan = 'Arm'; Name = 'Defender for Resource Manager'; Severity = 'Medium'; Always = $true
        Policy = @{ 'c3d20c29-b36d-48fe-808b-99a87530ad99' = 'Azure Defender for Resource Manager should be enabled' }
        Why = 'Defender for Resource Manager detects suspicious management operations such as the use of exploitation toolkits, unusual role assignments and suspicious control plane access.' }
    @{ Id = 'AZ-DEF-012'; Plan = 'Api'; Name = 'Defender for APIs'; Severity = 'Low'
        Types = @('Microsoft.ApiManagement/service')
        Policy = @{ '7926a6d1-b268-4586-8197-e8ae90c877d7' = 'Microsoft Defender for APIs should be enabled' }
        Why = 'Defender for APIs inventories APIs published through API Management and detects attacks against them.' }
    @{ Id = 'AZ-DEF-013'; Plan = 'AI'; Name = 'Defender for AI services'; Severity = 'Medium'
        Types = @('Microsoft.CognitiveServices/accounts')
        Why = 'Defender for AI services detects prompt injection (jailbreak), data leakage and credential theft attempts against Azure OpenAI and AI services.' }
)

foreach ($plan in $defenderPlans) {
    Add-AzTest @{
        Id          = $plan.Id
        Title       = "Microsoft $($plan.Name) is enabled"
        Category    = 'Logging and threat detection'
        Service     = 'Microsoft Defender for Cloud'
        Severity    = $plan.Severity
        Description = if ($plan.Always) { "Checks that the $($plan.Name) plan is enabled on the subscription." } else { "Checks that the $($plan.Name) plan is enabled, and that each resource it protects is covered by the plan or by protection enabled on the resource itself." }
        Rationale   = $plan.Why
        Remediation = "Enable the plan in Defender for Cloud > Environment settings > <subscription> > Defender plans (az security pricing create --name $($plan.Plan) --tier Standard)."
        References  = @('https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction')
        Policy      = $plan.Policy
        Requires    = @('defender/pricings')
        Config      = $plan
        Run         = {
            param($Test)
            $planCopy = $Test.Config
            $pricing = Get-DefenderPricing $planCopy.Plan
            $standard = $pricing.properties.pricingTier -eq 'Standard'
            $legacy = @($planCopy.Legacy | Where-Object { $_ } | Where-Object { (Get-DefenderPricing $_).properties.pricingTier -eq 'Standard' })
            $evidence = [ordered]@{ plan = $planCopy.Plan; pricingTier = $pricing.properties.pricingTier; subPlan = $pricing.properties.subPlan; enabledLegacyPlans = $legacy }
            if (-not $pricing) { return New-SubscriptionFinding (New-Unknown "Plan $($planCopy.Plan) was not returned by the pricings API" $evidence) }
            if ($planCopy.Always) {
                if ($standard) { return New-SubscriptionFinding (New-Pass "$($planCopy.Name) is enabled" $evidence) }
                return New-SubscriptionFinding (New-Fail "$($planCopy.Name) is not enabled" $evidence)
            }
            $records = @(Get-AzResourceRecords -Type $planCopy.Types)
            if (-not $records) {
                if ($standard) { return New-SubscriptionFinding (New-Pass "$($planCopy.Name) is enabled (no resources in scope yet)" $evidence) }
                return New-SubscriptionFinding (New-NotApplicable "$($planCopy.Name) is off and there are no resources it would protect" $evidence)
            }
            foreach ($record in $records) {
                $override = if ($planCopy.Override) { & $planCopy.Override $record } else { $null }
                $resourceEvidence = [ordered]@{ planTier = $pricing.properties.pricingTier; resourceLevelProtection = $override }
                $result = if ($override -eq $false) { New-Fail 'Protection is disabled on the resource, overriding the subscription plan' $resourceEvidence }
                elseif ($standard -or $legacy) { New-Pass "Protected by the $($planCopy.Name) plan" $resourceEvidence }
                elseif ($override -eq $true) { New-Pass 'Protection is enabled on the resource' $resourceEvidence }
                else { New-Fail "Not protected: the $($planCopy.Name) plan is off" $resourceEvidence }
                New-Finding -Record $record -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-014'
    Title       = 'Defender for Servers endpoint protection (Defender for Endpoint integration) is on'
    Category    = 'Endpoint security'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'High'
    Description = 'Checks the WDATP integration setting that deploys Microsoft Defender for Endpoint to machines protected by Defender for Servers.'
    Rationale   = 'Endpoint detection and response on servers is the primary control against malware, ransomware and hands-on-keyboard attacks; without the integration the Servers plan does not deploy it.'
    Remediation = "Enable 'Endpoint protection' under Defender plans > Servers > Settings (security setting WDATP set to enabled)."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/integration-defender-for-endpoint')
    Requires    = @('defender/settings', 'defender/pricings')
    Run         = {
        $setting = @(Get-IngestData 'defender/settings') | Where-Object { $_ -and $_.name -eq 'WDATP' } | Select-Object -First 1
        $servers = (Get-DefenderPricing 'VirtualMachines').properties.pricingTier
        $evidence = [ordered]@{ wdatpEnabled = [bool]$setting.properties.enabled; serversPlan = $servers }
        if (-not $setting) { return New-SubscriptionFinding (New-Unknown 'The WDATP setting was not returned' $evidence) }
        if (-not $setting.properties.enabled) { return New-SubscriptionFinding (New-Fail 'Defender for Endpoint integration is off' $evidence) }
        if ($servers -ne 'Standard') { return New-SubscriptionFinding (New-Fail 'Defender for Endpoint integration is on but Defender for Servers is off, so nothing is deployed' $evidence) }
        New-SubscriptionFinding (New-Pass 'Defender for Endpoint integration is on' $evidence)
    }
}

$defenderServerComponents = @(
    @{ Id = 'AZ-DEF-015'; Extension = 'AgentlessVmScanning'; Name = 'Agentless scanning for machines'; Severity = 'Medium'
        Why = 'Agentless scanning inspects disk snapshots for vulnerabilities, secrets and malware without an agent, including machines where agents are missing or broken.' }
    @{ Id = 'AZ-DEF-016'; Extension = 'FileIntegrityMonitoring'; Name = 'File integrity monitoring'; Severity = 'Low'
        Why = 'File integrity monitoring detects changes to operating system files, registry keys and application binaries that indicate compromise or unauthorized change.' }
)
foreach ($component in $defenderServerComponents) {
    Add-AzTest @{
        Id          = $component.Id
        Title       = "Defender for Servers component '$($component.Name)' is on"
        Category    = 'Posture and vulnerability management'
        Service     = 'Microsoft Defender for Cloud'
        Severity    = $component.Severity
        Description = "Checks that the $($component.Name) extension of the Defender for Servers plan (or Defender CSPM for agentless scanning) is enabled."
        Rationale   = $component.Why
        Remediation = "Enable '$($component.Name)' under Defender plans > Servers > Settings (requires Defender for Servers Plan 2)."
        References  = @('https://learn.microsoft.com/azure/defender-for-cloud/defender-for-servers-overview')
        Requires    = @('defender/pricings')
        Config      = $component
        Run         = {
            param($Test)
            $componentCopy = $Test.Config
            $sources = @('VirtualMachines')
            if ($componentCopy.Extension -eq 'AgentlessVmScanning') { $sources += 'CloudPosture' }
            $enabledIn = @($sources | Where-Object {
                    $pricing = Get-DefenderPricing $_
                    $extension = Get-PricingExtension $pricing $componentCopy.Extension
                    $pricing.properties.pricingTier -eq 'Standard' -and $extension -and $extension.isEnabled -eq 'True'
                })
            $evidence = [ordered]@{ enabledIn = $enabledIn; serversPlan = (Get-DefenderPricing 'VirtualMachines').properties.pricingTier; serversSubPlan = (Get-DefenderPricing 'VirtualMachines').properties.subPlan }
            if ($enabledIn) { return New-SubscriptionFinding (New-Pass "$($componentCopy.Name) is on ($($enabledIn -join ', '))" $evidence) }
            New-SubscriptionFinding (New-Fail "$($componentCopy.Name) is off" $evidence)
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-017'
    Version     = 2
    Title       = 'Vulnerability assessment for machines is configured'
    Category    = 'Posture and vulnerability management'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Medium'
    Description = 'Checks that Defender for Servers is on and that a vulnerability assessment provider (Microsoft Defender Vulnerability Management) covers machines. Both Plan 1 and Plan 2 include Defender Vulnerability Management.'
    Rationale   = 'Unknown vulnerabilities cannot be prioritized or patched. Built-in vulnerability management continuously finds missing patches and vulnerable software on servers.'
    Remediation = "Enable Defender for Servers and set 'Vulnerability assessment for machines' to Microsoft Defender Vulnerability Management."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management')
    Policy      = @{ '501541f7-f7e7-4cd6-868c-4190fdad3ac9' = 'A vulnerability assessment solution should be enabled on your virtual machines' }
    Requires    = @('defender/pricings')
    Run         = {
        $servers = Get-DefenderPricing 'VirtualMachines'
        $evidence = [ordered]@{ serversPlan = $servers.properties.pricingTier; serversSubPlan = $servers.properties.subPlan }
        if ($servers.properties.pricingTier -ne 'Standard') { return New-SubscriptionFinding (New-Fail 'Defender for Servers is off, so no vulnerability assessment runs' $evidence) }
        #both Defender for Servers plans include Defender Vulnerability Management, so the plan itself already satisfies this
        if ($servers.properties.subPlan -in 'P1', 'P2') { return New-SubscriptionFinding (New-Pass "Defender for Servers $($servers.properties.subPlan) includes Defender Vulnerability Management" $evidence) }
        if (-not (Test-IngestSection 'defender/serverVulnerabilityAssessmentsSettings')) { return New-SubscriptionFinding (New-Unknown 'The vulnerability assessment setting could not be read and the plan does not report a sub plan' $evidence) }
        $setting = @(Get-IngestData 'defender/serverVulnerabilityAssessmentsSettings') | Where-Object { $_ } | Select-Object -First 1
        $evidence.selectedProvider = $setting.properties.selectedProvider
        if ($evidence.selectedProvider) { return New-SubscriptionFinding (New-Pass "Vulnerability assessment provider $($evidence.selectedProvider)" $evidence) }
        New-SubscriptionFinding (New-Fail 'No vulnerability assessment provider is selected' $evidence)
    }
}

function Get-SecurityContact {
    return @(Get-IngestData 'defender/securityContacts') | Where-Object { $_ } | Select-Object -First 1
}

Add-AzTest @{
    Id          = 'AZ-DEF-018'
    Title       = 'A security contact email address is configured'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Medium'
    Description = 'Checks that Defender for Cloud email notifications have at least one additional email address.'
    Rationale   = 'Microsoft and Defender for Cloud use the security contact to report compromised resources and high severity alerts. Without it, notifications may reach nobody who acts on them.'
    Remediation = "Set 'Additional email addresses' (a monitored security team mailbox) under Defender for Cloud > Environment settings > Email notifications."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications')
    Requires    = @('defender/securityContacts')
    Run         = {
        $contact = Get-SecurityContact
        $emails = @(([string]$contact.properties.emails) -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $evidence = [ordered]@{ emails = $emails; isEnabled = $contact.properties.isEnabled }
        if ($emails) { return New-SubscriptionFinding (New-Pass "$($emails.Count) security contact address(es)" $evidence) }
        New-SubscriptionFinding (New-Fail 'No security contact email address' $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-019'
    Title       = 'Security alert notifications are sent to subscription owners'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Low'
    Description = "Checks that Defender for Cloud notifies users with the Owner role about alerts."
    Rationale   = 'Owners are accountable for the subscription and must know when its resources are attacked, especially when no central SOC monitors the alerts.'
    Remediation = "Under Email notifications, select 'Owner' in 'All users with the following roles'."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications')
    Policy      = @{ '0b15565f-aa9e-48ba-8619-45960f2c314d' = 'Email notification to subscription owner for high severity alerts should be enabled' }
    Requires    = @('defender/securityContacts')
    Run         = {
        $byRole = (Get-SecurityContact).properties.notificationsByRole
        $evidence = [ordered]@{ state = $byRole.state; roles = @($byRole.roles) }
        if ($byRole.state -eq 'On' -and @($byRole.roles) -contains 'Owner') { return New-SubscriptionFinding (New-Pass 'Owners are notified' $evidence) }
        New-SubscriptionFinding (New-Fail 'Owners are not notified about alerts' $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-020'
    Title       = 'Email notifications for security alerts are enabled'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Medium'
    Description = 'Checks that Defender for Cloud sends email notifications for alerts with a minimum severity of High or lower.'
    Rationale   = 'Alert emails are the minimum notification path so that detected attacks are acted upon quickly.'
    Remediation = "Under Email notifications, enable 'Notify about alerts with the following severity (or higher)' and select High (or Medium)."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications')
    Policy      = @{ '6e2593d9-add6-4083-9c9b-4b7d2188c899' = 'Email notification for high severity alerts should be enabled' }
    Requires    = @('defender/securityContacts')
    Run         = {
        $contact = Get-SecurityContact
        $source = @($contact.properties.notificationsSources) | Where-Object { $_ -and $_.sourceType -eq 'Alert' } | Select-Object -First 1
        $evidence = [ordered]@{ isEnabled = $contact.properties.isEnabled; minimalSeverity = $source.minimalSeverity }
        if ($contact.properties.isEnabled -and $source.minimalSeverity -in 'High', 'Medium', 'Low') { return New-SubscriptionFinding (New-Pass "Alert emails for severity $($source.minimalSeverity) and higher" $evidence) }
        New-SubscriptionFinding (New-Fail 'Alert email notifications are not enabled' $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-021'
    Title       = 'Email notifications for attack paths are enabled'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Low'
    Description = 'Checks that Defender for Cloud sends email notifications for attack paths with a minimum risk level.'
    Rationale   = 'Attack paths show exploitable chains from the internet to critical resources. Notifications make sure new high risk paths are handled promptly.'
    Remediation = "Under Email notifications, enable 'Notify about attack paths with the following risk level (or higher)' (requires Defender CSPM)."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications')
    Requires    = @('defender/securityContacts')
    Run         = {
        $contact = Get-SecurityContact
        $source = @($contact.properties.notificationsSources) | Where-Object { $_ -and $_.sourceType -eq 'AttackPath' } | Select-Object -First 1
        $evidence = [ordered]@{ isEnabled = $contact.properties.isEnabled; minimalRiskLevel = $source.minimalRiskLevel }
        if ($contact.properties.isEnabled -and $source.minimalRiskLevel) { return New-SubscriptionFinding (New-Pass "Attack path emails for risk level $($source.minimalRiskLevel) and higher" $evidence) }
        New-SubscriptionFinding (New-Fail 'Attack path notifications are not enabled' $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-022'
    Title       = 'No active high severity security alerts'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'High'
    Description = 'Lists Defender for Cloud alerts with severity High that are still active (not resolved or dismissed).'
    Rationale   = 'An active high severity alert may be an ongoing compromise. Alerts must be triaged, investigated and closed.'
    Remediation = 'Investigate each alert (Defender for Cloud > Security alerts, or the Defender portal incidents), contain and remediate, then resolve or dismiss it with a reason.'
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/managing-and-responding-alerts')
    Requires    = @('defender/alerts')
    Run         = {
        $alerts = @(Get-IngestData 'defender/alerts' | Where-Object { $_ -and $_.properties.severity -eq 'High' -and $_.properties.status -eq 'Active' })
        if (-not $alerts) { return New-SubscriptionFinding (New-Pass 'No active high severity alerts') }
        foreach ($alert in $alerts) {
            $p = $alert.properties
            $evidence = [ordered]@{ alert = $p.alertDisplayName; startTime = Format-UtcDate $p.startTimeUtc; compromisedEntity = $p.compromisedEntity; resource = @($p.resourceIdentifiers | ForEach-Object { $_.azureResourceId } | Where-Object { $_ }) }
            New-Finding -ResourceId $alert.id -ResourceType $alert.type -ResourceName $p.alertDisplayName -Result (New-Fail "$($p.alertDisplayName) on $($p.compromisedEntity) since $($evidence.startTime)" $evidence)
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-024'
    Title       = 'Sensitive data discovery is enabled'
    Category    = 'Data protection'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Medium'
    Description = 'Checks the sensitive data discovery extension of Defender CSPM or Defender for Storage.'
    Rationale   = 'Knowing where sensitive data lives drives the prioritization of attack paths, alerts and protection; sensitive data discovery classifies data in storage and databases automatically.'
    Remediation = "Enable 'Sensitive data discovery' in the Defender CSPM or Defender for Storage plan settings."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/concept-data-security-posture')
    Requires    = @('defender/pricings')
    Run         = {
        $enabledIn = @('CloudPosture', 'StorageAccounts' | Where-Object {
                $pricing = Get-DefenderPricing $_
                $extension = Get-PricingExtension $pricing 'SensitiveDataDiscovery'
                $pricing.properties.pricingTier -eq 'Standard' -and $extension.isEnabled -eq 'True'
            })
        $evidence = [ordered]@{ enabledIn = $enabledIn }
        if ($enabledIn) { return New-SubscriptionFinding (New-Pass "Sensitive data discovery on ($($enabledIn -join ', '))" $evidence) }
        New-SubscriptionFinding (New-Fail 'Sensitive data discovery is off' $evidence)
    }
}

Add-AzTest @{
    Id            = 'AZ-DEF-025'
    Version       = 2
    Title         = 'Defender for Storage malware scanning is enabled'
    Category      = 'Data protection'
    Service       = 'Microsoft Defender for Cloud'
    Severity      = 'Medium'
    Description   = 'Checks that on-upload malware scanning of Defender for Storage applies to each storage account (plan extension or account level override).'
    Rationale     = 'Storage accounts that receive files from users or partners are a malware distribution path; scanning on upload detects malicious content before it is consumed.'
    Remediation   = "Enable 'Malware scanning' in the Defender for Storage plan settings (with a monthly cap per account), or on the individual storage account."
    References    = @('https://learn.microsoft.com/azure/defender-for-cloud/on-upload-malware-scanning')
    Requires      = @('defender/pricings')
    ResourceTypes = @('Microsoft.Storage/storageAccounts')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'providers/Microsoft.Security/defenderForStorageSettings/current')) { return New-Unknown 'The Defender for Storage setting of the account could not be read' }
        $setting = (Get-Child $Record 'providers/Microsoft.Security/defenderForStorageSettings/current').properties
        $pricing = Get-DefenderPricing 'StorageAccounts'
        $planScanning = $pricing.properties.pricingTier -eq 'Standard' -and (Get-PricingExtension $pricing 'OnUploadMalwareScanning').isEnabled -eq 'True'
        $evidence = [ordered]@{ planMalwareScanning = $planScanning; accountOverride = [bool]$setting.overrideSubscriptionLevelSettings; accountMalwareScanning = $setting.malwareScanning.onUpload.isEnabled }
        $enabled = if ($setting.overrideSubscriptionLevelSettings) { $setting.isEnabled -and $setting.malwareScanning.onUpload.isEnabled } else { $planScanning }
        if ($enabled) { return New-Pass 'Malware scanning on upload enabled' $evidence }
        New-Fail 'No malware scanning on upload' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-DEF-023'
    Version     = 2
    Title       = 'Security alerts are forwarded to a SIEM or automation'
    Category    = 'Incident response'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Low'
    Description = 'Checks for a Defender for Cloud workflow automation or continuous export that handles security alerts, or the Microsoft Sentinel alert synchronization setting.'
    Rationale   = 'Alerts that stay in the portal depend on someone looking. Forwarding them to a SIEM, SOAR or ticketing flow makes sure every alert is triaged.'
    Remediation = 'Connect Defender for Cloud to Microsoft Sentinel (or your SIEM) through the Defender XDR connector or continuous export, or create a workflow automation for alerts.'
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/continuous-export')
    Requires    = @('defender/automations', 'defender/settings')
    Run         = {
        $automations = @(Get-IngestData 'defender/automations' | Where-Object { $_ -and $_.properties.isEnabled -and (@($_.properties.sources) | Where-Object { $_.eventSource -eq 'Alerts' }) })
        $sentinel = @(Get-IngestData 'defender/settings') | Where-Object { $_ -and $_.name -eq 'Sentinel' -and $_.properties.enabled }
        $evidence = [ordered]@{ alertAutomations = @($automations | ForEach-Object name | Sort-Object); sentinelAlertSync = [bool]$sentinel }
        if ($automations -or $sentinel) { return New-SubscriptionFinding (New-Pass 'Alerts are forwarded' $evidence) }
        New-SubscriptionFinding (New-Fail 'No alert export, automation or Sentinel synchronization configured for this subscription' $evidence)
    }
}
