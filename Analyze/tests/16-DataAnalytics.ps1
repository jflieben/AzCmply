#Data and analytics: Azure Databricks, Synapse Analytics, Data Factory and Azure Data Explorer

$databricksType = @('Microsoft.Databricks/workspaces')

Add-AzTest @{
    Id            = 'AZ-DBX-001'
    Title         = 'Databricks workspaces are deployed in a customer-managed virtual network'
    Category      = 'Network security'
    Service       = 'Azure Databricks'
    Severity      = 'Medium'
    Description   = 'Checks for VNet injection (customVirtualNetworkId) of Databricks workspaces.'
    Rationale     = 'VNet injection places cluster nodes in your own network, where NSGs, firewalls, private endpoints and flow logs control and record their traffic.'
    Remediation   = 'Deploy the workspace with VNet injection into dedicated host and container subnets (requires a new workspace).'
    References    = @('https://learn.microsoft.com/azure/databricks/security/network/classic/vnet-inject')
    Policy        = @{ '9c25c9e4-ee12-4882-afd2-11fb9d87893f' = 'Azure Databricks Workspaces should be in a virtual network' }
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        $vnet = $Record.resource.properties.parameters.customVirtualNetworkId.value
        if ($vnet) { return New-Pass 'VNet injected' ([ordered]@{ customVirtualNetworkId = $vnet }) }
        New-Fail 'Managed (Databricks) virtual network' ([ordered]@{ customVirtualNetworkId = $null })
    }
}

Add-AzTest @{
    Id            = 'AZ-DBX-006'
    Title         = 'Databricks subnets are associated with a network security group'
    Category      = 'Network security'
    Service       = 'Azure Databricks'
    Severity      = 'Medium'
    Description   = 'Checks the host and container subnets of VNet injected Databricks workspaces for an associated network security group. Workspaces on the Databricks managed virtual network are not applicable: Databricks manages their NSGs.'
    Rationale     = 'Databricks cluster nodes run customer code. Without an NSG on their subnets, that code can reach every address in the virtual network and its peers.'
    Remediation   = 'Associate the Databricks required NSG with both the host (public) and container (private) subnet of the workspace; Databricks manages the required rules within it.'
    References    = @('https://learn.microsoft.com/azure/databricks/security/network/classic/vnet-inject')
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        $parameters = $Record.resource.properties.parameters
        $vnetId = $parameters.customVirtualNetworkId.value
        if (-not $vnetId) { return New-NotApplicable 'Workspace uses the Databricks managed virtual network, whose NSGs are managed by Databricks' }
        $vnet = Get-AzResourceRecord $vnetId
        if (-not $vnet) { return New-Unknown "The injected virtual network $vnetId was not collected (it may live in another subscription)" ([ordered]@{ customVirtualNetworkId = $vnetId }) }
        $names = @($parameters.customPublicSubnetName.value, $parameters.customPrivateSubnetName.value) | Where-Object { $_ }
        $subnets = @($vnet.resource.properties.subnets | Where-Object { $_ -and (-not $names.Count -or $_.name -in $names) })
        if (-not $subnets) { return New-Unknown 'The Databricks subnets were not found in the injected virtual network' ([ordered]@{ customVirtualNetworkId = $vnetId; subnetNames = $names }) }
        $without = @($subnets | Where-Object { -not $_.properties.networkSecurityGroup.id } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ virtualNetwork = $vnet.resource.name; subnets = @($subnets | ForEach-Object name | Sort-Object); subnetsWithoutNsg = $without }
        if ($without) { return New-Fail "Databricks subnet(s) without a network security group: $($without -join ', ')" $evidence }
        New-Pass 'All Databricks subnets have a network security group' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-DBX-002'
    Title         = "Databricks clusters have no public IP addresses"
    Category      = 'Network security'
    Service       = 'Azure Databricks'
    Severity      = 'High'
    Description   = "Checks the 'No Public IP' (secure cluster connectivity) setting of Databricks workspaces."
    Rationale     = 'Without secure cluster connectivity every cluster node gets a public IP address and open inbound ports.'
    Remediation   = 'Enable secure cluster connectivity (No Public IP) on the workspace.'
    References    = @('https://learn.microsoft.com/azure/databricks/security/network/classic/secure-cluster-connectivity')
    Policy        = @{ '51c1490f-3319-459c-bbbc-7f391bbed753' = 'Azure Databricks Clusters should disable public IP' }
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.parameters.enableNoPublicIp.value
        if ($value -eq $true) { return New-Pass 'No public IP addresses' ([ordered]@{ enableNoPublicIp = $true }) }
        New-Fail 'Cluster nodes get public IP addresses' ([ordered]@{ enableNoPublicIp = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-DBX-003'
    Title         = 'Databricks workspaces disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Databricks'
    Severity      = 'Medium'
    Description   = 'Checks the public network access setting of Databricks workspaces.'
    Rationale     = 'A public workspace (web UI and REST API) can be reached with stolen tokens or credentials from anywhere.'
    Remediation   = 'Configure front-end private link and set public network access to Disabled.'
    References    = @('https://learn.microsoft.com/azure/databricks/security/network/front-end/front-end-private-connect')
    Policy        = @{ '0e7849de-b939-4c50-ab48-fc6b0f5eeba2' = 'Azure Databricks Workspaces should disable public network access' }
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.publicNetworkAccess
        if ($value -eq 'Disabled') { return New-Pass 'Public network access disabled' ([ordered]@{ publicNetworkAccess = $value }) }
        New-Fail 'Public network access enabled' ([ordered]@{ publicNetworkAccess = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-DBX-004'
    Title         = 'Databricks workspaces are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Azure Databricks'
    Severity      = 'Low'
    Description   = 'Checks Databricks workspaces for an approved private endpoint connection.'
    Rationale     = 'Private endpoints keep workspace and back-end traffic on private networks and enable disabling public access.'
    Remediation   = 'Create front-end and back-end private endpoints for the workspace.'
    References    = @('https://learn.microsoft.com/azure/databricks/security/network/classic/private-link')
    Policy        = @{ '258823f2-4595-4b52-b333-cc96192710d8' = 'Azure Databricks Workspaces should use private link' }
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        $connections = @($Record.resource.properties.privateEndpointConnections) + @(Get-Child $Record 'privateEndpointConnections') | Where-Object { $_ -and $_.properties.privateLinkServiceConnectionState.status -eq 'Approved' }
        $count = @($connections | ForEach-Object id | Sort-Object -Unique).Count
        if ($count) { return New-Pass "$count private endpoint(s)" ([ordered]@{ approvedPrivateEndpoints = $count }) }
        New-Fail 'No private endpoint' ([ordered]@{ approvedPrivateEndpoints = 0 })
    }
}

Add-AzTest @{
    Id            = 'AZ-DBX-005'
    Title         = 'Databricks diagnostic log delivery is configured'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Databricks'
    Severity      = 'Medium'
    Description   = 'Checks Databricks workspaces for a diagnostic setting that exports resource logs.'
    Rationale     = 'Databricks audit logs record logins, notebook and job activity, secret access and permission changes; without them misuse of the workspace goes unnoticed.'
    Remediation   = 'Create a diagnostic setting with all log categories to a Log Analytics workspace (requires the Premium tier).'
    References    = @('https://learn.microsoft.com/azure/databricks/admin/account-settings/audit-log-delivery')
    Policy        = @{ '138ff14d-b687-4faa-a81c-898c91a87fa2' = 'Resource logs in Azure Databricks Workspaces should be enabled' }
    ResourceTypes = $databricksType
    Evaluate      = {
        param($Record)
        if ($null -eq $Record.diagnosticSettings) { return New-Unknown 'Diagnostic settings could not be read' }
        if (Test-DiagnosticLogsEnabled -Settings $Record.diagnosticSettings) { return New-Pass 'Resource logs exported' }
        New-Fail 'No diagnostic log delivery'
    }
}

Add-AzTest @{
    Id            = 'AZ-SYN-001'
    Title         = 'Synapse workspaces use a managed virtual network with data exfiltration protection'
    Category      = 'Network security'
    Service       = 'Synapse Analytics'
    Severity      = 'Medium'
    Description   = 'Checks for the managed workspace virtual network with data exfiltration protection (outbound only to approved tenants).'
    Rationale     = 'Without exfiltration protection, Spark and pipeline code can send workspace data to any external destination or tenant.'
    Remediation   = 'Create the workspace with a managed virtual network and data exfiltration protection enabled (requires a new workspace), and list the approved tenants.'
    References    = @('https://learn.microsoft.com/azure/synapse-analytics/security/workspace-data-exfiltration-protection')
    Policy        = @{ '2d9dbfa3-927b-4cf0-9d0f-08747f971650' = 'Managed workspace virtual network on Azure Synapse workspaces should be enabled'; '3484ce98-c0c5-4c83-994b-c5ac24785218' = 'Azure Synapse workspaces should allow outbound data traffic only to approved targets' }
    ResourceTypes = @('Microsoft.Synapse/workspaces')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ managedVirtualNetwork = $p.managedVirtualNetwork; preventDataExfiltration = [bool]$p.managedVirtualNetworkSettings.preventDataExfiltration }
        if ($p.managedVirtualNetwork -and $p.managedVirtualNetworkSettings.preventDataExfiltration) { return New-Pass 'Managed virtual network with exfiltration protection' $evidence }
        New-Fail $(if (-not $p.managedVirtualNetwork) { 'No managed virtual network' } else { 'Data exfiltration protection disabled' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ADF-001'
    Title         = 'Data Factory linked services keep secrets in Key Vault'
    Category      = 'Identity management'
    Service       = 'Data Factory'
    Severity      = 'Medium'
    Description   = 'Finds linked services that store credentials in the factory (SecureString) instead of referencing Key Vault or using managed identity.'
    Rationale     = 'Credentials stored in Data Factory are not centrally rotated or audited and are available to every factory contributor through the linked service.'
    Remediation   = 'Use managed identity authentication where the connector supports it, otherwise store the secret in Key Vault and reference it with an AzureKeyVaultSecret.'
    References    = @('https://learn.microsoft.com/azure/data-factory/store-credentials-in-key-vault')
    Policy        = @{ '127ef6d7-242f-43b3-9eef-947faf1725d0' = 'Azure Data Factory linked services should use Key Vault for storing secrets' }
    ResourceTypes = @('Microsoft.DataFactory/factories')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'linkedservices')) { return New-Unknown 'Linked services could not be listed' }
        $stored = @(Get-Child $Record 'linkedservices' | Where-Object { $_ -and (($_.properties.typeProperties | ConvertTo-Json -Depth 20 -Compress) -match '"type":"SecureString"') } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ linkedServicesWithStoredSecrets = $stored }
        if ($stored) { return New-Fail "Linked service(s) with stored secrets: $($stored -join ', ')" $evidence }
        New-Pass 'No secrets stored in linked services' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ADF-002'
    Title         = 'Data Factory uses Git integration'
    Category      = 'Posture and vulnerability management'
    Service       = 'Data Factory'
    Severity      = 'Low'
    Description   = 'Checks for a Git repository configuration on data factories.'
    Rationale     = 'Git integration gives version history, review and controlled promotion of pipeline changes, instead of direct live edits that are hard to audit.'
    Remediation   = 'Connect the development factory to Azure DevOps or GitHub and deploy to production through CI/CD.'
    References    = @('https://learn.microsoft.com/azure/data-factory/source-control')
    Policy        = @{ '77d40665-3120-4348-b539-3192ec808307' = 'Azure Data Factory should use a Git repository for source control' }
    ResourceTypes = @('Microsoft.DataFactory/factories')
    Evaluate      = {
        param($Record)
        $repo = $Record.resource.properties.repoConfiguration
        if ($repo) { return New-Pass "Git integration ($($repo.type))" ([ordered]@{ repositoryType = $repo.type }) }
        New-Fail 'No Git integration' ([ordered]@{ repositoryType = $null })
    }
}

$kustoType = @('Microsoft.Kusto/clusters')

Add-AzTest @{
    Id            = 'AZ-ADX-001'
    Title         = 'Azure Data Explorer clusters disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Data Explorer'
    Severity      = 'Medium'
    Description   = 'Checks Azure Data Explorer clusters for disabled public network access and a SKU that supports private endpoints.'
    Rationale     = 'A public cluster endpoint accepts queries and ingestion from anywhere on the Internet, protected by authentication alone. Private endpoints keep analytics data and queries on private networks.'
    Remediation   = 'Create a private endpoint for the cluster (Standard or Basic tier), then set public network access to Disabled.'
    References    = @('https://learn.microsoft.com/azure/data-explorer/security-network-private-endpoint')
    ResourceTypes = $kustoType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; skuTier = $Record.resource.sku.tier }
        if ([string]$Record.resource.sku.tier -notin 'Standard', 'Basic') { return New-Fail "SKU tier $($Record.resource.sku.tier) does not support private endpoints" $evidence }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($p.publicNetworkAccess) { $p.publicNetworkAccess } else { 'Enabled (default)' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ADX-002'
    Title         = 'Azure Data Explorer clusters encrypt their disks'
    Category      = 'Data protection'
    Service       = 'Azure Data Explorer'
    Severity      = 'Medium'
    Description   = 'Checks Azure Data Explorer clusters for disk encryption, which encrypts the operating system and data disks (including the hot cache) of the cluster nodes.'
    Rationale     = 'Storage encryption covers the persisted data only. The node disks hold the hot cache, a copy of the most queried data, and are not encrypted unless disk encryption is on.'
    Remediation   = 'Enable disk encryption on the cluster (Security > Disk encryption).'
    References    = @('https://learn.microsoft.com/azure/data-explorer/cluster-encryption-disk')
    ResourceTypes = $kustoType
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ enableDiskEncryption = $Record.resource.properties.enableDiskEncryption }
        if ($Record.resource.properties.enableDiskEncryption -eq $true) { return New-Pass 'Disk encryption enabled' $evidence }
        New-Fail 'Disk encryption disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ADX-003'
    Title         = 'Azure Data Explorer clusters use double encryption'
    Category      = 'Data protection'
    Service       = 'Azure Data Explorer'
    Severity      = 'Low'
    Description   = 'Checks Azure Data Explorer clusters for double encryption, which adds infrastructure encryption with a second algorithm and key under the service level encryption.'
    Rationale     = 'Two independent layers of encryption protect the data if one encryption algorithm or key is compromised.'
    Remediation   = 'Double encryption can only be enabled when a cluster is created: create a new cluster with double encryption and move the databases to it.'
    References    = @('https://learn.microsoft.com/azure/data-explorer/cluster-encryption-double')
    ResourceTypes = $kustoType
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ enableDoubleEncryption = $Record.resource.properties.enableDoubleEncryption }
        if ($Record.resource.properties.enableDoubleEncryption -eq $true) { return New-Pass 'Double encryption enabled' $evidence }
        New-Fail 'Double encryption disabled' $evidence
    }
}
