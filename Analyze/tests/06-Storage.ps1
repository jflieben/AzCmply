#Storage accounts: transport, access model, network exposure, data protection and file shares

$storageType = @('Microsoft.Storage/storageAccounts')

function Test-SharedKeyDisabled { param($Record) return ($Record.resource.properties.allowSharedKeyAccess -eq $false) }
function Test-BlobCapable { param($Record) return ($Record.resource.kind -in 'StorageV2', 'Storage', 'BlobStorage', 'BlockBlobStorage') }
function Test-FileCapable { param($Record) return ($Record.resource.kind -in 'StorageV2', 'Storage', 'FileStorage') }

Add-AzTest @{
    Id            = 'AZ-STG-001'
    Title         = 'Storage accounts require secure transfer (HTTPS)'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'High'
    Description   = "Checks the 'Secure transfer required' setting (supportsHttpsTrafficOnly)."
    Rationale     = 'Without secure transfer, requests and shared access signatures can be sent over plain HTTP and SMB without encryption, exposing data and credentials on the network.'
    Remediation   = 'Enable secure transfer (az storage account update --https-only true ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer')
    Frameworks    = @{ MCSB = 'DP-3'; CIS = '9.3.4'; WAF = 'SE:07'; ALZ = @('Deny-Storage-http', 'Enforce-TLS-SSL-Q225') }
    Defender      = @{ '1c5de8e1-f68d-6a17-e0d2-ec259c42768c' = 'Secure transfer to storage accounts should be enabled' }
    Policy        = @{ '404c3081-a854-4457-ae30-26a93ef643f9' = 'Secure transfer to storage accounts should be enabled' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.supportsHttpsTrafficOnly
        if ($value -eq $false) { return New-Fail 'Secure transfer is not required' ([ordered]@{ supportsHttpsTrafficOnly = $value }) }
        New-Pass 'Secure transfer required' ([ordered]@{ supportsHttpsTrafficOnly = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-002'
    Title         = 'Storage accounts require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks the minimum TLS version of storage accounts.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses. Azure Storage stopped accepting them on 3 February 2026, and the account setting should reflect TLS 1.2 so clients and audits see the enforced minimum.'
    Remediation   = 'Set the minimum TLS version to TLS 1.2 (az storage account update --min-tls-version TLS1_2 ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version')
    Frameworks    = @{ MCSB = 'DP-3'; CIS = '9.3.6'; WAF = 'SE:07'; ALZ = 'Enforce-TLS-SSL-Q225' }
    Defender      = @{ '54bb9d74-fb09-c933-8249-91d5b36310c3' = 'Storage accounts should have the specified minimum TLS version' }
    Policy        = @{ 'fe83a0eb-a853-422d-aac2-1bffd182c5d0' = 'Storage accounts should have the specified minimum TLS version' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.minimumTlsVersion
        $evidence = [ordered]@{ minimumTlsVersion = $value }
        if (Test-VersionAtLeast $value '1.2') { return New-Pass "Minimum $value" $evidence }
        New-Fail $(if ($value) { "Minimum $value" } else { 'Minimum TLS version not set' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-003'
    Title         = 'Storage accounts disallow anonymous blob access'
    Category      = 'Network security'
    Service       = 'Storage'
    Severity      = 'High'
    Description   = "Checks that 'Allow Blob anonymous access' (allowBlobPublicAccess) is disabled on the account."
    Rationale     = 'When the account allows anonymous access, any container can be made public with a single change, exposing its blobs to anyone on the Internet without authentication.'
    Remediation   = 'Disable anonymous access on the account (az storage account update --allow-blob-public-access false ...). Serve public content through a CDN or Front Door with private origins if needed.'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent')
    Frameworks    = @{ MCSB = @('NS-2', 'IM-7'); CIS = '9.3.8'; WAF = 'SE:05'; ALZ = 'Enforce-GR-Storage0' }
    Defender      = @{ '51fd8bb1-0db4-bbf1-7e2b-cfcba7eb66a6' = 'Storage account public access should be disallowed' }
    Policy        = @{ '4fa4b6c0-31ca-4c0d-b10d-24b96f62a751' = 'Storage account public access should be disallowed' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.allowBlobPublicAccess
        $evidence = [ordered]@{ allowBlobPublicAccess = $value }
        if ($value -eq $false) { return New-Pass 'Anonymous access disallowed' $evidence }
        New-Fail $(if ($null -eq $value) { 'Anonymous access setting not set (allowed on older accounts)' } else { 'Anonymous access allowed' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-004'
    Title         = 'No blob containers are publicly accessible'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Critical'
    Description   = 'Finds containers with a public access level (Blob or Container) on accounts that allow anonymous access, which are readable by anyone on the Internet.'
    Rationale     = 'Publicly readable containers are a leading cause of data breaches; their content can be enumerated and downloaded without any credential.'
    Remediation   = "Set the container access level to Private (az storage container set-permission --public-access off ...) and disable anonymous access on the account."
    References    = @('https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent')
    Frameworks    = @{ MCSB = @('DP-2', 'NS-2'); WAF = 'SE:05' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-BlobCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'blobServices/default/containers')) { return New-Unknown 'Containers could not be read' }
        $public = @(Get-Child $Record 'blobServices/default/containers' | Where-Object { $_ -and $_.properties.publicAccess -and $_.properties.publicAccess -ne 'None' })
        $evidence = [ordered]@{ allowBlobPublicAccess = $Record.resource.properties.allowBlobPublicAccess; publicContainers = @($public | ForEach-Object { "$($_.name) ($($_.properties.publicAccess))" } | Sort-Object) }
        if ($public -and $Record.resource.properties.allowBlobPublicAccess -ne $false) { return New-Fail "Publicly readable container(s): $($evidence.publicContainers -join ', ')" $evidence }
        if ($public) { return New-Pass 'Containers have a public access level but the account blocks anonymous access' $evidence }
        New-Pass 'No public containers' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-005'
    Title         = 'Storage account key access (shared key) is disabled'
    Category      = 'Identity management'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = "Checks that 'Allow storage account key access' (allowSharedKeyAccess) is disabled, so requests must use Microsoft Entra authorization."
    Rationale     = 'Account keys grant full control over all data, never expire on their own, are not tied to an identity and bypass RBAC and Conditional Access. Service SAS and account SAS tokens are derived from them.'
    Remediation   = 'Move clients to Entra ID authorization (RBAC data roles, managed identities, user delegation SAS), then disable shared key access (az storage account update --allow-shared-key-access false ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent')
    Frameworks    = @{ MCSB = @('IM-1', 'IM-3'); CIS = '9.3.1.3'; WAF = 'SE:05'; ALZ = 'Enforce-GR-Storage0' }
    Defender      = @{ '3b363842-30f5-4056-980d-3a40fa5de8b3' = 'Storage accounts should prevent shared key access' }
    Policy        = @{ '8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54' = 'Storage accounts should prevent shared key access' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.allowSharedKeyAccess
        $evidence = [ordered]@{ allowSharedKeyAccess = $value }
        if ($value -eq $false) { return New-Pass 'Shared key access disabled' $evidence }
        New-Fail 'Shared key access allowed' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-006'
    Title         = 'Storage accounts disable public network access'
    Category      = 'Network security'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks that public network access is disabled (or secured by a network security perimeter), so the account is only reachable through private endpoints.'
    Rationale     = 'A public endpoint can be reached from anywhere; any leaked key, SAS token or overly broad firewall rule then exposes the data to the Internet.'
    Remediation   = 'Create private endpoints for the required sub-resources and set public network access to Disabled (az storage account update --public-network-access Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-network-security')
    Frameworks    = @{ MCSB = 'NS-2'; CIS = '9.3.2.2'; WAF = 'SE:06'; ALZ = @('Deny-Public-Endpoints', 'Enforce-GR-Storage0') }
    Defender      = @{ '85b39950-d5ba-0ff5-664d-8f33544545ca' = 'Storage accounts should disable public network access' }
    Policy        = @{ 'b2982f36-99f2-4db5-8eff-283140c09693' = 'Storage accounts should disable public network access' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.publicNetworkAccess
        $evidence = [ordered]@{ publicNetworkAccess = $value }
        if ($value -in 'Disabled', 'SecuredByPerimeter') { return New-Pass "Public network access $value" $evidence }
        New-Fail 'Public network access enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-007'
    Title         = 'Storage account firewalls deny access by default'
    Category      = 'Network security'
    Service       = 'Storage'
    Severity      = 'High'
    Description   = 'Checks that the storage firewall default action is Deny (or that public network access is disabled).'
    Rationale     = "With default action Allow, the public endpoint accepts traffic from every network, so authentication is the only barrier."
    Remediation   = 'Set the default network action to Deny and allow only required virtual networks, IP ranges and resource instances (az storage account update --default-action Deny ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-network-security')
    Frameworks    = @{ MCSB = 'NS-2'; CIS = '9.3.2.3'; WAF = 'SE:06' }
    Defender      = @{ '45d313c3-3fca-5040-035f-d61928366d31' = 'Access to storage accounts with firewall and virtual network configurations should be restricted' }
    Policy        = @{ '34c877ad-507e-4c82-993e-3452a6e0ad3c' = 'Storage accounts should restrict network access' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; defaultAction = $p.networkAcls.defaultAction; ipRules = @($p.networkAcls.ipRules).Count; virtualNetworkRules = @($p.networkAcls.virtualNetworkRules).Count }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if ($p.networkAcls.defaultAction -eq 'Deny') { return New-Pass 'Firewall default action Deny' $evidence }
        New-Fail 'Firewall default action Allow' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-008'
    Title         = 'Storage accounts are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks for at least one approved private endpoint connection.'
    Rationale     = 'Private endpoints keep traffic on the Microsoft backbone and let the public endpoint be disabled entirely.'
    Remediation   = 'Create private endpoints for the used sub-resources (blob, file, queue, table, dfs) with private DNS zone integration.'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-private-endpoints')
    Frameworks    = @{ MCSB = 'NS-2'; CIS = '9.3.2.1'; ALZ = 'Deploy-Private-DNS-Zones' }
    Defender      = @{ 'cdc78c07-02b0-4af0-1cb2-cb7c672a8b0a' = 'Storage account should use a private link connection' }
    Policy        = @{ '6edd7eda-6dd8-40f7-810d-67160c639cd9' = 'Storage accounts should use private link' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $approved = @($Record.resource.properties.privateEndpointConnections | Where-Object { $_ -and $_.properties.privateLinkServiceConnectionState.status -eq 'Approved' })
        $evidence = [ordered]@{ approvedPrivateEndpoints = $approved.Count }
        if ($approved) { return New-Pass "$($approved.Count) private endpoint(s)" $evidence }
        New-Fail 'No private endpoint' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-009'
    Title         = 'Storage firewalls allow trusted Microsoft services'
    Category      = 'Network security'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = "Checks that accounts with a restrictive firewall allow the trusted Microsoft services exception (bypass AzureServices), so platform services such as Backup, Defender and Monitor keep working."
    Rationale     = 'Without the exception, administrators tend to open the firewall entirely to make platform integrations work.'
    Remediation   = "Enable 'Allow Azure services on the trusted services list to access this storage account' (az storage account update --bypass AzureServices ...), or use resource instance rules."
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-network-security-trusted-azure-services')
    Frameworks    = @{ MCSB = 'NS-2'; CIS = '9.3.5' }
    Defender      = @{ '6bb1ea0d-9a68-9ca0-f16b-f77a4648a9f6' = 'Storage accounts should allow access from trusted Microsoft services' }
    Policy        = @{ 'c9d007d0-c057-4772-b18c-01e546713bcd' = 'Storage accounts should allow access from trusted Microsoft services' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $acls = $Record.resource.properties.networkAcls
        $evidence = [ordered]@{ defaultAction = $acls.defaultAction; bypass = $acls.bypass }
        if ($acls.defaultAction -ne 'Deny') { return New-NotApplicable 'The firewall does not restrict access' $evidence }
        if ([string]$acls.bypass -match 'AzureServices') { return New-Pass 'Trusted Microsoft services allowed' $evidence }
        New-Fail 'Trusted Microsoft services are not allowed' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-010'
    Title         = 'Cross-tenant object replication is disabled'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks that allowCrossTenantReplication is disabled.'
    Rationale     = 'Cross-tenant object replication lets data be copied continuously to a storage account in another Entra tenant, which is an exfiltration path outside your control.'
    Remediation   = 'Disable cross-tenant replication (az storage account update --allow-cross-tenant-replication false ...).'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/object-replication-prevent-cross-tenant-policies')
    Frameworks    = @{ MCSB = @('DP-2', 'PV-2'); CIS = '9.3.7' }
    Policy        = @{ '92a89a79-6c52-4a7e-a03f-61306fc49312' = 'Storage accounts should prevent cross tenant object replication' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.allowCrossTenantReplication
        $evidence = [ordered]@{ allowCrossTenantReplication = $value }
        if ($value -eq $false) { return New-Pass 'Cross-tenant replication disabled' $evidence }
        New-Fail $(if ($null -eq $value) { 'Setting not configured (allowed on older accounts)' } else { 'Cross-tenant replication allowed' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-011'
    Title         = 'The Azure portal defaults to Microsoft Entra authorization'
    Category      = 'Identity management'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks defaultToOAuthAuthentication, which makes the portal use Entra ID (RBAC) instead of the account key to access data.'
    Rationale     = 'Portal access with the account key bypasses data plane RBAC and is not attributable to a user in the logs.'
    Remediation   = "Enable 'Default to Microsoft Entra authorization in the Azure portal' (az storage account update --set defaultToOAuthAuthentication=true ...)."
    Frameworks    = @{ MCSB = 'IM-1'; CIS = '9.3.3.1' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.defaultToOAuthAuthentication
        $evidence = [ordered]@{ defaultToOAuthAuthentication = $value }
        if ($value -eq $true) { return New-Pass 'Portal defaults to Entra authorization' $evidence }
        New-Fail 'Portal uses the account key by default' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-012'
    Title         = 'Storage account key rotation reminders are configured'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks for a key expiration policy (keyPolicy.keyExpirationPeriodInDays) on accounts that allow shared key access.'
    Rationale     = 'A key expiration policy flags keys that are due for rotation, so long lived keys become visible.'
    Remediation   = 'Set a key expiration policy of 90 days or less (az storage account update --key-exp-days 90 ...) and rotate keys before they expire.'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage')
    Frameworks    = @{ MCSB = 'DP-6'; CIS = '9.3.1.1' }
    Defender      = @{ 'bdd60d05-d94b-268c-6298-fdc1597ca0e2' = 'Storage account keys should not be expired' }
    Policy        = @{ '044985bb-afe1-42cd-8a36-9d5d42424537' = 'Storage account keys should not be expired' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $days = $Record.resource.properties.keyPolicy.keyExpirationPeriodInDays
        $evidence = [ordered]@{ keyExpirationPeriodInDays = $days; allowSharedKeyAccess = $Record.resource.properties.allowSharedKeyAccess }
        if (Test-SharedKeyDisabled $Record) { return New-Pass 'Shared key access is disabled, keys cannot be used' $evidence }
        if ($days -gt 0) { return New-Pass "Key expiration policy of $days days" $evidence }
        New-Fail 'No key expiration policy' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-013'
    Title         = 'Storage account keys were regenerated within 90 days'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks the creation time of both access keys on accounts that allow shared key access.'
    Rationale     = 'Access keys are full access credentials. Regular regeneration limits how long a leaked key remains usable.'
    Remediation   = 'Regenerate the keys (az storage account keys renew --key primary|secondary ...) after updating clients, or disable shared key access.'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage')
    Frameworks    = @{ MCSB = 'DP-6'; CIS = '9.3.1.2' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $times = $Record.resource.properties.keyCreationTime
        $evidence = [ordered]@{ key1Created = Format-UtcDate $times.key1; key2Created = Format-UtcDate $times.key2 }
        if (Test-SharedKeyDisabled $Record) { return New-Pass 'Shared key access is disabled, keys cannot be used' $evidence }
        if (-not $times.key1 -or -not $times.key2) { return New-Fail 'Key creation time unknown (keys not regenerated since tracking started)' $evidence }
        $oldest = @((Get-AgeInDays $times.key1), (Get-AgeInDays $times.key2)) | Sort-Object -Descending | Select-Object -First 1
        $evidence.oldestKeyAgeInDays = $oldest
        if ($oldest -le 90) { return New-Pass 'Both keys regenerated within 90 days' $evidence }
        New-Fail "Oldest key is $oldest days old" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-014'
    Title         = 'Blob soft delete is enabled'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks that blob soft delete is enabled with a retention of at least 7 days.'
    Rationale     = 'Soft delete allows recovery of blobs that were deleted or overwritten by mistake or by an attacker (for example ransomware deleting data).'
    Remediation   = 'Enable blob soft delete with 7 to 365 days retention (az storage account blob-service-properties update --enable-delete-retention true --delete-retention-days 14 ...).'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/soft-delete-blob-overview')
    Frameworks    = @{ MCSB = @('BR-1', 'DP-4'); CIS = '9.2.1' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-BlobCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'blobServices/default')) { return New-Unknown 'Blob service properties could not be read' }
        $policy = (Get-Child $Record 'blobServices/default').properties.deleteRetentionPolicy
        $evidence = [ordered]@{ enabled = [bool]$policy.enabled; days = $policy.days }
        if ($policy.enabled -and $policy.days -ge 7) { return New-Pass "Blob soft delete for $($policy.days) days" $evidence }
        New-Fail $(if ($policy.enabled) { "Blob soft delete retention only $($policy.days) days" } else { 'Blob soft delete disabled' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-015'
    Title         = 'Container soft delete is enabled'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks that container soft delete is enabled with a retention of at least 7 days.'
    Rationale     = 'Deleting a container removes all of its blobs at once; container soft delete allows restoring it.'
    Remediation   = 'Enable container soft delete (az storage account blob-service-properties update --enable-container-delete-retention true --container-delete-retention-days 14 ...).'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/soft-delete-container-overview')
    Frameworks    = @{ MCSB = @('BR-1', 'DP-4'); CIS = '9.2.2' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-BlobCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'blobServices/default')) { return New-Unknown 'Blob service properties could not be read' }
        $policy = (Get-Child $Record 'blobServices/default').properties.containerDeleteRetentionPolicy
        $evidence = [ordered]@{ enabled = [bool]$policy.enabled; days = $policy.days }
        if ($policy.enabled -and $policy.days -ge 7) { return New-Pass "Container soft delete for $($policy.days) days" $evidence }
        New-Fail $(if ($policy.enabled) { "Container soft delete retention only $($policy.days) days" } else { 'Container soft delete disabled' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-016'
    Title         = 'Blob versioning is enabled'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks that blob versioning is enabled (not applicable to accounts with a hierarchical namespace).'
    Rationale     = 'Versioning keeps previous versions of overwritten blobs, which protects against accidental and malicious modification such as ransomware encryption.'
    Remediation   = 'Enable versioning (az storage account blob-service-properties update --enable-versioning true ...) with a lifecycle rule to delete old versions.'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/versioning-overview')
    Frameworks    = @{ MCSB = 'BR-1'; CIS = '9.2.3' }
    ResourceTypes = $storageType
    Filter        = { param($Record) (Test-BlobCapable $Record) -and -not $Record.resource.properties.isHnsEnabled }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'blobServices/default')) { return New-Unknown 'Blob service properties could not be read' }
        $enabled = [bool](Get-Child $Record 'blobServices/default').properties.isVersioningEnabled
        if ($enabled) { return New-Pass 'Versioning enabled' ([ordered]@{ isVersioningEnabled = $true }) }
        New-Fail 'Versioning disabled' ([ordered]@{ isVersioningEnabled = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-017'
    Title         = 'File share soft delete is enabled'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks that soft delete for Azure file shares is enabled with a retention of at least 7 days.'
    Rationale     = 'Soft delete allows recovery of file shares that were deleted by mistake or by an attacker.'
    Remediation   = 'Enable share soft delete (az storage account file-service-properties update --enable-delete-retention true --delete-retention-days 14 ...).'
    References    = @('https://learn.microsoft.com/azure/storage/files/storage-files-prevent-file-share-deletion')
    Frameworks    = @{ MCSB = @('BR-1', 'DP-4'); CIS = '9.1.1' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-FileCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'fileServices/default')) { return New-Unknown 'File service properties could not be read' }
        $policy = (Get-Child $Record 'fileServices/default').properties.shareDeleteRetentionPolicy
        $evidence = [ordered]@{ enabled = [bool]$policy.enabled; days = $policy.days }
        if ($policy.enabled -and $policy.days -ge 7) { return New-Pass "Share soft delete for $($policy.days) days" $evidence }
        New-Fail $(if ($policy.enabled) { "Share soft delete retention only $($policy.days) days" } else { 'Share soft delete disabled' }) $evidence
    }
}

function Get-SmbSetting {
    #SMB protocol setting of an account with file shares; returns $null when there are no shares
    param($Record, [string]$Name)
    $shares = @(Get-Child $Record 'fileServices/default/shares' | Where-Object { $_ -and $_.properties.enabledProtocols -ne 'NFS' })
    if (-not $shares) { return $null }
    return [pscustomobject]@{ Value = (Get-Child $Record 'fileServices/default').properties.protocolSettings.smb.$Name; Shares = $shares.Count }
}

Add-AzTest @{
    Id            = 'AZ-STG-018'
    Title         = 'SMB file shares only allow SMB 3.1.1'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks the allowed SMB protocol versions on accounts with SMB file shares.'
    Rationale     = 'Older SMB versions lack pre-authentication integrity and the strongest encryption, and allow downgrade attacks.'
    Remediation   = "Restrict SMB versions to SMB3.1.1 in the file service properties (az storage account file-service-properties update --versions SMB3.1.1 ...)."
    References    = @('https://learn.microsoft.com/azure/storage/files/files-smb-protocol')
    Frameworks    = @{ MCSB = @('DP-3', 'NS-8'); CIS = '9.1.2' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-FileCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'fileServices/default')) { return New-Unknown 'File service properties could not be read' }
        $setting = Get-SmbSetting $Record 'versions'
        if (-not $setting) { return New-NotApplicable 'No SMB file shares' }
        $versions = @(([string]$setting.Value) -split ';' | Where-Object { $_ })
        $evidence = [ordered]@{ versions = $versions; smbShares = $setting.Shares }
        if ($versions.Count -and -not ($versions | Where-Object { $_ -ne 'SMB3.1.1' })) { return New-Pass 'Only SMB 3.1.1 allowed' $evidence }
        New-Fail $(if ($versions) { "Allowed versions: $($versions -join ', ')" } else { 'All SMB versions allowed (default)' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-019'
    Title         = 'SMB file shares only allow AES-256-GCM channel encryption'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks the allowed SMB channel encryption algorithms on accounts with SMB file shares.'
    Rationale     = 'AES-256-GCM is the strongest channel encryption supported by Azure Files; allowing weaker algorithms permits negotiation down.'
    Remediation   = 'Restrict SMB channel encryption to AES-256-GCM (az storage account file-service-properties update --channel-encryption AES-256-GCM ...).'
    References    = @('https://learn.microsoft.com/azure/storage/files/files-smb-protocol')
    Frameworks    = @{ MCSB = 'DP-3'; CIS = '9.1.3' }
    ResourceTypes = $storageType
    Filter        = { param($Record) Test-FileCapable $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'fileServices/default')) { return New-Unknown 'File service properties could not be read' }
        $setting = Get-SmbSetting $Record 'channelEncryption'
        if (-not $setting) { return New-NotApplicable 'No SMB file shares' }
        $algorithms = @(([string]$setting.Value) -split ';' | Where-Object { $_ })
        $evidence = [ordered]@{ channelEncryption = $algorithms; smbShares = $setting.Shares }
        if ($algorithms.Count -and -not ($algorithms | Where-Object { $_ -ne 'AES-256-GCM' })) { return New-Pass 'Only AES-256-GCM allowed' $evidence }
        New-Fail $(if ($algorithms) { "Allowed: $($algorithms -join ', ')" } else { 'All algorithms allowed (default)' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-020'
    Title         = 'Storage accounts use infrastructure (double) encryption'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks requireInfrastructureEncryption, which adds a second layer of encryption at the infrastructure level. It can only be set when the account is created.'
    Rationale     = 'Double encryption protects against a compromise of one of the encryption algorithms or keys, and is required by some regulations for highly sensitive data.'
    Remediation   = 'For accounts with sensitive data, create a new account with infrastructure encryption enabled and migrate the data.'
    References    = @('https://learn.microsoft.com/azure/storage/common/infrastructure-encryption-enable')
    Frameworks    = @{ MCSB = 'DP-4' }
    Defender      = @{ 'a5cd34d5-26df-c2b1-0ace-ff62f8730abd' = 'Storage accounts should have infrastructure encryption' }
    Policy        = @{ '4733ea7b-a883-42fe-8cac-97454c2a9e4a' = 'Storage accounts should have infrastructure encryption' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.encryption.requireInfrastructureEncryption
        if ($value) { return New-Pass 'Infrastructure encryption enabled' ([ordered]@{ requireInfrastructureEncryption = $true }) }
        New-Fail 'Infrastructure encryption not enabled' ([ordered]@{ requireInfrastructureEncryption = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-021'
    Title         = 'Storage accounts use customer-managed keys (when required)'
    Category      = 'Data protection'
    Service       = 'Storage'
    Severity      = 'Informational'
    Description   = 'Checks whether the account encryption uses a customer-managed key from Key Vault.'
    Rationale     = 'Customer-managed keys give control over key rotation and the ability to revoke access to the data (crypto shredding). Only required for data whose classification or regulation demands it.'
    Remediation   = 'Configure encryption with a customer-managed key in Key Vault or Managed HSM, using a user-assigned managed identity and automatic key version updates.'
    References    = @('https://learn.microsoft.com/azure/storage/common/customer-managed-keys-overview')
    Frameworks    = @{ MCSB = 'DP-5'; ALZ = 'Enforce-Encrypt-CMK0' }
    Defender      = @{ 'ca98bba7-719e-48ee-e193-0b76766cdb07' = '[Enable if required] Storage accounts should use customer-managed key (CMK) for encryption' }
    Policy        = @{ '6fac406b-40ca-413b-bf8e-0bf964659c25' = 'Storage accounts should use customer-managed key for encryption' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $source = $Record.resource.properties.encryption.keySource
        $evidence = [ordered]@{ keySource = $source }
        if ($source -eq 'Microsoft.Keyvault') { return New-Pass 'Customer-managed key' $evidence }
        New-Fail 'Microsoft-managed keys' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-022'
    Title         = 'Storage accounts use geo-redundant replication'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks that the replication SKU is geo-redundant (GRS, RA-GRS, GZRS or RA-GZRS).'
    Rationale     = 'Geo-redundancy keeps a copy of the data in a paired region, which protects critical data against regional outages and disasters.'
    Remediation   = 'Change the redundancy of critical accounts to GZRS or GRS (az storage account update --sku Standard_GZRS ...).'
    References    = @('https://learn.microsoft.com/azure/storage/common/storage-redundancy')
    Frameworks    = @{ MCSB = 'BR-1'; CIS = '9.3.11' }
    Defender      = @{ 'bb819c3c-29fc-8bbe-4bb1-433ab95c4590' = 'Geo-redundant storage should be enabled for Storage Accounts' }
    Policy        = @{ 'bf045164-79ba-4215-8f95-f8048dc1780b' = 'Geo-redundant storage should be enabled for Storage Accounts' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $sku = $Record.resource.sku.name
        $evidence = [ordered]@{ sku = $sku }
        if ($sku -match 'GRS|GZRS') { return New-Pass "Replication $sku" $evidence }
        New-Fail "Replication $sku is not geo-redundant" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-023'
    Version       = 2
    Title         = 'SFTP local users do not use password authentication'
    Category      = 'Identity management'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Finds storage local users (SFTP) that have an SSH password.'
    Rationale     = 'Local users are not Entra identities: passwords cannot be protected with MFA or Conditional Access and are a target for brute force on the Internet facing SFTP endpoint.'
    Remediation   = 'Use SSH key authentication for local users, remove their passwords (az storage account local-user update --has-ssh-password false ...) and disable SFTP when not needed.'
    References    = @('https://learn.microsoft.com/azure/storage/blobs/secure-file-transfer-protocol-support-authorize-access')
    Frameworks    = @{ MCSB = @('IM-6', 'IM-3') }
    ResourceTypes = $storageType
    Filter        = { param($Record) $Record.resource.properties.isSftpEnabled -or @(Get-Child $Record 'localUsers' | Where-Object { $_ }).Count }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'localUsers')) { return New-Unknown 'SFTP local users could not be read' }
        $users = @(Get-Child $Record 'localUsers' | Where-Object { $_ })
        $withPassword = @($users | Where-Object { $_.properties.hasSshPassword } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ isSftpEnabled = [bool]$Record.resource.properties.isSftpEnabled; localUsers = $users.Count; usersWithPassword = $withPassword }
        if ($withPassword) { return New-Fail "Local user(s) with SSH password: $($withPassword -join ', ')" $evidence }
        New-Pass 'No local users with passwords' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-024'
    Title         = 'A SAS expiration policy is configured'
    Category      = 'Identity management'
    Service       = 'Storage'
    Severity      = 'Low'
    Description   = 'Checks for a SAS expiration policy (sasPolicy) on accounts that allow shared key access.'
    Rationale     = 'Account and service SAS tokens signed with the account key cannot be revoked individually. An expiration policy limits their validity and logs or blocks tokens that exceed it.'
    Remediation   = "Configure a SAS expiration policy, for example 7 days with action Block (az storage account update --sas-exp 7.00:00:00 ...), and prefer user delegation SAS."
    References    = @('https://learn.microsoft.com/azure/storage/common/sas-expiration-policy')
    Frameworks    = @{ MCSB = 'IM-8'; WAF = 'SE:09' }
    Policy        = @{ '7aa1c9d5-3d7e-4579-8117-d85e99211757' = 'Storage SAS tokens should adhere to 7 day maximum validity' }
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $policy = $Record.resource.properties.sasPolicy
        $evidence = [ordered]@{ sasExpirationPeriod = $policy.sasExpirationPeriod; expirationAction = $policy.expirationAction }
        if (Test-SharedKeyDisabled $Record) { return New-Pass 'Shared key access is disabled, account key SAS cannot be used' $evidence }
        if ($policy.sasExpirationPeriod) { return New-Pass "SAS expiration period $($policy.sasExpirationPeriod)" $evidence }
        New-Fail 'No SAS expiration policy' $evidence
    }
}

#CIS numbers storage account locks separately from the generic lock recommendation (AZ-GOV-004 / CIS 6.2):
#9.3.9 requires a Delete lock, 9.3.10 asks for a ReadOnly lock to be considered
Add-AzTest @{
    Id            = 'AZ-STG-025'
    Title         = 'Storage accounts have a delete lock'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Medium'
    Description   = 'Checks storage accounts for a CanNotDelete or ReadOnly lock on the account, its resource group or the subscription. A ReadOnly lock also prevents deletion.'
    Rationale     = 'Deleting a storage account destroys all of its data at once and cannot be undone. A lock makes that a deliberate two step action, because removing it needs Microsoft.Authorization/locks/delete.'
    Remediation   = 'Add a CanNotDelete lock (az lock create --lock-type CanNotDelete --name DoNotDelete --resource <storage account id>) and restrict lock administration to a dedicated role.'
    References    = @('https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources')
    Frameworks    = @{ MCSB = @('BR-2', 'AM-3'); CIS = '9.3.9' }
    Requires      = @('subscription/locks')
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $locks = @(Get-EffectiveLocks $Record.id)
        $evidence = [ordered]@{ locks = @($locks | ForEach-Object { "$($_.properties.level) @ $($_.id -replace '(?i)/providers/Microsoft\.Authorization/locks/.*$', '')" } | Sort-Object) }
        if ($locks | Where-Object { $_.properties.level -in 'CanNotDelete', 'ReadOnly' }) { return New-Pass "Locked ($(@($locks | ForEach-Object { $_.properties.level } | Sort-Object -Unique) -join ', '))" $evidence }
        New-Fail 'No delete lock on the account, resource group or subscription' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-STG-026'
    Title         = 'Storage accounts holding immutable data have a ReadOnly lock'
    Category      = 'Backup and recovery'
    Service       = 'Storage'
    Severity      = 'Informational'
    Description   = 'Reports whether a ReadOnly lock applies to each storage account. CIS recommends considering one for accounts whose configuration and data must not change; it also blocks listing and rotating the account keys, so it does not suit every account.'
    Rationale     = 'A ReadOnly lock prevents both deletion and configuration changes, including someone quietly widening the firewall or re-enabling anonymous access.'
    Remediation   = 'Decide per account whether a ReadOnly lock fits its use (az lock create --lock-type ReadOnly --name ReadOnly --resource <storage account id>). Accounts that need key rotation or data plane writes through the management plane should keep a CanNotDelete lock instead.'
    References    = @('https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources')
    Frameworks    = @{ MCSB = @('BR-2', 'AM-3'); CIS = '9.3.10' }
    Requires      = @('subscription/locks')
    ResourceTypes = $storageType
    Evaluate      = {
        param($Record)
        $locks = @(Get-EffectiveLocks $Record.id)
        $readOnly = @($locks | Where-Object { $_.properties.level -eq 'ReadOnly' })
        $evidence = [ordered]@{ locks = @($locks | ForEach-Object { "$($_.properties.level) @ $($_.id -replace '(?i)/providers/Microsoft\.Authorization/locks/.*$', '')" } | Sort-Object) }
        if ($readOnly) { return New-Pass 'ReadOnly lock applies' $evidence }
        New-Fail 'No ReadOnly lock; confirm this account does not need one' $evidence
    }
}
