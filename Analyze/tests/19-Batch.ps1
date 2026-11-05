#Batch: Batch accounts and their pools

$batchType = @('Microsoft.Batch/batchAccounts')

Add-AzTest @{
    Id            = 'AZ-BATCH-001'
    Title         = 'Batch pools encrypt their OS and temporary disks'
    Category      = 'Data protection'
    Service       = 'Batch'
    Severity      = 'Medium'
    Description   = 'Checks that every pool of a Batch account lists OsDisk and TemporaryDisk as disk encryption targets (deploymentConfiguration.virtualMachineConfiguration.diskEncryptionConfiguration).'
    Rationale     = 'Without disk encryption the OS and temporary disks of the compute nodes, which hold task input, output and credentials, are stored unencrypted on the host.'
    Remediation   = 'Recreate the pool with disk encryption for OsDisk and TemporaryDisk (the setting cannot be changed on an existing pool), or use encryption at host on the node size.'
    References    = @('https://learn.microsoft.com/azure/batch/disk-encryption')
    Policy        = @{ '1760f9d4-7206-436e-a28f-d9f3a5c8a227' = 'Azure Batch pools should have disk encryption enabled' }
    ResourceTypes = $batchType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'pools')) { return New-Unknown 'The pools of the account could not be read' }
        $pools = @(Get-Child $Record 'pools' | Where-Object { $_ })
        if (-not $pools) { return New-NotApplicable 'No pools' }
        $unencrypted = [System.Collections.Generic.List[string]]::new()
        foreach ($pool in $pools) {
            $targets = @($pool.properties.deploymentConfiguration.virtualMachineConfiguration.diskEncryptionConfiguration.targets | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $missing = @('OsDisk', 'TemporaryDisk' | Where-Object { $_ -notin $targets })
            if ($missing) { $unencrypted.Add("$(([string]$pool.name -split '/')[-1]): $($missing -join ', ')") }
        }
        $evidence = [ordered]@{ pools = $pools.Count; notEncrypted = @($unencrypted | Sort-Object) }
        if ($unencrypted.Count) { return New-Fail "Disks without encryption: $($evidence.notEncrypted -join '; ')" $evidence }
        New-Pass "All $($pools.Count) pool(s) encrypt their OS and temporary disks" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BATCH-002'
    Title         = 'Batch accounts only allow Microsoft Entra authentication'
    Category      = 'Identity management'
    Service       = 'Batch'
    Severity      = 'Medium'
    Description   = 'Checks that the allowed authentication modes of Batch accounts are AAD only, without SharedKey or TaskAuthenticationToken.'
    Rationale     = 'Shared keys give full access to the Batch service API without an identity, MFA or Conditional Access, and task authentication tokens let tasks call the API with the rights of the account.'
    Remediation   = 'Move clients to Microsoft Entra ID and set the authentication modes to Microsoft Entra ID only (az batch account set --allowed-authentication-modes AAD ...).'
    References    = @('https://learn.microsoft.com/azure/batch/security-best-practices#batch-account-authentication')
    Policy        = @{ '6f68b69f-05fe-49cd-b361-777ee9ca7e35' = 'Batch accounts should have local authentication methods disabled' }
    ResourceTypes = $batchType
    Evaluate      = {
        param($Record)
        $modes = @($Record.resource.properties.allowedAuthenticationModes | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object)
        $evidence = [ordered]@{ allowedAuthenticationModes = $modes }
        if (-not $modes) { return New-Unknown 'The allowed authentication modes are not in the resource' $evidence }
        $others = @($modes | Where-Object { $_ -ne 'AAD' })
        if ($others) { return New-Fail "Also allows $($others -join ', ')" $evidence }
        New-Pass 'Only Microsoft Entra authentication' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BATCH-003'
    Title         = 'Batch accounts are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Batch'
    Severity      = 'Low'
    Description   = 'Checks that Batch accounts have at least one private endpoint connection and that every connection is approved.'
    Rationale     = 'Private endpoints let clients and nodes reach the Batch account over private addresses, so public network access can be turned off.'
    Remediation   = 'Create a private endpoint for the account (group batchAccount, and nodeManagement for simplified node communication) with a private DNS zone, and approve or remove pending connections.'
    References    = @('https://learn.microsoft.com/azure/batch/private-connectivity')
    Defender      = @{ '48aeb3bb-b47a-c873-7308-e7aa6126d242' = 'Private endpoint connections on Batch accounts should be enabled' }
    Policy        = @{ '009a0c92-f5b4-4776-9b66-4ed2b4775563' = 'Private endpoint connections on Batch accounts should be enabled' }
    ResourceTypes = $batchType
    Evaluate      = {
        param($Record)
        if (Test-ChildCollected $Record 'privateEndpointConnections') { $connections = @(Get-Child $Record 'privateEndpointConnections' | Where-Object { $_ }) }
        elseif ($null -ne $Record.resource.properties.privateEndpointConnections) { $connections = @($Record.resource.properties.privateEndpointConnections | Where-Object { $_ }) }
        else { return New-Unknown 'Private endpoint connections could not be read' }
        $states = @($connections | ForEach-Object { [string]$_.properties.privateLinkServiceConnectionState.status })
        $notApproved = @($states | Where-Object { $_ -ne 'Approved' })
        $evidence = [ordered]@{ privateEndpointConnections = $connections.Count; notApproved = $notApproved.Count }
        if (-not $connections.Count) { return New-Fail 'No private endpoint' $evidence }
        if ($notApproved) { return New-Fail "$($notApproved.Count) private endpoint connection(s) not approved" $evidence }
        New-Pass "$($connections.Count) approved private endpoint connection(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BATCH-004'
    Title         = 'Batch accounts disable public network access'
    Category      = 'Network security'
    Service       = 'Batch'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of Batch accounts is Disabled. SecuredByPerimeter (a network security perimeter) does not count as disabled.'
    Rationale     = 'With public network access enabled the Batch service API of the account is reachable from the Internet and protected by keys or tokens alone.'
    Remediation   = 'Create private endpoints and set public network access to Disabled (az batch account create --public-network-access Disabled, or the Networking blade).'
    References    = @('https://learn.microsoft.com/azure/batch/public-network-access')
    Policy        = @{ '74c5a0ae-5e48-4738-b093-65e23a060488' = 'Public network access should be disabled for Batch accounts' }
    ResourceTypes = $batchType
    Evaluate      = {
        param($Record)
        $access = [string]$Record.resource.properties.publicNetworkAccess
        $evidence = [ordered]@{ publicNetworkAccess = $access }
        if ($access -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($access) { $access } else { 'not set (enabled by default)' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BATCH-005'
    Title         = 'Batch account service and audit logs are exported'
    Category      = 'Logging and threat detection'
    Service       = 'Batch'
    Severity      = 'Medium'
    Description   = 'Checks that a diagnostic setting of each Batch account sends the ServiceLog and AuditLog categories (or the allLogs category group) to a Log Analytics workspace, storage account or event hub.'
    Rationale     = 'The service log records the operations on pools, jobs and tasks and the audit log the management of the account; without them abuse of the account cannot be detected or investigated.'
    Remediation   = 'Create a diagnostic setting with the allLogs category group, or ServiceLog and AuditLog, to a central Log Analytics workspace.'
    References    = @('https://learn.microsoft.com/azure/batch/batch-diagnostics')
    Defender      = @{ '32771b45-220c-1a8b-584e-fdd5a2584a66' = 'Diagnostic logs in Batch accounts should be enabled' }
    Policy        = @{ '428256e6-1fac-4f48-a757-df34c2b3336d' = 'Resource logs in Batch accounts should be enabled' }
    ResourceTypes = $batchType
    Evaluate      = {
        param($Record)
        if ($null -eq $Record.diagnosticSettings) { return New-Unknown 'Diagnostic settings could not be read' }
        $covering = [System.Collections.Generic.List[string]]::new()
        foreach ($setting in @($Record.diagnosticSettings | Where-Object { $_ })) {
            $p = $setting.properties
            if (-not ($p.workspaceId -or $p.storageAccountId -or $p.eventHubAuthorizationRuleId -or $p.marketplacePartnerId)) { continue }
            $enabled = @($p.logs | Where-Object { $_ -and $_.enabled })
            if ($enabled | Where-Object { $_.categoryGroup -eq 'allLogs' }) { $covering.Add([string]$setting.name); continue }
            $categories = @($enabled | ForEach-Object { [string]$_.category })
            #the audit category group holds AuditLog only
            if ($enabled | Where-Object { $_.categoryGroup -eq 'audit' }) { $categories += 'AuditLog' }
            if ('ServiceLog' -in $categories -and 'AuditLog' -in $categories) { $covering.Add([string]$setting.name) }
        }
        $evidence = [ordered]@{ diagnosticSettings = @($Record.diagnosticSettings | Where-Object { $_ } | ForEach-Object name | Sort-Object); exportingBoth = @($covering | Sort-Object) }
        if ($covering.Count) { return New-Pass "ServiceLog and AuditLog exported by $($evidence.exportingBoth -join ', ')" $evidence }
        New-Fail 'No diagnostic setting exports both ServiceLog and AuditLog' $evidence
    }
}
