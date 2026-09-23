#Backup and recovery: Recovery Services vaults and Backup vaults

$rsvType = 'Microsoft.RecoveryServices/vaults'
$backupVaultType = 'Microsoft.DataProtection/backupVaults'
$backupVaultTypes = @($rsvType, $backupVaultType)

Add-AzTest @{
    Id            = 'AZ-BCK-001'
    Title         = 'Backup vaults have soft delete enabled'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'High'
    Description   = 'Checks soft delete on Recovery Services vaults and Backup vaults (Always-on soft delete is the strongest setting).'
    Rationale     = 'Attackers delete backups before encrypting production data. Soft delete keeps deleted backup data recoverable for at least 14 days.'
    Remediation   = 'Enable soft delete and make it always-on so it cannot be disabled (vault Properties > Security settings > Soft delete).'
    References    = @('https://learn.microsoft.com/azure/backup/secure-by-default')
    Frameworks    = @{ MCSB = 'BR-2'; WAF = 'SE:12' }
    Policy        = @{ '31b8092a-36b8-434b-9af7-5ec844364148' = 'Soft delete must be enabled for Recovery Services Vaults.'; '9798d31d-6028-4dee-8643-46102185c016' = 'Soft delete should be enabled for Backup Vaults' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $state = $Record.resource.properties.securitySettings.softDeleteSettings.softDeleteState
        if (-not $state) { $state = $Record.resource.properties.securitySettings.softDeleteSettings.state }
        if (-not $state -and $Record.type -eq $rsvType) { $state = (Get-Child $Record 'backupconfig/vaultconfig').properties.softDeleteFeatureState }
        $evidence = [ordered]@{ softDeleteState = $state }
        if (-not $state) { return New-Unknown 'Soft delete state could not be read' $evidence }
        if ($state -match '^(Enabled|On|AlwaysOn)$') { return New-Pass "Soft delete $state" $evidence }
        New-Fail "Soft delete $state" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-002'
    Title         = 'Backup vaults have immutability enabled'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Medium'
    Description   = 'Checks the immutability state of Recovery Services vaults and Backup vaults (Locked is irreversible and strongest).'
    Rationale     = 'Immutability prevents recovery points from being deleted or their retention reduced before they expire, even by a compromised administrator.'
    Remediation   = 'Enable immutability on the vault and lock it once retention settings are final.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-azure-immutable-vault-concept')
    Frameworks    = @{ MCSB = 'BR-2'; WAF = 'SE:12' }
    Policy        = @{ 'd6f6f560-14b7-49a4-9fc8-d2c3a9807868' = 'Immutability must be enabled for Recovery Services vaults'; '2514263b-bc0d-4b06-ac3e-f262c0979018' = 'Immutability must be enabled for backup vaults' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $state = $Record.resource.properties.securitySettings.immutabilitySettings.state
        $evidence = [ordered]@{ immutabilityState = $state }
        if ($state -in 'Locked', 'Unlocked') { return New-Pass "Immutability $state" $evidence }
        New-Fail "Immutability $(if ($state) { $state } else { 'not configured' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-003'
    Title         = 'Backup vaults are protected with Multi-User Authorization'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Low'
    Description   = 'Checks for a Resource Guard association (Multi-User Authorization) on Recovery Services vaults and Backup vaults.'
    Rationale     = 'With Multi-User Authorization, destructive operations such as disabling soft delete or reducing retention need approval on a Resource Guard owned by another team or tenant.'
    Remediation   = 'Create a Resource Guard in a separate subscription or tenant and associate it with the vault.'
    References    = @('https://learn.microsoft.com/azure/backup/multi-user-authorization-concept')
    Frameworks    = @{ MCSB = @('BR-2', 'PA-1') }
    Policy        = @{ 'c7031eab-0fc0-4cd9-acd0-4497bd66d91a' = 'Multi-User Authorization (MUA) must be enabled for Recovery Services Vaults.'; 'c58e083e-7982-4e24-afdc-be14d312389e' = 'Multi-User Authorization (MUA) must be enabled for Backup Vaults.' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'backupResourceGuardProxies')) { return New-Unknown 'Resource Guard associations could not be read' }
        $guards = @(Get-Child $Record 'backupResourceGuardProxies' | Where-Object { $_ })
        $evidence = [ordered]@{ resourceGuards = @($guards | ForEach-Object { $_.properties.resourceGuardResourceId } | Sort-Object) }
        if ($guards) { return New-Pass 'Resource Guard associated' $evidence }
        New-Fail 'No Resource Guard' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-004'
    Title         = 'Backup vaults store backups geo-redundantly'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Low'
    Description   = 'Checks the backup storage redundancy of Recovery Services vaults and Backup vaults.'
    Rationale     = 'Geo-redundant backup storage (with cross region restore) keeps backups available after a regional disaster.'
    Remediation   = 'Set storage redundancy to geo-redundant before protecting the first item (it cannot be changed afterwards) and enable cross region restore.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-create-recovery-services-vault#set-storage-redundancy')
    Frameworks    = @{ MCSB = 'BR-1' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $type = if ($Record.type -eq $rsvType) {
            $config = (Get-Child $Record 'backupstorageconfig/vaultstorageconfig').properties
            if ($config.storageModelType) { $config.storageModelType } elseif ($config.storageType) { $config.storageType } else { $Record.resource.properties.redundancySettings.standardTierStorageRedundancy }
        } else { (@($Record.resource.properties.storageSettings) | Select-Object -First 1).type }
        $evidence = [ordered]@{ storageRedundancy = $type }
        if (-not $type) { return New-Unknown 'Storage redundancy could not be read' $evidence }
        if ($type -eq 'GeoRedundant') { return New-Pass 'Geo-redundant' $evidence }
        New-Fail "$type storage" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-005'
    Title         = 'Backup vaults disable cross subscription restore'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Low'
    Description   = 'Checks the cross subscription restore setting of Recovery Services vaults and Backup vaults.'
    Rationale     = 'Cross subscription restore lets backup data be restored into another subscription, which an attacker with backup operator rights can use to exfiltrate data.'
    Remediation   = 'Disable cross subscription restore (or disable it permanently) unless it is a documented requirement.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-azure-arm-restore-vms')
    Frameworks    = @{ MCSB = @('BR-2', 'DP-2') }
    Policy        = @{ 'f19b0c83-716f-4b81-85e3-2dbf057c35d6' = 'Disable Cross Subscription Restore for Azure Recovery Services vaults'; '4d479a11-f2b5-4f0a-bb1e-d2332aa95cda' = 'Disable Cross Subscription Restore for Backup Vaults' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $state = if ($Record.type -eq $rsvType) { $p.restoreSettings.crossSubscriptionRestoreSettings.crossSubscriptionRestoreState } else { $p.featureSettings.crossSubscriptionRestoreSettings.state }
        $evidence = [ordered]@{ crossSubscriptionRestore = $state }
        if ($state -in 'Disabled', 'PermanentlyDisabled') { return New-Pass "Cross subscription restore $state" $evidence }
        New-Fail "Cross subscription restore $(if ($state) { $state } else { 'enabled (default)' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-006'
    Title         = 'Backup job failures raise Azure Monitor alerts'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Low'
    Description   = 'Checks that built-in Azure Monitor alerts for all job failures are enabled on Recovery Services vaults and Backup vaults.'
    Rationale     = 'Failing backups are only useful to know about before a restore is needed; alerts on job failures make backup monitoring part of daily operations.'
    Remediation   = "Enable 'Use Azure Monitor alerts for all job failures' in the vault monitoring settings and route alerts through an action group."
    References    = @('https://learn.microsoft.com/azure/backup/backup-azure-monitoring-built-in-monitor')
    Frameworks    = @{ MCSB = 'BR-3'; WAF = 'SE:10' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $settings = $Record.resource.properties.monitoringSettings.azureMonitorAlertSettings
        $evidence = [ordered]@{ alertsForAllJobFailures = $settings.alertsForAllJobFailures }
        if ($settings.alertsForAllJobFailures -eq 'Enabled') { return New-Pass 'Alerts for job failures enabled' $evidence }
        New-Fail 'No Azure Monitor alerts for job failures' $evidence
    }
}
