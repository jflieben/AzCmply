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

#user databases of SQL servers; master and dedicated SQL pools (data warehouses) have their own backup model
function Test-UserDatabase {
    param($Record)
    return ($Record.type -ne 'Microsoft.Sql/servers/databases' -or ($Record.resource.name -ne 'master' -and [string]$Record.resource.kind -notmatch '(?i)system|datawarehouse'))
}

Add-AzTest @{
    Id            = 'AZ-BCK-007'
    Title         = 'Database backups are stored geo-redundantly'
    Category      = 'Backup and recovery'
    Service       = 'Databases'
    Severity      = 'Medium'
    Description   = 'Checks the backup storage redundancy of Azure SQL databases and managed instances, geo-redundant backup on PostgreSQL and MySQL flexible servers, and the backup policy of Cosmos DB accounts.'
    Rationale     = 'Point-in-time restore depends on the backups the database service makes itself. Kept only in the primary region, they are lost together with the database in a regional outage or disaster.'
    Remediation   = 'Use geo-redundant (or geo-zone-redundant) backup storage on SQL databases and managed instances, enable geo-redundant backup on PostgreSQL and MySQL flexible servers (only possible when the server is created), and use geo-redundant periodic backup or a second region for Cosmos DB.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/automated-backups-overview', 'https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-backup-restore', 'https://learn.microsoft.com/azure/cosmos-db/periodic-backup-storage-redundancy')
    Frameworks    = @{ MCSB = 'BR-1' }
    ResourceTypes = @('Microsoft.Sql/servers/databases', 'Microsoft.Sql/managedInstances', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DocumentDB/databaseAccounts')
    Filter        = { param($Record) Test-UserDatabase $Record }
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        if ($Record.type -eq 'Microsoft.DocumentDB/databaseAccounts') {
            $regions = @($p.locations | Where-Object { $_ } | ForEach-Object { $_.locationName })
            $evidence = [ordered]@{ backupPolicy = $p.backupPolicy.type; backupStorageRedundancy = $p.backupPolicy.periodicModeProperties.backupStorageRedundancy; regions = $regions }
            if (-not $p.backupPolicy.type) { return New-Unknown 'Backup policy could not be read' $evidence }
            if ($p.backupPolicy.type -eq 'Continuous') {
                if ($regions.Count -gt 1) { return New-Pass "Continuous backup in $($regions.Count) regions" $evidence }
                return New-Fail "Continuous backup kept in $($regions -join ', ') only" $evidence
            }
            $redundancy = $p.backupPolicy.periodicModeProperties.backupStorageRedundancy
            if (-not $redundancy) { return New-Unknown 'Periodic backup storage redundancy could not be read' $evidence }
            if ($redundancy -eq 'Geo') { return New-Pass 'Periodic backup on geo-redundant storage' $evidence }
            return New-Fail "Periodic backup on $redundancy storage" $evidence
        }
        if ($Record.type -in 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers') {
            $evidence = [ordered]@{ geoRedundantBackup = $p.backup.geoRedundantBackup; backupRetentionDays = $p.backup.backupRetentionDays }
            if (-not $p.backup.geoRedundantBackup) { return New-Unknown 'Backup settings could not be read' $evidence }
            if ($p.backup.geoRedundantBackup -eq 'Enabled') { return New-Pass 'Geo-redundant backup enabled' $evidence }
            return New-Fail "Geo-redundant backup $($p.backup.geoRedundantBackup)" $evidence
        }
        $redundancy = if ($p.currentBackupStorageRedundancy) { $p.currentBackupStorageRedundancy } else { $p.requestedBackupStorageRedundancy }
        $evidence = [ordered]@{ backupStorageRedundancy = $redundancy }
        if (-not $redundancy) { return New-Unknown 'Backup storage redundancy could not be read' $evidence }
        if ($redundancy -in 'Geo', 'GeoZone') { return New-Pass "$redundancy backup storage" $evidence }
        New-Fail "$redundancy backup storage" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-008'
    Title         = 'Azure SQL databases have long-term backup retention'
    Category      = 'Backup and recovery'
    Service       = 'Azure SQL'
    Severity      = 'Low'
    Description   = 'Checks the long-term retention policy (weekly, monthly or yearly full backups) of Azure SQL databases.'
    Rationale     = 'Point-in-time restore covers at most 35 days. Recovering from corruption or an attack found later, or meeting a retention obligation, needs backups kept for months or years.'
    Remediation   = 'Configure long-term retention on the database (SQL server > Backups > Retention policies) with the weekly, monthly and yearly retention your recovery and retention requirements ask for.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/long-term-retention-overview')
    Frameworks    = @{ MCSB = 'BR-1' }
    Policy        = @{ 'd38fc420-0735-4ef3-ac11-c806f651a570' = 'Long-term geo-redundant backup should be enabled for Azure SQL Databases' }
    ResourceTypes = @('Microsoft.Sql/servers/databases')
    Filter        = { param($Record) Test-UserDatabase $Record }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'backupLongTermRetentionPolicies')) { return New-Unknown 'The long-term retention policy could not be read' }
        $policy = @(Get-Child $Record 'backupLongTermRetentionPolicies' | Where-Object { $_ }) | Select-Object -First 1
        $p = $policy.properties
        $evidence = [ordered]@{ weeklyRetention = $p.weeklyRetention; monthlyRetention = $p.monthlyRetention; yearlyRetention = $p.yearlyRetention }
        $kept = @(foreach ($pair in @(@('weekly', $p.weeklyRetention), @('monthly', $p.monthlyRetention), @('yearly', $p.yearlyRetention))) {
                if ($pair[1] -and $pair[1] -notmatch '^PT?0+[SDWMY]$') { "$($pair[0]) $($pair[1])" }
            })
        if ($kept) { return New-Pass "Long-term retention: $($kept -join ', ')" $evidence }
        New-Fail 'No long-term retention configured' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BCK-009'
    Title         = 'Geo-redundant backup vaults allow cross region restore'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Low'
    Description   = 'Checks that Recovery Services vaults and Backup vaults with geo-redundant storage have cross region restore enabled.'
    Rationale     = 'Geo-redundant backups can only be restored in the paired region at will when cross region restore is enabled; otherwise a restore after a regional disaster waits until Microsoft declares a failover of the region.'
    Remediation   = 'Enable cross region restore on the vault (Properties > Backup configuration). It cannot be disabled again once enabled.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-create-recovery-services-vault#set-cross-region-restore')
    Frameworks    = @{ MCSB = 'BR-1' }
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        if ($Record.type -eq $rsvType) {
            $config = if (Test-ChildCollected $Record 'backupstorageconfig/vaultstorageconfig') { (Get-Child $Record 'backupstorageconfig/vaultstorageconfig').properties } else { $null }
            $redundancy = if ($p.redundancySettings.standardTierStorageRedundancy) { $p.redundancySettings.standardTierStorageRedundancy } elseif ($config.storageModelType) { $config.storageModelType } else { $config.storageType }
            $enabled = if ($p.redundancySettings.crossRegionRestore) { $p.redundancySettings.crossRegionRestore -eq 'Enabled' } elseif ($config -and $null -ne $config.crossRegionRestoreFlag) { [bool]$config.crossRegionRestoreFlag } else { $null }
        } else {
            $redundancy = (@($p.storageSettings) | Select-Object -First 1).type
            #a Backup vault only reports the setting once it has been changed; absent means disabled
            $enabled = $p.featureSettings.crossRegionRestoreSettings.state -eq 'Enabled'
        }
        $evidence = [ordered]@{ storageRedundancy = $redundancy; crossRegionRestore = $enabled }
        if (-not $redundancy) { return New-Unknown 'Storage redundancy could not be read' $evidence }
        if ($redundancy -ne 'GeoRedundant') { return New-NotApplicable "$redundancy storage (see AZ-BCK-004)" $evidence }
        if ($null -eq $enabled) { return New-Unknown 'The cross region restore setting could not be read' $evidence }
        if ($enabled) { return New-Pass 'Cross region restore enabled' $evidence }
        New-Fail 'Cross region restore disabled' $evidence
    }
}

#activity log operations that restore from a backup or fail over a replicated item
$recoveryOperations = '(?i)^(Microsoft\.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/(restore|provisionInstantItemRecovery)/action|Microsoft\.DataProtection/backupVaults/backupInstances/restore/action|Microsoft\.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/(testFailover|plannedFailover|unplannedFailover)/action)$'

function Get-RecoveryEvents {
    #vault id (lowercase) -> the most recent restore or failover the activity log records for it
    if (-not $script:Ingest.Cache.ContainsKey('#recoveryEvents')) {
        $map = @{}
        foreach ($entry in @(Get-IngestData 'activityLog/activityLog' | Where-Object { $_ })) {
            $operation = [string]$entry.operationName.value
            if ($operation -notmatch $recoveryOperations -or [string]$entry.status.value -eq 'Failed') { continue }
            if ([string]$entry.resourceId -notmatch '(?i)^(/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.(RecoveryServices/vaults|DataProtection/backupVaults)/[^/]+)/') { continue }
            $vault = $Matches[1].ToLowerInvariant()
            $age = Get-AgeInDays $entry.eventTimestamp
            if ($null -eq $age) { continue }
            if (-not $map.ContainsKey($vault) -or $age -lt $map[$vault].Age) {
                $map[$vault] = [pscustomobject]@{ Age = $age; Time = Format-UtcDate $entry.eventTimestamp; Operation = ($operation -split '/')[-2] }
            }
        }
        $script:Ingest.Cache['#recoveryEvents'] = $map
    }
    return $script:Ingest.Cache['#recoveryEvents']
}

function Get-ActivityLogDays {
    $name = 'activityLog/activityLog'
    $section = $script:Ingest.Manifest.sections.$name
    if ($section.days) { return [int]$section.days }
    if ($script:Ingest.Manifest.parameters.activityLogDays) { return [int]$script:Ingest.Manifest.parameters.activityLogDays }
    return $null
}

Add-AzTest @{
    Id            = 'AZ-BCK-010'
    Title         = 'Backup restores and disaster recovery failovers are tested'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Informational'
    Description   = 'For every Recovery Services vault and Backup vault that protects something, looks for a restore or failover in the collected activity log, and for a Site Recovery test failover in the last year.'
    Rationale     = 'A backup that has never been restored is an assumption, not a recovery capability. Regular restore tests and disaster recovery drills show that the data, the procedure and the recovery time hold up. The activity log reaches back 90 days at most, so a test done earlier in the year is not visible here.'
    Remediation   = 'Restore a representative item from each vault to an isolated location on a schedule (at least yearly), run Site Recovery test failovers into an isolated network, and keep the results as evidence.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-azure-arm-restore-vms', 'https://learn.microsoft.com/azure/site-recovery/azure-to-azure-tutorial-dr-drill')
    Frameworks    = @{ MCSB = 'BR-4' }
    Requires      = @('activityLog/activityLog')
    ResourceTypes = $backupVaultTypes
    Evaluate      = {
        param($Record)
        $isRecoveryServices = $Record.type -eq $rsvType
        $paths = if ($isRecoveryServices) { @('backupProtectedItems', 'replicationProtectedItems') } else { @('backupInstances') }
        $missing = @($paths | Where-Object { -not (Test-ChildCollected $Record $_) })
        if ($missing) { return New-Unknown "The protected items could not be read ($($missing -join ', '))" }
        $protected = @(foreach ($path in $paths) { Get-Child $Record $path | Where-Object { $_ } })
        if (-not $protected) { return New-NotApplicable 'The vault protects nothing' }
        $days = Get-ActivityLogDays
        $recovery = (Get-RecoveryEvents)[$Record.id.ToLowerInvariant()]
        $drill = @(if ($isRecoveryServices) {
                Get-Child $Record 'replicationProtectedItems' | Where-Object { $_ -and $_.properties.lastSuccessfulTestFailoverTime } | ForEach-Object {
                    [pscustomobject]@{ Name = [string]$_.properties.friendlyName; Age = Get-AgeInDays $_.properties.lastSuccessfulTestFailoverTime; Time = Format-UtcDate $_.properties.lastSuccessfulTestFailoverTime }
                }
            }) | Where-Object { $_.Age -le 365 } | Sort-Object Age, Name | Select-Object -First 1
        $evidence = [ordered]@{
            protectedItems             = $protected.Count
            activityLogDays            = $days
            lastRestoreOrFailover      = $(if ($recovery) { "$($recovery.Operation) $($recovery.Time)" } else { $null })
            lastSuccessfulTestFailover = $(if ($drill) { "$($drill.Name) $($drill.Time)" } else { $null })
        }
        if ($recovery) { return New-Pass "$($recovery.Operation) started $($recovery.Time)" $evidence }
        if ($drill) { return New-Pass "Test failover of $($drill.Name) on $($drill.Time)" $evidence }
        $window = if ($days) { "the $days days of activity log collected" } else { 'the activity log collected' }
        New-Fail "No restore or failover in $window, and no Site Recovery test failover in the last year" $evidence
    }
}

function Get-ReplicatedMachines {
    #Azure VM id (lowercase) -> Site Recovery replicated item, and whether every vault's replicated items could be read
    if (-not $script:Ingest.Cache.ContainsKey('#replicated')) {
        $machines = @{}
        $complete = -not @(Get-FailedResourceIds -Type $rsvType).Count
        foreach ($vault in (Get-AzResourceRecords -Type $rsvType)) {
            if (-not (Test-ChildCollected $vault 'replicationProtectedItems')) { $complete = $false; continue }
            foreach ($item in @(Get-Child $vault 'replicationProtectedItems' | Where-Object { $_ })) {
                $source = [string]$item.properties.providerSpecificDetails.fabricObjectId
                if ($source -match '(?i)/providers/Microsoft\.Compute/virtualMachines/[^/]+$' -and -not $machines.ContainsKey($source.ToLowerInvariant())) {
                    $machines[$source.ToLowerInvariant()] = [pscustomobject]@{ Vault = [string]$vault.resource.name; Item = $item }
                }
            }
        }
        $script:Ingest.Cache['#replicated'] = [pscustomobject]@{ Machines = $machines; Complete = $complete }
    }
    return $script:Ingest.Cache['#replicated']
}

Add-AzTest @{
    Id            = 'AZ-BCK-011'
    Title         = 'Virtual machines are replicated for disaster recovery'
    Category      = 'Backup and recovery'
    Service       = 'Azure Site Recovery'
    Severity      = 'Informational'
    Description   = 'Checks whether each virtual machine is replicated to another region with Azure Site Recovery by a Recovery Services vault in this subscription.'
    Rationale     = 'Backups restore data, but bringing a critical workload back in another region within its recovery time objective needs a replica that is ready to fail over. Not every machine needs one; the ones behind critical or important functions do.'
    Remediation   = 'Enable Site Recovery replication for the machines behind critical or important functions, choose a target region and network, and run test failovers regularly.'
    References    = @('https://learn.microsoft.com/azure/site-recovery/azure-to-azure-tutorial-enable-replication')
    Frameworks    = @{ DORA = @('Art. 11', 'Art. 12', 'RTS Art. 26') }
    Policy        = @{ '0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56' = 'Audit virtual machines without disaster recovery configured' }
    ResourceTypes = @('Microsoft.Compute/virtualMachines')
    Evaluate      = {
        param($Record)
        $replicated = Get-ReplicatedMachines
        $entry = $replicated.Machines[$Record.id.ToLowerInvariant()]
        if ($entry) {
            $p = $entry.Item.properties
            $evidence = [ordered]@{ vault = $entry.Vault; protectionState = $p.protectionState; replicationHealth = $p.replicationHealth; lastSuccessfulTestFailover = Format-UtcDate $p.lastSuccessfulTestFailoverTime }
            return New-Pass "Replicated by vault $($entry.Vault) ($($p.protectionState), health $($p.replicationHealth))" $evidence
        }
        if (-not $replicated.Complete) { return New-Unknown 'The replicated items of every Recovery Services vault could not be read' }
        New-Fail 'Not replicated with Site Recovery in this subscription'
    }
}

$zoneTypes = @(
    'Microsoft.Storage/storageAccounts', 'Microsoft.Sql/servers/databases', 'Microsoft.Sql/managedInstances', 'Microsoft.Web/serverfarms',
    'Microsoft.ContainerService/managedClusters', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers',
    'Microsoft.DocumentDB/databaseAccounts', 'Microsoft.Network/applicationGateways', 'Microsoft.Network/azureFirewalls', 'Microsoft.Compute/virtualMachineScaleSets'
)

Add-AzTest @{
    Id            = 'AZ-BCK-012'
    Title         = 'Zone capable resources are zone redundant'
    Category      = 'Backup and recovery'
    Service       = 'Multiple'
    Severity      = 'Informational'
    Description   = 'Checks zone redundancy of storage accounts, SQL databases and managed instances, App Service plans, AKS node pools, PostgreSQL and MySQL flexible servers, Cosmos DB regions, Application Gateways, Azure Firewalls and virtual machine scale sets.'
    Rationale     = 'A resource in a single availability zone is a single point of failure: a datacenter outage takes it down even though the region keeps running. Zone redundancy keeps it available without a failover. It is only possible in regions with availability zones.'
    Remediation   = 'Use zone-redundant storage (ZRS or GZRS), enable zone redundancy on databases, App Service plans (Premium v2, v3 or Isolated v2) and Cosmos DB regions, spread AKS node pools, scale sets, Application Gateways and firewalls over at least two zones, and use zone-redundant high availability for flexible servers.'
    References    = @('https://learn.microsoft.com/azure/reliability/availability-zones-overview')
    Frameworks    = @{ ALZ = 'Audit-ZoneResiliency'; DORA = @('Art. 7', 'Art. 12') }
    ResourceTypes = $zoneTypes
    Filter        = { param($Record) (Test-UserDatabase $Record) -and -not ($Record.type -eq 'Microsoft.Web/serverfarms' -and [string]$Record.resource.sku.tier -in 'Free', 'Shared', 'Dynamic', 'FlexConsumption') }
    Evaluate      = {
        param($Record)
        $r = $Record.resource
        $p = $r.properties
        $type = $Record.type
        if ($type -eq 'Microsoft.Storage/storageAccounts') {
            $evidence = [ordered]@{ sku = $r.sku.name }
            if (-not $r.sku.name) { return New-Unknown 'The replication setting could not be read' $evidence }
            if ([string]$r.sku.name -match 'ZRS$') { return New-Pass "$($r.sku.name) replicates across availability zones" $evidence }
            return New-Fail "$($r.sku.name) is not zone redundant" $evidence
        }
        if ($type -eq 'Microsoft.ContainerService/managedClusters') {
            $pools = @($p.agentPoolProfiles | Where-Object { $_ })
            $evidence = [ordered]@{ nodePools = @($pools | ForEach-Object { "$($_.name): zones $(@($_.availabilityZones | Where-Object { $_ }) -join ',')" } | Sort-Object) }
            if (-not $pools) { return New-Unknown 'The node pools could not be read' $evidence }
            $single = @($pools | Where-Object { @($_.availabilityZones | Where-Object { $_ }).Count -lt 2 } | ForEach-Object { $_.name } | Sort-Object)
            if ($single) { return New-Fail "Node pool(s) $($single -join ', ') not spread over availability zones" $evidence }
            return New-Pass 'All node pools spread over availability zones' $evidence
        }
        if ($type -in 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers') {
            $evidence = [ordered]@{ highAvailability = $p.highAvailability.mode }
            if (-not $p.highAvailability.mode) { return New-Unknown 'The high availability setting could not be read' $evidence }
            if ($p.highAvailability.mode -eq 'ZoneRedundant') { return New-Pass 'Zone-redundant high availability' $evidence }
            return New-Fail "High availability $($p.highAvailability.mode)" $evidence
        }
        if ($type -eq 'Microsoft.DocumentDB/databaseAccounts') {
            $locations = @($p.locations | Where-Object { $_ })
            $evidence = [ordered]@{ regions = @($locations | ForEach-Object { "$($_.locationName): $(if ($_.isZoneRedundant) { 'zone redundant' } else { 'single zone' })" }) }
            if (-not $locations) { return New-Unknown 'The account regions could not be read' $evidence }
            $single = @($locations | Where-Object { -not $_.isZoneRedundant } | ForEach-Object { $_.locationName })
            if ($single) { return New-Fail "Not zone redundant in $($single -join ', ')" $evidence }
            return New-Pass 'Zone redundant in every region' $evidence
        }
        if ($type -in 'Microsoft.Network/applicationGateways', 'Microsoft.Network/azureFirewalls', 'Microsoft.Compute/virtualMachineScaleSets') {
            $zones = @($r.zones | Where-Object { $_ })
            $evidence = [ordered]@{ zones = $zones }
            if ($zones.Count -ge 2) { return New-Pass "Spread over zones $($zones -join ', ')" $evidence }
            $detail = if ($zones) { "Deployed in zone $($zones -join ', ') only" } else { 'Not deployed across availability zones' }
            return New-Fail $detail $evidence
        }
        #SQL databases, managed instances and App Service plans
        $evidence = [ordered]@{ zoneRedundant = $p.zoneRedundant; sku = $r.sku.name }
        if ($null -eq $p.zoneRedundant) { return New-Unknown 'The zone redundancy setting could not be read' $evidence }
        if ($p.zoneRedundant) { return New-Pass 'Zone redundant' $evidence }
        New-Fail 'Not zone redundant' $evidence
    }
}
