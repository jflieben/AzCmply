#Compute: virtual machines, scale sets, Arc machines, managed disks and Azure Virtual Desktop

$vmType = 'Microsoft.Compute/virtualMachines'
$vmssType = 'Microsoft.Compute/virtualMachineScaleSets'
$arcType = 'Microsoft.HybridCompute/machines'

function Get-MachineProfile {
    #VM properties, or the VM profile of a scale set
    param($Record)
    if ($Record.type -eq $vmssType) { return $Record.resource.properties.virtualMachineProfile }
    return $Record.resource.properties
}

function Get-MachineExtensions {
    #'publisher/type' of the extensions of a VM, scale set or Arc machine
    param($Record)
    $extensions = @(Get-Child $Record 'extensions' | Where-Object { $_ })
    if ($Record.type -eq $vmssType) { $extensions += @($Record.resource.properties.virtualMachineProfile.extensionProfile.extensions | Where-Object { $_ }) }
    @($extensions | ForEach-Object { "$($_.properties.publisher)/$(if ($_.properties.type) { $_.properties.type } else { $_.type })" } | Sort-Object -Unique)
}

function Test-MachineExtensionsCollected {
    #false when the extension list of a machine was not read, so neither the presence nor the absence
    #of an agent can be concluded. Scale sets also carry extensions in the VM profile on the resource itself.
    param($Record)
    if (Test-ChildCollected $Record 'extensions') { return $true }
    return ($Record.type -eq $vmssType -and $null -ne $Record.resource.properties.virtualMachineProfile.extensionProfile)
}

function Get-MachineOsType {
    param($Record)
    if ($Record.type -eq $arcType) { return $Record.resource.properties.osType }
    return (Get-MachineProfile $Record).storageProfile.osDisk.osType
}

Add-AzTest @{
    Id            = 'AZ-VM-001'
    Title         = 'Virtual machines use managed disks'
    Category      = 'Posture and vulnerability management'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks that the OS disk of each virtual machine is a managed disk.'
    Rationale     = 'Unmanaged (page blob) disks live in storage accounts that can be read with an account key or SAS, lack disk level RBAC, encryption at host and network access policies, and are being retired.'
    Remediation   = 'Convert the virtual machine to managed disks (az vm convert ...).'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks')
    Policy        = @{ '06a78e20-9358-41c9-923c-fb736d382a4d' = 'Audit VMs that do not use managed disks' }
    ResourceTypes = @($vmType)
    Evaluate      = {
        param($Record)
        $osDisk = $Record.resource.properties.storageProfile.osDisk
        $evidence = [ordered]@{ managedDisk = [bool]$osDisk.managedDisk; vhd = $osDisk.vhd.uri }
        if ($osDisk.managedDisk) { return New-Pass 'Managed OS disk' $evidence }
        New-Fail 'Unmanaged OS disk' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-002'
    Title         = 'Virtual machines use encryption at host'
    Category      = 'Data protection'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks virtual machines and scale sets for encryption at host (or confidential VM disk encryption).'
    Rationale     = 'Encryption at host encrypts temporary disks, caches and data flows to storage end to end; server side encryption alone leaves the temp disk and cache unencrypted.'
    Remediation   = 'Register the EncryptionAtHost feature, deallocate the VM and enable encryption at host (az vm update --set securityProfile.encryptionAtHost=true ...). Azure Disk Encryption is scheduled for retirement; prefer encryption at host.'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview')
    Defender      = @{ 'efbbd784-656d-473a-9863-ea7693bfcd2a' = 'Virtual machines and virtual machine scale sets should have encryption at host enabled' }
    Policy        = @{ 'fc4d8e41-e223-45ea-9bf5-eada37891d87' = 'Virtual machines and virtual machine scale sets should have encryption at host enabled' }
    ResourceTypes = @($vmType, $vmssType)
    Evaluate      = {
        param($Record)
        $security = (Get-MachineProfile $Record).securityProfile
        $evidence = [ordered]@{ encryptionAtHost = [bool]$security.encryptionAtHost; securityType = $security.securityType }
        if ($security.encryptionAtHost -or $security.securityType -eq 'ConfidentialVM') { return New-Pass $(if ($security.encryptionAtHost) { 'Encryption at host enabled' } else { 'Confidential VM' }) $evidence }
        New-Fail 'Encryption at host not enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-003'
    Title         = 'Virtual machines use Trusted Launch with Secure Boot and vTPM'
    Category      = 'Posture and vulnerability management'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks the security type of virtual machines and scale sets for Trusted Launch (or confidential VM) with Secure Boot and vTPM enabled.'
    Rationale     = 'Secure Boot and a virtual TPM protect against boot kits, rootkits and kernel level malware and enable boot integrity monitoring.'
    Remediation   = 'Enable Trusted Launch with Secure Boot and vTPM (existing Gen2 VMs can be upgraded in place: az vm update --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true ...).'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/trusted-launch')
    Policy        = @{ '97566dd7-78ae-4997-8b36-1c7bfe0d8121' = '[Preview]: Secure Boot should be enabled on supported Windows virtual machines'; '1c30f9cd-b84c-49cc-aa2c-9288447cc3b3' = '[Preview]: vTPM should be enabled on supported virtual machines' }
    ResourceTypes = @($vmType, $vmssType)
    Evaluate      = {
        param($Record)
        $security = (Get-MachineProfile $Record).securityProfile
        $evidence = [ordered]@{ securityType = $security.securityType; secureBootEnabled = [bool]$security.uefiSettings.secureBootEnabled; vTpmEnabled = [bool]$security.uefiSettings.vTpmEnabled }
        if ($security.securityType -in 'TrustedLaunch', 'ConfidentialVM' -and $security.uefiSettings.secureBootEnabled -and $security.uefiSettings.vTpmEnabled) { return New-Pass "$($security.securityType) with Secure Boot and vTPM" $evidence }
        $missing = @()
        if ($security.securityType -notin 'TrustedLaunch', 'ConfidentialVM') { $missing += 'Trusted Launch' }
        if (-not $security.uefiSettings.secureBootEnabled) { $missing += 'Secure Boot' }
        if (-not $security.uefiSettings.vTpmEnabled) { $missing += 'vTPM' }
        New-Fail "Not enabled: $($missing -join ', ')" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-004'
    Title         = 'Linux virtual machines require SSH keys'
    Category      = 'Identity management'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks that password authentication is disabled on Linux virtual machines and scale sets.'
    Rationale     = 'Password based SSH is exposed to brute force and password reuse; SSH keys (or Entra login for Linux) are far stronger.'
    Remediation   = 'Configure SSH keys or the Entra login extension and set disablePasswordAuthentication to true; for existing VMs disable PasswordAuthentication in sshd_config.'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/linux/create-ssh-keys-detailed')
    Policy        = @{ '630c64f9-8b6b-4c64-b511-6544ceff6fd6' = 'Authentication to Linux machines should require SSH keys' }
    ResourceTypes = @($vmType, $vmssType)
    Filter        = { param($Record) (Get-MachineOsType $Record) -eq 'Linux' }
    Evaluate      = {
        param($Record)
        $osProfile = (Get-MachineProfile $Record).osProfile
        if (-not $osProfile) { return New-Unknown 'No OS profile (VM created from a specialized disk); check sshd configuration inside the VM' }
        $value = $osProfile.linuxConfiguration.disablePasswordAuthentication
        $evidence = [ordered]@{ disablePasswordAuthentication = $value }
        if ($value -eq $true) { return New-Pass 'Password authentication disabled' $evidence }
        New-Fail 'Password authentication enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-005'
    Title         = 'Virtual machines periodically assess missing updates'
    Category      = 'Posture and vulnerability management'
    Service       = 'Azure Update Manager'
    Severity      = 'Medium'
    Description   = 'Checks that the patch assessment mode of virtual machines is AutomaticByPlatform (periodic assessment by Azure Update Manager).'
    Rationale     = 'Without periodic assessment, missing security updates are not reported and unpatched vulnerabilities go unnoticed.'
    Remediation   = "Enable periodic assessment (az vm update --set osProfile.windowsConfiguration.patchSettings.assessmentMode=AutomaticByPlatform ...) or assign the 'Configure periodic checking for missing system updates' policy."
    References    = @('https://learn.microsoft.com/azure/update-manager/assessment-options')
    Defender      = @{ '90386950-71ca-4357-a12e-486d1679427c' = 'Machines should be configured to periodically check for missing system updates' }
    Policy        = @{ 'bd876905-5b84-4f73-ab2d-2e7a7c4568d9' = 'Machines should be configured to periodically check for missing system updates' }
    ResourceTypes = @($vmType)
    Evaluate      = {
        param($Record)
        $osProfile = $Record.resource.properties.osProfile
        if (-not $osProfile) { return New-Unknown 'No OS profile (VM created from a specialized disk); check assessment in Azure Update Manager' }
        $settings = if ($osProfile.windowsConfiguration) { $osProfile.windowsConfiguration.patchSettings } else { $osProfile.linuxConfiguration.patchSettings }
        $evidence = [ordered]@{ assessmentMode = $settings.assessmentMode; patchMode = $settings.patchMode }
        if ($settings.assessmentMode -eq 'AutomaticByPlatform') { return New-Pass 'Periodic assessment enabled' $evidence }
        New-Fail "Assessment mode $(if ($settings.assessmentMode) { $settings.assessmentMode } else { 'ImageDefault' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-006'
    Version       = 2
    Title         = 'Machines run Microsoft Defender for Endpoint'
    Category      = 'Endpoint security'
    Service       = 'Virtual machines'
    Severity      = 'High'
    Description   = 'Checks virtual machines, scale sets and Arc machines for the Microsoft Defender for Endpoint extension (MDE.Windows or MDE.Linux).'
    Rationale     = 'Without EDR, malware, ransomware and hands-on-keyboard attacks on the machine are neither prevented nor detected.'
    Remediation   = 'Enable Defender for Servers with the endpoint protection component, which deploys the MDE extension automatically, or onboard the machine to Defender for Endpoint directly.'
    References    = @('https://learn.microsoft.com/azure/defender-for-cloud/integration-defender-for-endpoint')
    Defender      = @{ '06e3a6db-6c0c-4ad9-943f-31d9d73ecf6c' = 'EDR solution should be installed on Virtual Machines' }
    ResourceTypes = @($vmType, $vmssType, $arcType)
    Evaluate      = {
        param($Record)
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read' }
        $extensions = @(Get-MachineExtensions $Record)
        $evidence = [ordered]@{ extensions = $extensions }
        if ($extensions | Where-Object { $_ -match '/MDE\.(Windows|Linux)$' }) { return New-Pass 'Defender for Endpoint extension installed' $evidence }
        New-Fail 'No Defender for Endpoint extension' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-007'
    Version       = 2
    Title         = 'Machines have the guest configuration extension with a system assigned identity'
    Category      = 'Posture and vulnerability management'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks virtual machines for the Azure machine configuration (guest configuration) extension and a system assigned managed identity.'
    Rationale     = 'Machine configuration audits the operating system against the Azure compute security baseline and custom baselines; without it OS hardening drift is not measured.'
    Remediation   = "Assign the 'Deploy prerequisites to enable Guest Configuration policies on virtual machines' initiative, which adds the extension and identity."
    References    = @('https://learn.microsoft.com/azure/governance/machine-configuration/overview')
    Defender      = @{ '6c99f570-2ce7-46bc-8175-cde013df43bc' = 'Guest Configuration extension should be installed on machines'; '69133b6b-695a-43eb-a763-221e19556755' = "Virtual machines' Guest Configuration extension should be deployed with system-assigned managed identity" }
    Policy        = @{ 'ae89ebca-1c92-4898-ac2c-9f63decb045c' = 'Guest Configuration extension should be installed on your machines' }
    ResourceTypes = @($vmType)
    Evaluate      = {
        param($Record)
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read' }
        $extensions = @(Get-MachineExtensions $Record)
        $installed = [bool]($extensions | Where-Object { $_ -match '^Microsoft\.GuestConfiguration/' })
        $systemIdentity = [string]$Record.resource.identity.type -match 'SystemAssigned'
        $evidence = [ordered]@{ guestConfigurationExtension = $installed; systemAssignedIdentity = $systemIdentity }
        if ($installed -and $systemIdentity) { return New-Pass 'Guest configuration enabled' $evidence }
        New-Fail $(if (-not $installed) { 'Guest configuration extension missing' } else { 'No system assigned managed identity' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-008'
    Version       = 2
    Title         = 'Machines run the Azure Monitor Agent'
    Category      = 'Logging and threat detection'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Checks virtual machines, scale sets and Arc machines for the Azure Monitor Agent extension.'
    Rationale     = 'The Azure Monitor Agent collects security events, syslog and performance data for Sentinel and Defender; without it host level activity is invisible to the SOC.'
    Remediation   = 'Install the Azure Monitor Agent (az vm extension set --name AzureMonitorWindowsAgent|AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor ...) and associate data collection rules.'
    References    = @('https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview')
    ResourceTypes = @($vmType, $vmssType, $arcType)
    Evaluate      = {
        param($Record)
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read' }
        $extensions = @(Get-MachineExtensions $Record)
        $evidence = [ordered]@{ extensions = $extensions }
        if ($extensions | Where-Object { $_ -match '/AzureMonitor(Windows|Linux)Agent$' }) { return New-Pass 'Azure Monitor Agent installed' $evidence }
        New-Fail 'No Azure Monitor Agent' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-009'
    Version       = 2
    Title         = 'Machines do not run the retired Log Analytics agent'
    Category      = 'Logging and threat detection'
    Service       = 'Virtual machines'
    Severity      = 'Medium'
    Description   = 'Finds virtual machines, scale sets and Arc machines with the legacy Log Analytics agent (MicrosoftMonitoringAgent / OmsAgentForLinux), retired since August 2024.'
    Rationale     = 'The retired agent no longer receives security updates or support, and its data collection may stop working at any time.'
    Remediation   = 'Migrate data collection to the Azure Monitor Agent with data collection rules, then remove the legacy extension.'
    References    = @('https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-migration')
    Policy        = @{ 'd2185817-5b7e-473c-aadd-9de6ac114280' = 'The legacy Log Analytics extension should not be installed on virtual machines'; 'ba6881f9-ab93-498b-8bad-bb91b1d755bf' = 'The legacy Log Analytics extension should not be installed on virtual machine scale sets' }
    ResourceTypes = @($vmType, $vmssType, $arcType)
    Evaluate      = {
        param($Record)
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read' }
        $legacy = @(Get-MachineExtensions $Record | Where-Object { $_ -match '/(MicrosoftMonitoringAgent|OmsAgentForLinux)$' })
        $evidence = [ordered]@{ legacyExtensions = $legacy }
        if ($legacy) { return New-Fail "Legacy agent installed: $($legacy -join ', ')" $evidence }
        New-Pass 'No legacy Log Analytics agent' $evidence
    }
}

function Get-BackupProtectedIds {
    #lowercase ids of resources protected by Recovery Services vaults; $null when no vault data was readable
    $ids = [System.Collections.Generic.HashSet[string]]::new()
    $readable = $false
    foreach ($vault in (Get-AzResourceRecords -Type 'Microsoft.RecoveryServices/vaults')) {
        if (-not (Test-ChildCollected $vault 'backupProtectedItems')) { continue }
        $readable = $true
        foreach ($item in @(Get-Child $vault 'backupProtectedItems' | Where-Object { $_ })) {
            foreach ($id in @($item.properties.sourceResourceId, $item.properties.virtualMachineId)) { if ($id) { $null = $ids.Add($id.ToLowerInvariant()) } }
        }
    }
    if (-not $readable -and @(Get-AzResourceRecords -Type 'Microsoft.RecoveryServices/vaults').Count) { return $null }
    return , $ids
}

Add-AzTest @{
    Id            = 'AZ-VM-010'
    Title         = 'Virtual machines are protected by Azure Backup'
    Category      = 'Backup and recovery'
    Service       = 'Azure Backup'
    Severity      = 'Medium'
    Description   = 'Checks that each virtual machine is a protected item in a Recovery Services vault in this subscription.'
    Rationale     = 'Without backups a VM cannot be restored after ransomware, destructive attacks or accidental deletion.'
    Remediation   = 'Enable backup for the VM with an enhanced policy in a vault with immutability and soft delete (az backup protection enable-for-vm ...). VMs backed up by a vault in another subscription or by another product must be verified manually.'
    References    = @('https://learn.microsoft.com/azure/backup/backup-azure-vms-introduction')
    Policy        = @{ '013e242c-8828-4970-87b3-ab247555486d' = 'Azure Backup should be enabled for Virtual Machines' }
    ResourceTypes = @($vmType)
    Evaluate      = {
        param($Record)
        $protected = Get-BackupProtectedIds
        if ($null -eq $protected) { return New-Unknown 'Backup protected items could not be read' }
        if ($protected.Contains($Record.id.ToLowerInvariant())) { return New-Pass 'Protected by Azure Backup' }
        New-Fail 'Not protected by a Recovery Services vault in this subscription'
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-011'
    Title         = 'Managed disks disable public network access'
    Category      = 'Network security'
    Service       = 'Managed disks'
    Severity      = 'Medium'
    Description   = 'Checks the network access policy and public network access of managed disks, which control disk export and import over SAS URLs.'
    Rationale     = "With 'AllowAll' anyone with Contributor rights can generate a SAS URL and download the whole disk (including credentials and data) from the Internet."
    Remediation   = 'Set the network access policy to DenyAll, or AllowPrivate with a disk access resource, and disable public network access (az disk update --network-access-policy DenyAll --public-network-access Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/disks-enable-private-links-for-import-export-portal')
    Defender      = @{ 'f635fb12-4c7f-e9a8-5ed1-c005728ea849' = 'Managed disks should disable public network access' }
    Policy        = @{ '8405fdab-1faf-48aa-b702-999c9c172094' = 'Managed disks should disable public network access' }
    ResourceTypes = @('Microsoft.Compute/disks')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ networkAccessPolicy = $p.networkAccessPolicy; publicNetworkAccess = $p.publicNetworkAccess }
        if ($p.networkAccessPolicy -in 'DenyAll', 'AllowPrivate' -or $p.publicNetworkAccess -eq 'Disabled') { return New-Pass "Network access policy $($p.networkAccessPolicy)" $evidence }
        New-Fail 'Disk export over the Internet is allowed' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-012'
    Title         = 'Disk snapshots disable public network export'
    Category      = 'Network security'
    Service       = 'Managed disks'
    Severity      = 'Medium'
    Description   = 'Checks the network access policy and public network access of managed disk snapshots, and flags any snapshot with a live export session (SAS or upload). Managed disks themselves are covered by AZ-VM-011.'
    Rationale     = "A snapshot is a full copy of a disk and is often left behind long after the disk is gone. With an 'AllowAll' network policy anyone with Contributor rights can mint a SAS URL and download it, including credentials and data, from the Internet. An active export session means such a URL is live right now."
    Remediation   = 'Set the snapshot network access policy to DenyAll, or AllowPrivate with a disk access resource, and disable public network access (az snapshot update --network-access-policy DenyAll --public-network-access Disabled ...). Revoke any active export with az snapshot revoke-access and delete snapshots that are no longer needed.'
    References     = @('https://learn.microsoft.com/azure/virtual-machines/disks-enable-private-links-for-import-export-portal')
    ResourceTypes = @('Microsoft.Compute/snapshots')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ networkAccessPolicy = $p.networkAccessPolicy; publicNetworkAccess = $p.publicNetworkAccess; diskState = $p.diskState }
        if ([string]$p.diskState -in 'ActiveSAS', 'ActiveSASFrozen', 'ActiveUpload', 'ActiveUploadSAS') { return New-Fail 'A snapshot export session (SAS or upload) is currently active' $evidence }
        if ($p.networkAccessPolicy -in 'DenyAll', 'AllowPrivate' -or $p.publicNetworkAccess -eq 'Disabled') { return New-Pass "Network access policy $($p.networkAccessPolicy)" $evidence }
        New-Fail 'Snapshot export over the Internet is allowed' $evidence
    }
}

$dataCollectionRuleAssociationsPath = 'providers/Microsoft.Insights/dataCollectionRuleAssociations'

Add-AzTest @{
    Id            = 'AZ-VM-013'
    Title         = 'Change Tracking and Inventory is enabled on machines'
    Category      = 'Asset management'
    Service       = 'Virtual machines'
    Severity      = 'Low'
    Description   = 'Checks virtual machines, scale sets and Arc machines for the Change Tracking extension with the Azure Monitor Agent, and for an associated data collection rule that collects change tracking data. Scale sets managed by AKS are left out.'
    Rationale     = 'Change Tracking and Inventory records the software, services, files and registry keys of each machine and every change to them. It is the software inventory of the fleet and shows unauthorized installations and configuration drift.'
    Remediation   = "Enable Change Tracking and Inventory (machine > Operations > Inventory), or assign the built-in initiatives 'Enable ChangeTracking and Inventory for virtual machines', 'for virtual machine scale sets' and 'for Arc-enabled virtual machines'."
    References    = @('https://learn.microsoft.com/azure/automation/change-tracking/overview-monitoring-agent')
    ResourceTypes = @($vmType, $vmssType, $arcType)
    Filter        = { param($Record) -not ($Record.type -eq $vmssType -and @($Record.resource.tags.PSObject.Properties.Name | Where-Object { $_ -like 'aks-managed-*' }).Count) }
    Evaluate      = {
        param($Record)
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read' }
        $extensions = @(Get-MachineExtensions $Record)
        $evidence = [ordered]@{
            changeTrackingExtension = [bool]@($extensions | Where-Object { $_ -match '^Microsoft\.Azure\.ChangeTrackingAndInventory/ChangeTracking-(Windows|Linux)$' }).Count
            azureMonitorAgent       = [bool]@($extensions | Where-Object { $_ -match '/AzureMonitor(Windows|Linux)Agent$' }).Count
        }
        if (-not $evidence.changeTrackingExtension) { return New-Fail 'No Change Tracking extension' $evidence }
        if (-not $evidence.azureMonitorAgent) { return New-Fail 'Change Tracking extension without the Azure Monitor Agent' $evidence }
        if (-not (Test-ChildCollected $Record $dataCollectionRuleAssociationsPath)) { return New-Unknown 'Data collection rule associations could not be read' $evidence }
        $ruleIds = @(Get-Child $Record $dataCollectionRuleAssociationsPath | Where-Object { $_ -and $_.properties.dataCollectionRuleId } | ForEach-Object { [string]$_.properties.dataCollectionRuleId } | Sort-Object -Unique)
        $evidence.dataCollectionRules = @($ruleIds | ForEach-Object { ($_ -split '/')[-1] })
        $unread = 0
        foreach ($ruleId in $ruleIds) {
            $rule = Get-AzResourceRecord $ruleId
            if (-not $rule) { $unread++; continue }
            if (@($rule.resource.properties.dataSources.extensions | Where-Object { $_ -and [string]$_.extensionName -match '^ChangeTracking-(Windows|Linux)$' }).Count) { return New-Pass "Data collection rule '$($rule.resource.name)' collects change tracking data" $evidence }
        }
        if ($unread) { return New-Unknown "No readable data collection rule collects change tracking data; $unread associated rule(s) could not be read" $evidence }
        New-Fail 'No associated data collection rule collects change tracking data' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AVD-001'
    Title         = 'Azure Virtual Desktop host pools and workspaces disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Virtual Desktop'
    Severity      = 'Medium'
    Description   = 'Checks the public network access setting of Azure Virtual Desktop host pools and workspaces.'
    Rationale     = 'With public network access, session hosts and users reach the host pool and the workspace feed over the Internet. Private Link keeps both connections on private networks, so only clients on those networks can discover and open the desktops.'
    Remediation   = 'Create private endpoints for the host pool (connection) and the workspaces (feed and global), then set public network access to Disabled.'
    References    = @('https://learn.microsoft.com/azure/virtual-desktop/private-link-overview')
    ResourceTypes = @('Microsoft.DesktopVirtualization/hostPools', 'Microsoft.DesktopVirtualization/workspaces')
    Evaluate      = {
        param($Record)
        $access = $Record.resource.properties.publicNetworkAccess
        $evidence = [ordered]@{ publicNetworkAccess = $access }
        if ($access -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($access) { $access } else { 'Enabled (default)' })" $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-VM-014'
    Title       = 'The serial console is disabled for the subscription'
    Category    = 'Privileged access'
    Service     = 'Virtual machines'
    Severity    = 'Low'
    Description = 'Checks the serial console setting of the subscription when it has virtual machines or scale sets. The setting only exists once the Microsoft.SerialConsole resource provider is registered; until then the serial console is enabled.'
    Rationale   = 'The serial console opens a text console on a virtual machine through the Azure portal, outside its network: network security groups, Bastion, just-in-time access and firewalls do not apply. Anyone who can change the machine and read the keys of its boot diagnostics storage (Contributor, for example) can open it, and with a local password or the single user mode of Linux it is a way in that bypasses every network control.'
    Remediation = 'Disable the serial console for the subscription (az resource invoke-action --action disableConsole --ids /subscriptions/<id>/providers/Microsoft.SerialConsole/consoleServices/default --api-version 2023-01-01) and enable it again only for a recovery.'
    References  = @('https://learn.microsoft.com/troubleshoot/azure/virtual-machines/windows/serial-console-enable-disable')
    Requires    = @('subscription/resources')
    Run         = {
        $machines = @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.type -in 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets' })
        if (-not $machines) { return New-SubscriptionFinding (New-NotApplicable 'No virtual machines or scale sets') }
        if (Test-IngestSection 'subscription/serialConsole') {
            $disabled = [bool](Get-IngestData 'subscription/serialConsole').properties.disabled
            $evidence = [ordered]@{ disabled = $disabled; machines = $machines.Count }
            if ($disabled) { return New-SubscriptionFinding (New-Pass 'The serial console is disabled' $evidence) }
            return New-SubscriptionFinding (New-Fail 'The serial console is enabled' $evidence)
        }
        #without a registered provider the setting cannot exist, so the console has its default: enabled
        $provider = @(Get-IngestData 'subscription/providers' | Where-Object { $_ -and $_.namespace -eq 'Microsoft.SerialConsole' }) | Select-Object -First 1
        $evidence = [ordered]@{ providerRegistration = $provider.registrationState; machines = $machines.Count }
        if ($provider -and $provider.registrationState -eq 'NotRegistered') { return New-SubscriptionFinding (New-Fail 'The serial console has its default, enabled: the Microsoft.SerialConsole provider was never registered to turn it off' $evidence) }
        New-SubscriptionFinding (New-Unknown "The serial console setting could not be read: $(Get-IngestSectionProblem 'subscription/serialConsole')" $evidence)
    }
}

#domain controller signals (AZ-VM-015, AZ-VM-016). Ports only a domain controller serves: Kerberos, Kerberos password change, global
#catalog and AD Web Services. LDAP is left out, AD LDS and other directories serve it too.
$dcPorts = @(88, 464, 3268, 3269, 9389)
$adDsPromotionPattern = '(?i)\b(Install-ADDS(Forest|DomainController|Domain)|ADDSDeployment|AD-Domain-Services|dcpromo|(Create|Configure|Prepare)AD[PB]DC|CreateADForest|xADDomain(Controller)?)\b'
$dcNamePattern = '(?i)(^|[^a-z0-9])(ad)?dc([^a-z]|$)|dc\d{1,3}$|domaincontroller'

function Test-AddressInPrefix {
    #true when an IPv4 address lies in an address or CIDR prefix
    param([string]$Address, [string]$Prefix)
    $parts = @($Prefix -split '/')
    if ($parts.Count -gt 2 -or ($parts.Count -eq 2 -and $parts[1] -notmatch '^\d{1,2}$')) { return $false }
    $bits = if ($parts.Count -eq 2) { [int]$parts[1] } else { 32 }
    $network = ConvertTo-IPv4Number $parts[0]
    $value = ConvertTo-IPv4Number $Address
    if ($null -eq $network -or $null -eq $value -or $bits -gt 32) { return $false }
    return (($value -shr (32 - $bits)) -eq ($network -shr (32 - $bits)))
}

function Get-DnsServerReferences {
    #address -> where it is set as DNS server (virtual networks, network interfaces, Azure Firewall, DNS forwarding rules),
    #and the sources that could not be read
    if (-not $script:Ingest.Cache.ContainsKey('#dnsServers')) {
        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($vnet in (Get-AzResourceRecords -Type 'Microsoft.Network/virtualNetworks')) {
            foreach ($address in @($vnet.resource.properties.dhcpOptions.dnsServers)) { $entries.Add([pscustomobject]@{ Address = $address; Source = "virtual network $($vnet.resource.name)" }) }
        }
        foreach ($nic in (Get-AzResourceRecords -Type 'Microsoft.Network/networkInterfaces')) {
            foreach ($address in @($nic.resource.properties.dnsSettings.dnsServers)) { $entries.Add([pscustomobject]@{ Address = $address; Source = "network interface $($nic.resource.name)" }) }
        }
        foreach ($policy in (Get-AzResourceRecords -Type 'Microsoft.Network/firewallPolicies')) {
            foreach ($address in @($policy.resource.properties.dnsSettings.servers)) { $entries.Add([pscustomobject]@{ Address = $address; Source = "firewall policy $($policy.resource.name)" }) }
        }
        foreach ($firewall in (Get-AzResourceRecords -Type 'Microsoft.Network/azureFirewalls')) {
            #a firewall without a policy keeps its DNS servers in additionalProperties
            foreach ($address in @([string]$firewall.resource.properties.additionalProperties.'Network.DNS.Servers' -split ',')) { $entries.Add([pscustomobject]@{ Address = $address; Source = "firewall $($firewall.resource.name)" }) }
        }
        $unread = [System.Collections.Generic.List[string]]::new()
        foreach ($ruleset in (Get-AzResourceRecords -Type 'Microsoft.Network/dnsForwardingRulesets')) {
            if (-not (Test-ChildCollected $ruleset 'forwardingRules')) { $unread.Add("forwarding rules of $($ruleset.resource.name)"); continue }
            foreach ($rule in @(Get-Child $ruleset 'forwardingRules' | Where-Object { $_ -and $_.properties.forwardingRuleState -ne 'Disabled' })) {
                foreach ($target in @($rule.properties.targetDnsServers | Where-Object { $_ })) { $entries.Add([pscustomobject]@{ Address = $target.ipAddress; Source = "forwarding rule for $($rule.properties.domainName) in $($ruleset.resource.name)" }) }
            }
        }
        foreach ($id in (Get-FailedResourceIds -Type 'Microsoft.Network/virtualNetworks', 'Microsoft.Network/networkInterfaces', 'Microsoft.Network/firewallPolicies', 'Microsoft.Network/azureFirewalls', 'Microsoft.Network/dnsForwardingRulesets')) {
            $unread.Add(($id -replace '(?i)^.*/providers/Microsoft\.Network/', ''))
        }
        $servers = @{}
        foreach ($entry in $entries) {
            $address = ([string]$entry.Address).Trim()
            if (-not $address) { continue }
            if (-not $servers.ContainsKey($address)) { $servers[$address] = [System.Collections.Generic.List[string]]::new() }
            if (-not $servers[$address].Contains($entry.Source)) { $servers[$address].Add($entry.Source) }
        }
        $script:Ingest.Cache['#dnsServers'] = [pscustomobject]@{ Servers = $servers; Unread = @($unread | Sort-Object -Unique) }
    }
    return $script:Ingest.Cache['#dnsServers']
}

function Get-RuleDcPorts {
    #domain controller ports an inbound allow rule names explicitly: a single port or a range of at most 10, never '*'
    param($Rule)
    $p = $Rule.properties
    if ($p.direction -ne 'Inbound' -or $p.access -ne 'Allow' -or $p.protocol -notin '*', 'Tcp', 'Udp') { return }
    $ranges = [System.Collections.Generic.List[string]]::new()
    foreach ($range in @(@($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ })) {
        if ([string]$range -match '^\d+$') { $ranges.Add([string]$range); continue }
        if ([string]$range -match '^(\d+)-(\d+)$' -and ([int]$Matches[2] - [int]$Matches[1]) -le 10) { $ranges.Add([string]$range) }
    }
    foreach ($port in $dcPorts) {
        if (@($ranges | Where-Object { Test-PortInRange -Range $_ -Port $port }).Count) { $port }
    }
}

function Test-RuleTargetsMachine {
    #true when the destination of an NSG rule includes one of the addresses or application security groups of a machine
    param($Rule, [string[]]$Addresses, [string[]]$SecurityGroups)
    $p = $Rule.properties
    $groups = @($p.destinationApplicationSecurityGroups | Where-Object { $_.id } | ForEach-Object { ([string]$_.id).ToLowerInvariant() })
    if ($groups.Count) { return [bool]@($groups | Where-Object { $_ -in $SecurityGroups }).Count }
    foreach ($prefix in @(@($p.destinationAddressPrefix) + @($p.destinationAddressPrefixes) | Where-Object { $_ })) {
        if ($prefix -in '*', 'Any', 'VirtualNetwork') { return $true }
        if (@($Addresses | Where-Object { Test-AddressInPrefix $_ $prefix }).Count) { return $true }
    }
    return $false
}

function Get-DomainControllerSignals {
    #what the Azure configuration shows of a Windows virtual machine being a domain controller. Confidence is Likely (two
    #signals or an AD DS promotion), Possible (one signal) or $null; NotRead lists the sources that could not be read.
    param($Record)
    if (-not $script:Ingest.Cache.ContainsKey('#dcSignals')) { $script:Ingest.Cache['#dcSignals'] = @{} }
    $cache = $script:Ingest.Cache['#dcSignals']
    $key = $Record.id.ToLowerInvariant()
    if ($cache.ContainsKey($key)) { return $cache[$key] }

    $p = $Record.resource.properties
    $unread = [System.Collections.Generic.List[string]]::new()
    $addresses = [System.Collections.Generic.List[string]]::new()
    $securityGroups = [System.Collections.Generic.List[string]]::new()
    $nsgIds = [ordered]@{}
    $static = $false
    $nicReferences = @($p.networkProfile.networkInterfaces | Where-Object { $_.id })
    if (-not $nicReferences) { $unread.Add('network interfaces') }
    foreach ($reference in $nicReferences) {
        $nic = Get-AzResourceRecord $reference.id
        if (-not $nic) { $unread.Add("network interface $(Get-ResourceName $reference.id)"); continue }
        if ($nic.resource.properties.networkSecurityGroup.id) { $nsgIds[([string]$nic.resource.properties.networkSecurityGroup.id).ToLowerInvariant()] = $true }
        foreach ($configuration in @($nic.resource.properties.ipConfigurations | Where-Object { $_ })) {
            $c = $configuration.properties
            if ($c.privateIPAddress) { $addresses.Add([string]$c.privateIPAddress) }
            if ($c.privateIPAllocationMethod -eq 'Static') { $static = $true }
            foreach ($group in @($c.applicationSecurityGroups | Where-Object { $_.id })) { $securityGroups.Add(([string]$group.id).ToLowerInvariant()) }
            if (-not $c.subnet.id) { continue }
            $subnetId = [string]$c.subnet.id
            $vnetId = $subnetId -replace '(?i)/subnets/[^/]+$', ''
            $vnet = Get-AzResourceRecord $vnetId
            if (-not $vnet) { $unread.Add("virtual network $(Get-ResourceName $vnetId)"); continue }
            $subnet = @($vnet.resource.properties.subnets | Where-Object { $_.id -and $_.id -eq $subnetId }) | Select-Object -First 1
            if ($subnet.properties.networkSecurityGroup.id) { $nsgIds[([string]$subnet.properties.networkSecurityGroup.id).ToLowerInvariant()] = $true }
        }
    }

    $dns = Get-DnsServerReferences
    $dnsFor = @($addresses | ForEach-Object { $dns.Servers[$_] } | ForEach-Object { $_ } | Sort-Object -Unique)

    $portRules = [System.Collections.Generic.List[string]]::new()
    foreach ($nsgId in @($nsgIds.Keys)) {
        $nsg = Get-AzResourceRecord $nsgId
        if (-not $nsg) { $unread.Add("network security group $(Get-ResourceName $nsgId)"); continue }
        foreach ($rule in @($nsg.resource.properties.securityRules | Where-Object { $_ } | Sort-Object { [int]$_.properties.priority }, name)) {
            $ports = @(Get-RuleDcPorts $rule)
            if ($ports.Count -and (Test-RuleTargetsMachine $rule $addresses $securityGroups)) { $portRules.Add("$($nsg.resource.name)/$($rule.name) ($($ports -join ', '))") }
        }
    }

    #AD DS promotion in userData, custom data or extension settings (names and public settings; protected settings are never returned)
    $surfaces = [ordered]@{}
    if ($p.userData) { $surfaces['userData'] = Convert-FromBase64Utf8 ([string]$p.userData) }
    if ($p.osProfile.customData) { $surfaces['custom data'] = Convert-FromBase64Utf8 ([string]$p.osProfile.customData) }
    if (Test-ChildCollected $Record 'extensions') {
        foreach ($extension in @(Get-Child $Record 'extensions' | Where-Object { $_ } | Sort-Object name)) {
            $settings = $extension.properties.settings
            $text = "$($extension.name) $(if ($null -ne $settings) { $settings | ConvertTo-Json -Depth 20 -Compress })"
            $script = Get-Prop $settings 'script'
            if ($script) { $text += " $(Convert-FromBase64Utf8 ([string]$script))" }
            $surfaces["extension $($extension.name)"] = $text
        }
    } else {
        $unread.Add('installed extensions')
    }
    $promotion = @(foreach ($name in $surfaces.Keys) { if ([string]$surfaces[$name] -match $adDsPromotionPattern) { "$name ($($Matches[1]))" } })

    $dcName = @(@($Record.resource.name, $p.osProfile.computerName) | Where-Object { $_ -and [string]$_ -match $dcNamePattern }) | Select-Object -First 1
    $evidence = [ordered]@{
        privateIpAddresses          = @($addresses | Sort-Object)
        dnsServerFor                = $dnsFor
        domainControllerPortRules   = @($portRules)
        adDsPromotion               = $promotion
        domainControllerName        = $dcName
        staticPrivateIp             = $static
        dataDisksWithoutHostCaching = @($p.storageProfile.dataDisks | Where-Object { $_ -and $_.caching -eq 'None' }).Count
    }
    $notRead = @(@($unread) + @($dns.Unread) | Where-Object { $_ } | Sort-Object -Unique)
    if ($notRead) { $evidence.signalsNotRead = $notRead }

    $signals = [System.Collections.Generic.List[string]]::new()
    if ($dnsFor) { $signals.Add('DNS server') }
    if ($portRules.Count) { $signals.Add('domain controller ports') }
    if ($promotion) { $signals.Add('AD DS promotion') }
    if ($dcName) { $signals.Add('name') }
    $confidence = if ($promotion -or $signals.Count -ge 2) { 'Likely' } elseif ($signals.Count) { 'Possible' } else { $null }
    $cache[$key] = [pscustomobject]@{ Confidence = $confidence; Signals = @($signals); NotRead = $notRead; Evidence = $evidence }
    return $cache[$key]
}

function Get-DomainControllerIds {
    #lowercase ids of the Windows virtual machines that are likely or possible domain controllers
    if (-not $script:Ingest.Cache.ContainsKey('#dcIds')) {
        $ids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($machine in (Get-AzResourceRecords -Type $vmType)) {
            if ((Get-MachineOsType $machine) -eq 'Windows' -and (Get-DomainControllerSignals $machine).Confidence) { $null = $ids.Add($machine.id.ToLowerInvariant()) }
        }
        $script:Ingest.Cache['#dcIds'] = $ids
    }
    return , $script:Ingest.Cache['#dcIds']
}

#roles that can take over a domain controller through Azure: run code on it, change it, copy its disks or restore its
#backup elsewhere. A role that can assign roles can grant itself any of these.
$dcTakeoverActions = @(
    'Microsoft.Compute/virtualMachines/runCommand/action', 'Microsoft.Compute/virtualMachines/runCommands/write',
    'Microsoft.Compute/virtualMachines/extensions/write', 'Microsoft.Compute/virtualMachines/write',
    'Microsoft.GuestConfiguration/guestConfigurationAssignments/write', 'Microsoft.Compute/disks/beginGetAccess/action',
    'Microsoft.Compute/snapshots/write', 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action'
)
$roleAssignmentWriteAction = 'Microsoft.Authorization/roleAssignments/write'
#resource types of the domain controllers themselves and of shared plumbing; anything else in a scope is another workload
$dcSupportingTypes = @(
    'Microsoft.Network/*', 'Microsoft.Compute/disks', 'Microsoft.Compute/snapshots', 'Microsoft.Compute/availabilitySets',
    'Microsoft.Compute/proximityPlacementGroups', 'Microsoft.Compute/restorePointCollections', 'Microsoft.Compute/diskEncryptionSets',
    'Microsoft.RecoveryServices/vaults', 'Microsoft.DataProtection/backupVaults', 'Microsoft.KeyVault/vaults', 'Microsoft.Storage/storageAccounts',
    'Microsoft.ManagedIdentity/userAssignedIdentities', 'Microsoft.Insights/*', 'Microsoft.OperationalInsights/*',
    'Microsoft.OperationsManagement/*', 'Microsoft.AlertsManagement/*', 'Microsoft.Maintenance/*'
)

function Test-RoleGrantsAction {
    #true when a role definition allows an action in one of its permission blocks (actions minus notActions, with wildcards)
    param($Definition, [string]$Action)
    foreach ($permission in @($Definition.properties.permissions | Where-Object { $_ })) {
        if (-not @($permission.actions | Where-Object { $_ -and $Action -like $_ }).Count) { continue }
        if (@($permission.notActions | Where-Object { $_ -and $Action -like $_ }).Count) { continue }
        return $true
    }
    return $false
}

function Test-ScopeCovers {
    #true when a role assignment scope applies to one of the (lowercase) resource ids; management group and root
    #assignments in the ingestion are the ones this subscription inherits
    param([string]$Scope, [string[]]$ResourceIds)
    if ((Get-ScopeLevel $Scope) -in 'root', 'managementGroup') { return $true }
    $prefix = $Scope.TrimEnd('/').ToLowerInvariant()
    return [bool]@($ResourceIds | Where-Object { $_ -eq $prefix -or $_.StartsWith("$prefix/") }).Count
}

function Get-ScopeLabel {
    param([string]$Scope)
    switch (Get-ScopeLevel $Scope) {
        'root' { return 'the tenant root' }
        'managementGroup' { return "management group $(Get-ResourceName $Scope)" }
        'subscription' { return 'the subscription' }
        'resourceGroup' { return "resource group $(Get-ResourceName $Scope)" }
    }
    return Get-ResourceName $Scope
}

function Get-ScopeWorkloads {
    #resources in a subscription or resource group that are neither domain controllers nor shared plumbing (Others), and
    #virtual machines there that could not be read, so may be domain controllers (Unread)
    param([string]$Scope)
    if (-not $script:Ingest.Cache.ContainsKey('#dcScopes')) { $script:Ingest.Cache['#dcScopes'] = @{} }
    $cache = $script:Ingest.Cache['#dcScopes']
    $prefix = $Scope.TrimEnd('/').ToLowerInvariant()
    if (-not $cache.ContainsKey($prefix)) {
        $controllers = Get-DomainControllerIds
        $others = [System.Collections.Generic.List[string]]::new()
        $unread = [System.Collections.Generic.List[string]]::new()
        foreach ($resource in @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.id } | Sort-Object { ([string]$_.id).ToLowerInvariant() })) {
            $id = ([string]$resource.id).ToLowerInvariant()
            if (-not $id.StartsWith("$prefix/")) { continue }
            if ($id -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachines/[^/]+)') {
                #a machine and its child resources (extensions, run commands) belong to the machine
                $machineId = $Matches[1]
                if ($machineId -ne $id -or $controllers.Contains($machineId)) { continue }
                if (Get-AzResourceRecord $machineId) { $others.Add([string]$resource.name) } else { $unread.Add("virtual machine $($resource.name)") }
                continue
            }
            if (@($dcSupportingTypes | Where-Object { [string]$resource.type -like $_ }).Count) { continue }
            $others.Add([string]$resource.name)
        }
        $cache[$prefix] = [pscustomobject]@{ Others = @($others); Unread = @($unread) }
    }
    return $cache[$prefix]
}

function Get-DomainControllerProtection {
    #Tier 0 protection of a domain controller: no role that can take it over is delegated on a subscription or resource
    #group shared with other workloads, held by a workload identity, or held permanently by a user or group
    param($Record, $Signals)
    $p = $Record.resource.properties
    $machineId = $Record.id.ToLowerInvariant()
    $notRead = [System.Collections.Generic.List[string]]::new()
    $resourceIds = [System.Collections.Generic.List[string]]::new()
    $resourceIds.Add($machineId)
    foreach ($disk in @(@($p.storageProfile.osDisk) + @($p.storageProfile.dataDisks) | Where-Object { $_.managedDisk.id })) { $resourceIds.Add(([string]$disk.managedDisk.id).ToLowerInvariant()) }
    #vaults that back the machine up: their restore right is a takeover right too
    foreach ($id in (Get-FailedResourceIds -Type 'Microsoft.RecoveryServices/vaults')) { $notRead.Add("vault $(Get-ResourceName $id)") }
    foreach ($vault in (Get-AzResourceRecords -Type 'Microsoft.RecoveryServices/vaults')) {
        if (-not (Test-ChildCollected $vault 'backupProtectedItems')) { $notRead.Add("protected items of vault $($vault.resource.name)"); continue }
        foreach ($item in @(Get-Child $vault 'backupProtectedItems' | Where-Object { $_ })) {
            if (@(@($item.properties.sourceResourceId, $item.properties.virtualMachineId) | Where-Object { $_ -and ([string]$_).ToLowerInvariant() -eq $machineId }).Count) { $resourceIds.Add($vault.id.ToLowerInvariant()); break }
        }
    }

    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in (Get-ActiveRoleAssignments)) { $candidates.Add([pscustomobject]@{ Item = $assignment; Kind = 'active' }) }
    if (Test-IngestSection 'rbac/roleEligibilitySchedules') {
        foreach ($schedule in @(Get-IngestData 'rbac/roleEligibilitySchedules' | Where-Object { $_ })) { $candidates.Add([pscustomobject]@{ Item = $schedule; Kind = 'eligible' }) }
    } else {
        $notRead.Add('eligible role assignments')
    }
    $instancesRead = Test-IngestSection 'rbac/roleAssignmentScheduleInstances'
    $instances = @{}
    if ($instancesRead) {
        foreach ($instance in @(Get-IngestData 'rbac/roleAssignmentScheduleInstances' | Where-Object { $_ -and $_.properties.originRoleAssignmentId })) { $instances[([string]$instance.properties.originRoleAssignmentId).ToLowerInvariant()] = $instance }
    }

    $takeover = [System.Collections.Generic.List[string]]::new()
    $shared = [System.Collections.Generic.List[string]]::new()
    $workload = [System.Collections.Generic.List[string]]::new()
    $standing = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in $candidates) {
        $a = $candidate.Item.properties
        if (-not $a.scope -or -not (Test-ScopeCovers $a.scope $resourceIds)) { continue }
        $definition = (Get-RoleDefinitionMap)[(Get-RoleDefinitionGuid $a.roleDefinitionId)]
        if (-not $definition) { $notRead.Add("role definition $(Get-RoleName $a.roleDefinitionId)"); continue }
        $assignsRoles = Test-RoleGrantsAction $definition $roleAssignmentWriteAction
        if (-not $assignsRoles -and -not @($dcTakeoverActions | Where-Object { Test-RoleGrantsAction $definition $_ }).Count) { continue }
        $label = "$($definition.properties.roleName) for $(Get-PrincipalLabel $a.principalId) on $(Get-ScopeLabel $a.scope)"
        $takeover.Add("$label ($($candidate.Kind))")
        if ($a.principalType -eq 'ServicePrincipal') {
            $workload.Add($label)
        } elseif ($a.principalType -eq 'Group') {
            if (Test-GroupMembersComplete $a.principalId) {
                foreach ($member in @(Get-GroupMembers $a.principalId | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' })) { $workload.Add("$label, through $($member.displayName)") }
            } else {
                $notRead.Add("members of $(Get-PrincipalLabel $a.principalId)")
            }
        }
        if ($candidate.Kind -eq 'active' -and $a.principalType -in 'User', 'Group') {
            $instance = $instances[([string]$candidate.Item.id).ToLowerInvariant()]
            if (-not $instancesRead) { $notRead.Add('role assignment schedules') }
            elseif (-not $instance) { $notRead.Add("assignment schedule of $label") }
            elseif ($instance.properties.assignmentType -eq 'Assigned' -and -not $instance.properties.endDateTime) { $standing.Add($label) }
        }
        #roles that assign roles control the scope itself and count as Tier 0 administration there
        if (-not $assignsRoles -and (Get-ScopeLevel $a.scope) -in 'subscription', 'resourceGroup') {
            $scope = Get-ScopeWorkloads $a.scope
            if ($scope.Others.Count) { $shared.Add("$label, shared with $($scope.Others.Count) other resource(s): $(@($scope.Others | Select-Object -First 3) -join ', ')") }
            foreach ($item in $scope.Unread) { $notRead.Add($item) }
        }
    }

    $evidence = [ordered]@{}
    foreach ($name in $Signals.Evidence.Keys) { $evidence[$name] = $Signals.Evidence[$name] }
    $evidence.takeoverRoles = @($takeover | Sort-Object -Unique)
    $evidence.sharedScopes = @($shared | Sort-Object -Unique)
    $evidence.workloadIdentities = @($workload | Sort-Object -Unique)
    $evidence.standingAccess = @($standing | Sort-Object -Unique)
    $protectionNotRead = @($notRead | Sort-Object -Unique)
    if ($protectionNotRead) { $evidence.protectionNotRead = $protectionNotRead }

    $issues = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $evidence.sharedScopes) { $issues.Add("delegated on a shared scope: $item") }
    foreach ($item in $evidence.workloadIdentities) { $issues.Add("workload identity: $item") }
    foreach ($item in $evidence.standingAccess) { $issues.Add("permanent: $item") }
    $subject = "$($Signals.Confidence) domain controller ($($Signals.Signals -join ', '))"
    if ($issues.Count) {
        $more = if ($issues.Count -gt 3) { "; and $($issues.Count - 3) more" } else { '' }
        return New-Fail "$subject without Tier 0 protection: $(@($issues | Select-Object -First 3) -join '; ')$more" $evidence
    }
    if ($protectionNotRead) { return New-Unknown "$subject, Tier 0 protection not established; not read: $($protectionNotRead -join ', ')" $evidence }
    New-Pass "$subject with Tier 0 protection: $($takeover.Count) role assignment(s) can take it over, none delegated on a shared scope, held by a workload identity or permanent" $evidence
}

$dcDetection = 'A Windows virtual machine is a likely domain controller with an AD DS promotion or two of these signals, a possible one with one: its private address is the DNS server of a virtual network, network interface, Azure Firewall or DNS forwarding rule; a network security group rule allows Kerberos (88, 464), the global catalog (3268, 3269) or AD Web Services (9389) to it; its userData, custom data or extension settings promote it (Install-ADDSForest, CreateADPDC); its name is one (DC01, vm-dc-02).'
$dcProtection = 'Tier 0 protection: no role that can take the machine over (run command, extensions, changing the machine, disk export, snapshots, restore from its backup vault, or assigning roles) is delegated on a subscription or resource group that also holds other workloads, held by a service principal or managed identity (also through a group), or held permanently by a user or group instead of through PIM. Roles that assign roles are Tier 0 administration of their scope and do not count as delegated; management group and root roles count for the last two checks.'
$dcRationale = 'A domain controller holds the password hashes of every account in the domain. Anyone who can run commands on it, install an extension, change it, copy its disks or restore its backup through Azure controls the domain: Virtual Machine Contributor on a domain controller amounts to Domain Admin. Those rights have to stay with Tier 0 administrators, not with the administrators of other workloads in the same subscription or resource group, not with pipelines and automation that cannot use MFA, and not permanently available to an account that is phished.'
$dcRemediation = 'Place domain controllers in a subscription or resource group of their own (the identity landing zone) and remove the delegated roles other teams hold there. Grant the remaining roles through PIM eligibility to role-assignable groups, remove workload identities, and alert on run command (AZ-LOG-029).'
$dcReferences = @('https://learn.microsoft.com/azure/architecture/example-scenario/identity/adds-extend-domain', 'https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model')

Add-AzTest @{
    Id            = 'AZ-VM-015'
    Title         = 'No virtual machine acts as a domain controller without Tier 0 protection'
    Category      = 'Privileged access'
    Service       = 'Virtual machines'
    Severity      = 'High'
    Description   = "Checks the Tier 0 protection of likely domain controllers. $dcDetection $dcProtection Best effort: a domain controller promoted from inside the machine, with another name, and used as DNS server only outside this subscription shows no signal. A machine whose signals could not all be read is reported as unknown here; possible domain controllers are AZ-VM-016."
    Rationale     = $dcRationale
    Remediation   = $dcRemediation
    References    = $dcReferences
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'subscription/resources')
    ResourceTypes = @($vmType)
    Filter        = { param($Record) (Get-MachineOsType $Record) -eq 'Windows' }
    Evaluate      = {
        param($Record)
        $signals = Get-DomainControllerSignals $Record
        if ($signals.Confidence -eq 'Likely') { return Get-DomainControllerProtection $Record $signals }
        if ($signals.NotRead) { return New-Unknown "Not ruled out as a likely domain controller; not read: $($signals.NotRead -join ', ')" $signals.Evidence }
    }
}

Add-AzTest @{
    Id            = 'AZ-VM-016'
    Title         = 'No virtual machine that may be a domain controller runs without Tier 0 protection'
    Category      = 'Privileged access'
    Service       = 'Virtual machines'
    Severity      = 'Informational'
    Description   = "Checks the Tier 0 protection of possible domain controllers: machines with one signal, which AZ-VM-015 leaves out. $dcDetection $dcProtection"
    Rationale     = "$dcRationale One signal is not proof: confirm whether the machine is a domain controller."
    Remediation   = "Confirm whether the machine is a domain controller. If it is: $dcRemediation"
    References    = $dcReferences
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'subscription/resources')
    ResourceTypes = @($vmType)
    Filter        = { param($Record) (Get-MachineOsType $Record) -eq 'Windows' }
    Evaluate      = {
        param($Record)
        $signals = Get-DomainControllerSignals $Record
        if ($signals.Confidence -eq 'Possible') { return Get-DomainControllerProtection $Record $signals }
    }
}
