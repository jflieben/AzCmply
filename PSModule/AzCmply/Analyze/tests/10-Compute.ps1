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

