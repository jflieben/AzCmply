#Compute: virtual machines, scale sets, Arc machines and managed disks

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
    Frameworks    = @{ MCSB = @('PV-3', 'DP-4'); ALZ = 'Deny-UnmanagedDisk' }
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
    Frameworks    = @{ MCSB = 'DP-4'; WAF = 'SE:07'; ALZ = 'Enforce-GR-Compute0' }
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
    Frameworks    = @{ MCSB = @('PV-3', 'PV-4'); WAF = 'SE:08'; ALZ = @('Audit-TrustedLaunch', 'Deploy-GuestAttest') }
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
    Frameworks    = @{ MCSB = 'IM-6'; WAF = 'SE:05'; ALZ = 'Enforce-ACSB' }
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
    Frameworks    = @{ MCSB = @('PV-6', 'PV-5'); CIS = '8.1.10'; WAF = 'SE:08'; ALZ = 'Enable-AUM-CheckUpdates' }
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
    Frameworks    = @{ MCSB = @('ES-1', 'ES-2'); WAF = 'SE:10'; ALZ = @('Deploy-MDEndpoints', 'Deploy-MDEndpointsAMA') }
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
    Frameworks    = @{ MCSB = @('PV-4', 'PV-3'); ALZ = 'Enforce-ACSB' }
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
    Frameworks    = @{ MCSB = @('LT-3', 'LT-5'); WAF = 'SE:10'; ALZ = 'Deploy-VM-Monitoring' }
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
    Frameworks    = @{ MCSB = @('LT-3', 'PV-6') }
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
    Frameworks    = @{ MCSB = 'BR-1'; WAF = 'SE:12'; ALZ = 'Deploy-VM-Backup' }
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
    Frameworks    = @{ MCSB = @('NS-2', 'DP-2'); WAF = 'SE:06' }
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
    Frameworks    = @{ MCSB = @('NS-2', 'DP-2'); WAF = 'SE:06' }
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
