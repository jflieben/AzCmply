#Key Vault and Managed HSM: deletion protection, access model, network exposure, key/secret/certificate lifecycle

$vaultTypes = @('Microsoft.KeyVault/vaults', 'Microsoft.KeyVault/managedHSMs')

function Get-VaultItems {
    #enabled keys or secrets of a vault, with their attributes
    param($Record, [ValidateSet('keys', 'secrets')][string]$Kind)
    @(Get-Child $Record $Kind | Where-Object { $_ -and $_.properties.attributes.enabled -ne $false })
}

function Test-CertificateSecret {
    param($Secret)
    return ([string]$Secret.properties.contentType -in 'application/x-pkcs12', 'application/x-pem-file')
}

Add-AzTest @{
    Id            = 'AZ-KV-001'
    Title         = 'Key vaults have soft delete and purge protection enabled'
    Category      = 'Data protection'
    Service       = 'Key Vault'
    Severity      = 'High'
    Description   = 'Checks soft delete and purge protection on key vaults and managed HSMs.'
    Rationale     = 'Without purge protection a deleted vault, key or secret can be permanently purged immediately, by mistake or by an attacker. Losing a key used for encryption at rest makes the data unrecoverable.'
    Remediation   = 'Enable purge protection (az keyvault update --enable-purge-protection true ...). It cannot be disabled afterwards.'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview')
    Defender      = @{ '4ed62ae4-5072-f9e7-8d94-51c76c48159a' = 'Key vaults should have deletion protection enabled'; '78211c00-15a9-336e-17c4-0b48613dadf4' = 'Key vaults should have soft delete enabled'; '7b4f60c5-48fd-b41c-9180-43783796f753' = 'Azure Key Vault Managed HSM should have purge protection enabled' }
    Policy        = @{ '0b60c0b2-2dc2-4e1c-b5c9-abbed971de53' = 'Key vaults should have deletion protection enabled'; '1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d' = 'Key vaults should have soft delete enabled'; 'c39ba22d-4428-4149-b981-70acb31fc383' = 'Azure Key Vault Managed HSM should have purge protection enabled' }
    ResourceTypes = $vaultTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ enableSoftDelete = $p.enableSoftDelete; enablePurgeProtection = $p.enablePurgeProtection; softDeleteRetentionInDays = $p.softDeleteRetentionInDays }
        if ($p.enableSoftDelete -eq $false) { return New-Fail 'Soft delete is disabled' $evidence }
        if ($p.enablePurgeProtection -eq $true) { return New-Pass 'Soft delete and purge protection enabled' $evidence }
        New-Fail 'Purge protection is not enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-KV-002'
    Title         = 'Key vaults use the Azure RBAC permission model'
    Category      = 'Privileged access'
    Service       = 'Key Vault'
    Severity      = 'Medium'
    Description   = 'Checks that key vaults use Azure RBAC for data plane authorization instead of vault access policies.'
    Rationale     = 'Access policies cannot be scoped to individual keys or secrets, are not covered by PIM or deny assignments, and anyone with Contributor on the vault can grant themselves access. RBAC is the default from API version 2026-02-01.'
    Remediation   = 'Recreate the access policy permissions as Key Vault RBAC role assignments, then switch the permission model to Azure RBAC (az keyvault update --enable-rbac-authorization true ...).'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/rbac-migration')
    Policy        = @{ '12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5' = 'Azure Key Vault should use RBAC permission model' }
    ResourceTypes = @('Microsoft.KeyVault/vaults')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ enableRbacAuthorization = $p.enableRbacAuthorization; accessPolicies = @($p.accessPolicies).Count }
        if ($p.enableRbacAuthorization -eq $true) { return New-Pass 'Azure RBAC permission model' $evidence }
        New-Fail 'Vault access policy permission model' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-KV-003'
    Title         = 'Key vaults disable public network access'
    Category      = 'Network security'
    Service       = 'Key Vault'
    Severity      = 'Medium'
    Description   = 'Checks that public network access is disabled on key vaults and managed HSMs, so they are only reachable through private endpoints.'
    Rationale     = 'A public endpoint allows anyone with a stolen token or credential to reach the secrets from any network.'
    Remediation   = 'Create a private endpoint and set public network access to Disabled (az keyvault update --public-network-access Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/network-security')
    Defender      = @{ '52f7826a-ace7-3107-dd0d-4875853c1576' = 'Firewall should be enabled on Key Vault' }
    Policy        = @{ '405c5871-3e91-4644-8a63-58e19d68ff5b' = 'Azure Key Vault should disable public network access'; '19ea9d63-adee-4431-a95e-1913c6c1c75f' = '[Preview]: Azure Key Vault Managed HSM should disable public network access' }
    ResourceTypes = $vaultTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; firewallDefaultAction = $p.networkAcls.defaultAction }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if ($p.networkAcls.defaultAction -eq 'Deny') { return New-Fail 'Public endpoint enabled, restricted by the firewall' $evidence }
        New-Fail 'Public endpoint enabled and open to all networks' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-KV-004'
    Title         = 'Key vaults are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Key Vault'
    Severity      = 'Low'
    Description   = 'Checks key vaults and managed HSMs for at least one approved private endpoint connection.'
    Rationale     = 'Private endpoints keep secret retrieval on private networks and allow the public endpoint to be disabled.'
    Remediation   = 'Create a private endpoint for the vault with privatelink.vaultcore.azure.net DNS integration.'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/private-link-service')
    Defender      = @{ 'f6b59724-4a05-aa38-33e2-25f15eecf00b' = 'Azure Key Vaults should use private link' }
    Policy        = @{ 'a6abeaec-4d90-4a02-805f-6b26c4d3fbe9' = 'Azure Key Vaults should use private link'; '59fee2f4-d439-4f1b-9b9a-982e1474bfd8' = '[Preview]: Azure Key Vault Managed HSM should use private link' }
    ResourceTypes = $vaultTypes
    Evaluate      = {
        param($Record)
        $approved = @($Record.resource.properties.privateEndpointConnections | Where-Object { $_ -and $_.properties.privateLinkServiceConnectionState.status -eq 'Approved' })
        if ($approved) { return New-Pass "$($approved.Count) private endpoint(s)" ([ordered]@{ approvedPrivateEndpoints = $approved.Count }) }
        New-Fail 'No private endpoint' ([ordered]@{ approvedPrivateEndpoints = 0 })
    }
}

#CIS numbers expiry dates separately for RBAC and access policy vaults (keys 8.3.1 / 8.3.2, secrets 8.3.3 / 8.3.4),
#so each permission model gets its own test and a control is never judged on vaults it does not cover
$vaultExpiryTests = @(
    @{ Id = 'AZ-KV-005'; Item = 'keys'; Noun = 'key'; Rbac = $true }
    @{ Id = 'AZ-KV-010'; Item = 'keys'; Noun = 'key'; Rbac = $false }
    @{ Id = 'AZ-KV-006'; Item = 'secrets'; Noun = 'secret'; Rbac = $true }
    @{ Id = 'AZ-KV-011'; Item = 'secrets'; Noun = 'secret'; Rbac = $false }
)

foreach ($expiry in $vaultExpiryTests) {
    $model = if ($expiry.Rbac) { 'RBAC' } else { 'access policy' }
    Add-AzTest @{
        Id          = $expiry.Id
        Version     = 2
        Title       = "Key Vault $($expiry.Item) in $model vaults have an expiration date"
        Category    = 'Data protection'
        Service     = 'Key Vault'
        Severity    = 'Medium'
        Description = "Checks every enabled $($expiry.Noun) in key vaults that use the $model permission model for an expiration date."
        Rationale   = if ($expiry.Item -eq 'keys') {
            'Keys without an expiration date are never forced through rotation, which extends the impact of a key compromise indefinitely.'
        } else {
            'Secrets without an expiration date tend never to be rotated, so a leaked secret stays valid indefinitely.'
        }
        Remediation = if ($expiry.Item -eq 'keys') {
            'Set an expiration date on each key (az keyvault key set-attributes --expires ...) and configure a rotation policy that creates new versions before expiry.'
        } else {
            'Set an expiration date on each secret (az keyvault secret set-attributes --expires ...) aligned with the rotation of the credential it holds, and monitor near-expiry events.'
        }
        References  = if ($expiry.Item -eq 'keys') {
            @('https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation')
        } else {
            @('https://learn.microsoft.com/azure/key-vault/secrets/tutorial-rotation')
        }
        Defender    = if ($expiry.Item -eq 'keys') { @{ '1aabfa0d-7585-f9f5-1d92-ecb40291d9f2' = 'Key Vault keys should have an expiration date' } } else { $null }
        Policy      = if ($expiry.Item -eq 'keys') {
            @{ '152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0' = 'Key Vault keys should have an expiration date' }
        } else {
            @{ '98728c90-32c7-4049-8429-847dc0f4fe37' = 'Key Vault secrets should have an expiration date' }
        }
        Config      = $expiry
        Run         = {
            param($Test)
            $config = $Test.Config
            $vaults = @(Get-AzResourceRecords -Type 'Microsoft.KeyVault/vaults' | Where-Object { [bool]$_.resource.properties.enableRbacAuthorization -eq $config.Rbac })
            if (-not $vaults) { return }
            foreach ($vault in $vaults) {
                if (-not (Test-ChildCollected $vault $config.Item)) { New-Finding -Record $vault -Result (New-Unknown "$($config.Item.Substring(0,1).ToUpperInvariant())$($config.Item.Substring(1)) could not be listed"); continue }
                foreach ($item in (Get-VaultItems $vault $config.Item)) {
                    $expires = $item.properties.attributes.exp
                    $evidence = [ordered]@{ vault = $vault.resource.name; permissionModel = if ($config.Rbac) { 'RBAC' } else { 'access policies' }; expires = Format-UtcDate $expires }
                    if ($config.Item -eq 'secrets') { $evidence.contentType = $item.properties.contentType }
                    $result = if ($expires) { New-Pass "Expires $($evidence.expires)" $evidence } else { New-Fail 'No expiration date' $evidence }
                    New-Finding -ResourceId $item.id -ResourceType "Microsoft.KeyVault/vaults/$($config.Item)" -ResourceName "$($vault.resource.name)/$($item.name)" -Result $result
                }
            }
        }
    }
}
Add-AzTest @{
    Id          = 'AZ-KV-007'
    Title       = 'Key Vault keys have an automatic rotation policy'
    Category    = 'Data protection'
    Service     = 'Key Vault'
    Severity    = 'Low'
    Description = 'Checks every enabled key for a rotation policy with a Rotate lifetime action.'
    Rationale   = 'Automatic rotation limits the amount of data protected by a single key version and removes the dependency on manual processes.'
    Remediation = 'Configure a key rotation policy (az keyvault key rotation-policy update ...) and let dependent services use versionless key URIs.'
    References  = @('https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation')
    Policy      = @{ 'd8cf8476-a2ec-4916-896e-992351803c44' = 'Keys should have a rotation policy ensuring that their rotation is scheduled within the specified number of days after creation.' }
    Run         = {
        foreach ($vault in (Get-AzResourceRecords -Type 'Microsoft.KeyVault/vaults')) {
            if (-not (Test-ChildCollected $vault 'keys')) { New-Finding -Record $vault -Result (New-Unknown 'Keys could not be listed'); continue }
            foreach ($key in (Get-VaultItems $vault 'keys')) {
                $policy = $key.properties.rotationPolicy
                $rotate = @($policy.lifetimeActions | Where-Object { $_ -and $_.action.type -eq 'Rotate' })
                $evidence = [ordered]@{ vault = $vault.resource.name; rotationPolicyReturned = ($key.properties.PSObject.Properties.Name -contains 'rotationPolicy'); rotateAction = [bool]$rotate }
                $result = if ($rotate) { New-Pass 'Automatic rotation configured' $evidence } elseif (-not $evidence.rotationPolicyReturned) { New-Unknown 'The key listing does not include the rotation policy' $evidence } else { New-Fail 'No automatic rotation' $evidence }
                New-Finding -ResourceId $key.id -ResourceType 'Microsoft.KeyVault/vaults/keys' -ResourceName "$($vault.resource.name)/$($key.name)" -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-KV-008'
    Title       = 'Key Vault certificates are valid for at most 12 months'
    Category    = 'Data protection'
    Service     = 'Key Vault'
    Severity    = 'Medium'
    Description = 'Checks the validity period of certificates, using the not-before and expiry dates of the certificate backed secrets.'
    Rationale   = 'Long lived certificates increase the window in which a compromised private key can be abused and conflict with the 398 day (and shrinking) CA/Browser Forum limits for public TLS certificates.'
    Remediation = 'Set the certificate policy validity to 12 months or less (az keyvault certificate set-attributes / policy update) and automate renewal.'
    References  = @('https://learn.microsoft.com/azure/key-vault/certificates/overview-renew-certificate')
    Defender    = @{ 'fc84abc0-eee6-4758-8372-a7681965ca44' = 'Validity period of certificates stored in Azure Key Vault should not exceed 12 months' }
    Policy      = @{ '0a075868-4c26-42ef-914c-5bc007359560' = 'Certificates should have the specified maximum validity period' }
    Run         = {
        foreach ($vault in (Get-AzResourceRecords -Type 'Microsoft.KeyVault/vaults')) {
            if (-not (Test-ChildCollected $vault 'secrets')) { continue }
            foreach ($secret in @(Get-VaultItems $vault 'secrets' | Where-Object { Test-CertificateSecret $_ })) {
                $start = ConvertTo-UtcDate $secret.properties.attributes.nbf
                $end = ConvertTo-UtcDate $secret.properties.attributes.exp
                $evidence = [ordered]@{ vault = $vault.resource.name; notBefore = Format-UtcDate $start; expires = Format-UtcDate $end }
                $result = if (-not $start -or -not $end) { New-Unknown 'Validity dates not available' $evidence }
                else {
                    $days = [int]($end - $start).TotalDays
                    $evidence.validityDays = $days
                    if ($days -le 366) { New-Pass "Valid for $days days" $evidence } else { New-Fail "Valid for $days days" $evidence }
                }
                New-Finding -ResourceId $secret.id -ResourceType 'Microsoft.KeyVault/vaults/certificates' -ResourceName "$($vault.resource.name)/$($secret.name)" -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-KV-009'
    Title         = 'Key vault access policies do not grant full or purge permissions'
    Category      = 'Privileged access'
    Service       = 'Key Vault'
    Severity      = 'Medium'
    Description   = "Checks vaults that use access policies for principals with 'all' or 'purge' permissions on keys, secrets or certificates."
    Rationale     = 'Full and purge permissions allow reading every secret and permanently destroying keys. Applications need only the individual operations they use.'
    Remediation   = 'Reduce each access policy to the required operations (for example get and list on secrets), or migrate the vault to Azure RBAC with narrowly scoped roles.'
    References    = @('https://learn.microsoft.com/azure/key-vault/general/assign-access-policy')
    ResourceTypes = @('Microsoft.KeyVault/vaults')
    Evaluate      = {
        param($Record)
        if ($Record.resource.properties.enableRbacAuthorization -eq $true) { return New-NotApplicable 'The vault uses Azure RBAC' }
        $broad = foreach ($policy in @($Record.resource.properties.accessPolicies | Where-Object { $_ })) {
            $grants = @()
            foreach ($kind in 'keys', 'secrets', 'certificates') {
                $permissions = @($policy.permissions.$kind | ForEach-Object { ([string]$_).ToLowerInvariant() })
                if ($permissions -contains 'all') { $grants += "${kind}:all" } elseif ($permissions -contains 'purge') { $grants += "${kind}:purge" }
            }
            if ($grants) { "$(Get-PrincipalLabel $policy.objectId): $($grants -join ', ')" }
        }
        $evidence = [ordered]@{ accessPolicies = @($Record.resource.properties.accessPolicies).Count; broadGrants = @($broad | Sort-Object) }
        if ($broad) { return New-Fail "$(@($broad).Count) access policy(ies) with full or purge permissions" $evidence }
        New-Pass 'No full or purge permissions in access policies' $evidence
    }
}
