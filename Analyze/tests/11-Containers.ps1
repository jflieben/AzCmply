#Containers: AKS, Container Registry, Container Apps and Container Instances

$aksType = @('Microsoft.ContainerService/managedClusters')
$acrType = @('Microsoft.ContainerRegistry/registries')

Add-AzTest @{
    Id            = 'AZ-AKS-001'
    Title         = 'AKS clusters disable local accounts'
    Category      = 'Identity management'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'High'
    Description   = 'Checks disableLocalAccounts, which removes the static cluster admin credential.'
    Rationale     = 'The local admin kubeconfig is a non-expiring certificate with cluster-admin rights that bypasses Entra ID, MFA and Conditional Access and cannot be attributed to a person.'
    Remediation   = 'Enable Entra integration and disable local accounts (az aks update --disable-local-accounts ...), then rotate the cluster certificates to invalidate issued admin kubeconfigs.'
    References    = @('https://learn.microsoft.com/azure/aks/manage-local-accounts-managed-azure-ad')
    Policy        = @{ '993c2fcd-2b29-49d2-9eb0-df2c3a730c32' = 'Azure Kubernetes Service Clusters should have local authentication methods disabled' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableLocalAccounts
        if ($value -eq $true) { return New-Pass 'Local accounts disabled' ([ordered]@{ disableLocalAccounts = $true }) }
        New-Fail 'Local accounts enabled' ([ordered]@{ disableLocalAccounts = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-002'
    Title         = 'AKS clusters use Entra ID with Azure RBAC for Kubernetes authorization'
    Category      = 'Identity management'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks for managed Entra ID integration with Azure RBAC for Kubernetes authorization.'
    Rationale     = 'Entra integration applies MFA and Conditional Access to kubectl access; Azure RBAC makes cluster permissions visible and reviewable alongside other Azure access, including PIM.'
    Remediation   = 'Enable managed Entra integration and Azure RBAC (az aks update --enable-aad --enable-azure-rbac ...).'
    References    = @('https://learn.microsoft.com/azure/aks/manage-azure-rbac')
    Policy        = @{ '450d2877-ebea-41e8-b00c-e286317d21bf' = 'Azure Kubernetes Service Clusters should enable Microsoft Entra ID integration' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $profile = $Record.resource.properties.aadProfile
        $evidence = [ordered]@{ managedEntraIntegration = [bool]$profile.managed; azureRbac = [bool]$profile.enableAzureRBAC }
        if ($profile.managed -and $profile.enableAzureRBAC) { return New-Pass 'Entra ID with Azure RBAC' $evidence }
        New-Fail $(if (-not $profile) { 'No Entra ID integration' } else { 'Kubernetes RBAC without Azure RBAC' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-003'
    Title         = 'AKS API servers are private or restricted to authorized IP ranges'
    Category      = 'Network security'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'High'
    Description   = 'Checks for a private cluster, API server VNet integration or authorized IP ranges on the API server.'
    Rationale     = 'A public API server without IP restrictions can be probed and attacked from anywhere, and any leaked credential gives direct cluster access.'
    Remediation   = 'Use a private cluster or API server VNet integration, or restrict access with authorized IP ranges (az aks update --api-server-authorized-ip-ranges ...).'
    References    = @('https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges')
    Policy        = @{ '040732e8-d947-40b8-95d6-854c95024bf8' = 'Azure Kubernetes Service Private Clusters should be enabled'; '0e246bcf-5f6f-4f87-bc6f-775d4712c7ea' = 'Authorized IP ranges should be defined on Kubernetes Services' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $access = $Record.resource.properties.apiServerAccessProfile
        $evidence = [ordered]@{ privateCluster = [bool]$access.enablePrivateCluster; vnetIntegration = [bool]$access.enableVnetIntegration; authorizedIpRanges = @($access.authorizedIPRanges) }
        if ($access.enablePrivateCluster) { return New-Pass 'Private cluster' $evidence }
        if (@($access.authorizedIPRanges | Where-Object { $_ -and $_ -ne '0.0.0.0/0' }).Count) { return New-Pass 'Authorized IP ranges configured' $evidence }
        New-Fail 'Public API server open to all networks' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-004'
    Title         = 'The Azure Policy add-on is enabled on AKS clusters'
    Category      = 'Posture and vulnerability management'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks the azurepolicy add-on, which enforces pod security and other guardrails with Gatekeeper.'
    Rationale     = 'Without admission control, privileged containers, host mounts and other risky workloads can be deployed freely.'
    Remediation   = 'Enable the add-on (az aks enable-addons --addons azure-policy ...) and assign the Kubernetes pod security baseline or restricted initiative.'
    References    = @('https://learn.microsoft.com/azure/governance/policy/concepts/policy-for-kubernetes')
    Policy        = @{ '0a15ec92-a229-4763-bb14-0ea34a568f8d' = 'Azure Policy Add-on for Kubernetes service (AKS) should be installed and enabled on your clusters' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $enabled = [bool]$Record.resource.properties.addonProfiles.azurepolicy.enabled
        if ($enabled) { return New-Pass 'Azure Policy add-on enabled' ([ordered]@{ azurepolicy = $true }) }
        New-Fail 'Azure Policy add-on not enabled' ([ordered]@{ azurepolicy = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-005'
    Title         = 'AKS command invoke is disabled'
    Category      = 'Privileged access'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks apiServerAccessProfile.disableRunCommand.'
    Rationale     = 'Command invoke runs kubectl commands with cluster admin level credentials through the Azure API, bypassing private cluster network controls for anyone with the right Azure role.'
    Remediation   = 'Disable run command (az aks command invoke is then blocked): az aks update --disable-run-command ...'
    References    = @('https://learn.microsoft.com/azure/aks/access-private-cluster')
    Policy        = @{ '89f2d532-c53c-4f8f-9afa-4927b1114a0d' = 'Azure Kubernetes Service Clusters should disable Command Invoke' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.apiServerAccessProfile.disableRunCommand
        if ($value) { return New-Pass 'Command invoke disabled' ([ordered]@{ disableRunCommand = $true }) }
        New-Fail 'Command invoke enabled' ([ordered]@{ disableRunCommand = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-006'
    Title         = 'AKS clusters upgrade automatically'
    Category      = 'Posture and vulnerability management'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks the cluster auto-upgrade channel and the node OS upgrade channel.'
    Rationale     = 'Kubernetes versions leave support quickly and node images receive security patches weekly; without automatic upgrades clusters fall behind on security fixes.'
    Remediation   = "Set an auto-upgrade channel (patch or stable) and the node OS upgrade channel to NodeImage or SecurityPatch, with a planned maintenance window."
    References    = @('https://learn.microsoft.com/azure/aks/auto-upgrade-cluster')
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $profile = $Record.resource.properties.autoUpgradeProfile
        $evidence = [ordered]@{ upgradeChannel = $profile.upgradeChannel; nodeOSUpgradeChannel = $profile.nodeOSUpgradeChannel; kubernetesVersion = $Record.resource.properties.kubernetesVersion }
        $problems = @()
        if (-not $profile.upgradeChannel -or $profile.upgradeChannel -eq 'none') { $problems += 'no cluster auto-upgrade' }
        if (-not $profile.nodeOSUpgradeChannel -or $profile.nodeOSUpgradeChannel -in 'None', 'Unmanaged') { $problems += 'no node OS upgrades' }
        if ($problems) { return New-Fail ($problems -join ', ') $evidence }
        New-Pass "Auto-upgrade $($profile.upgradeChannel), node OS $($profile.nodeOSUpgradeChannel)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-007'
    Title         = 'AKS clusters enforce network policies'
    Category      = 'Network security'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks that a network policy engine (Azure, Calico or Cilium) is configured.'
    Rationale     = 'Without a network policy engine every pod can reach every other pod, so one compromised workload can move laterally through the cluster.'
    Remediation   = 'Enable a network policy engine (az aks update --network-policy azure|calico|cilium ...) and apply default deny policies per namespace.'
    References    = @('https://learn.microsoft.com/azure/aks/use-network-policies')
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $network = $Record.resource.properties.networkProfile
        $evidence = [ordered]@{ networkPlugin = $network.networkPlugin; networkPolicy = $network.networkPolicy; dataplane = $network.networkDataplane }
        if ($network.networkPolicy -and $network.networkPolicy -ne 'none') { return New-Pass "Network policy $($network.networkPolicy)" $evidence }
        New-Fail 'No network policy engine' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-008'
    Title         = 'AKS clusters use managed identities'
    Category      = 'Identity management'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Medium'
    Description   = 'Checks that the cluster identity is a managed identity instead of a service principal with a client secret.'
    Rationale     = 'Service principal based clusters store a client secret on every node, which expires and is often long lived and widely privileged.'
    Remediation   = 'Update the cluster to use a managed identity (az aks update --enable-managed-identity ...).'
    References    = @('https://learn.microsoft.com/azure/aks/use-managed-identity')
    Policy        = @{ 'da6e2401-19da-4532-9141-fb8fbde08431' = 'Azure Kubernetes Service Clusters should use managed identities' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $type = $Record.resource.identity.type
        $evidence = [ordered]@{ identityType = $type; servicePrincipalClientId = $Record.resource.properties.servicePrincipalProfile.clientId }
        if ($type -and $type -ne 'None') { return New-Pass "Managed identity ($type)" $evidence }
        New-Fail 'Service principal based cluster identity' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AKS-009'
    Title         = 'AKS encrypts Kubernetes secrets with Key Vault KMS'
    Category      = 'Data protection'
    Service       = 'Azure Kubernetes Service'
    Severity      = 'Low'
    Description   = 'Checks for Key Management Service (KMS) etcd encryption with a Key Vault key.'
    Rationale     = 'KMS adds envelope encryption of Kubernetes secrets in etcd with a customer controlled key that can be rotated and revoked.'
    Remediation   = 'Enable KMS etcd encryption (az aks update --enable-azure-keyvault-kms --azure-keyvault-kms-key-id ...), or keep application secrets in Key Vault via the Secrets Store CSI driver.'
    References    = @('https://learn.microsoft.com/azure/aks/use-kms-etcd-encryption')
    Policy        = @{ 'dbbdc317-9734-4dd8-9074-993b29c69008' = 'Azure Kubernetes Clusters should enable Key Management Service (KMS)' }
    ResourceTypes = $aksType
    Evaluate      = {
        param($Record)
        $kms = $Record.resource.properties.securityProfile.azureKeyVaultKms
        if ($kms.enabled) { return New-Pass 'KMS enabled' ([ordered]@{ kmsEnabled = $true; keyVaultNetworkAccess = $kms.keyVaultNetworkAccess }) }
        New-Fail 'KMS not enabled' ([ordered]@{ kmsEnabled = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-ACR-001'
    Title         = 'Container registries disable the admin user'
    Category      = 'Identity management'
    Service       = 'Container Registry'
    Severity      = 'Medium'
    Description   = 'Checks adminUserEnabled on container registries.'
    Rationale     = 'The admin user is a shared username and password with push and pull rights on every repository, not tied to an identity.'
    Remediation   = 'Use Entra identities (managed identities, service principals) with ACR RBAC roles and disable the admin user (az acr update --admin-enabled false ...).'
    References    = @('https://learn.microsoft.com/azure/container-registry/container-registry-authentication')
    Policy        = @{ 'dc921057-6b28-4fbe-9b83-f7bec05db6c2' = 'Container registries should have local admin account disabled.' }
    ResourceTypes = $acrType
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.adminUserEnabled
        if ($value) { return New-Fail 'Admin user enabled' ([ordered]@{ adminUserEnabled = $true }) }
        New-Pass 'Admin user disabled' ([ordered]@{ adminUserEnabled = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-ACR-002'
    Title         = 'Container registries disable anonymous pull'
    Category      = 'Identity management'
    Service       = 'Container Registry'
    Severity      = 'High'
    Description   = 'Checks anonymousPullEnabled on container registries.'
    Rationale     = 'Anonymous pull lets anyone download images, which often contain proprietary code, configuration and embedded secrets.'
    Remediation   = 'Disable anonymous pull (az acr update --anonymous-pull-enabled false ...).'
    References    = @('https://learn.microsoft.com/azure/container-registry/anonymous-pull-access')
    Policy        = @{ '9f2dea28-e834-476c-99c5-3507b4728395' = 'Container registries should have anonymous authentication disabled.' }
    ResourceTypes = $acrType
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.anonymousPullEnabled
        if ($value) { return New-Fail 'Anonymous pull enabled' ([ordered]@{ anonymousPullEnabled = $true }) }
        New-Pass 'Anonymous pull disabled' ([ordered]@{ anonymousPullEnabled = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-ACR-003'
    Title         = 'Container registries restrict network access'
    Category      = 'Network security'
    Service       = 'Container Registry'
    Severity      = 'Medium'
    Description   = 'Checks that public network access is disabled or the network rule set denies access by default (Premium SKU).'
    Rationale     = 'A registry open to all networks can be reached with a leaked token from anywhere, allowing image theft or poisoning.'
    Remediation   = 'Use the Premium SKU with private endpoints and disable public network access, or set the default network action to Deny with specific IP rules.'
    References    = @('https://learn.microsoft.com/azure/container-registry/container-registry-access-selected-networks')
    Policy        = @{ 'd0793b48-0edc-4296-a390-4c75d1bdfd71' = 'Container registries should not allow unrestricted network access'; 'e8eef0a8-67cf-4eb4-9386-14b0e78733d4' = 'Container registries should use private link' }
    ResourceTypes = $acrType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; defaultAction = $p.networkRuleSet.defaultAction; sku = $Record.resource.sku.name }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if ($p.networkRuleSet.defaultAction -eq 'Deny') { return New-Pass 'Default network action Deny' $evidence }
        New-Fail 'Open to all networks' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ACR-004'
    Title         = 'Container registries disable ARM audience token authentication'
    Category      = 'Identity management'
    Service       = 'Container Registry'
    Severity      = 'Low'
    Description   = "Checks the azureADAuthenticationAsArmPolicy, which decides whether general Azure Resource Manager tokens are accepted for registry access."
    Rationale     = 'Accepting ARM audience tokens means any token issued for management.azure.com can be used against the registry; registry scoped tokens limit the blast radius of a stolen token.'
    Remediation   = 'Disable ARM audience tokens (az acr config authentication-as-arm update --status disabled ...).'
    References    = @('https://learn.microsoft.com/azure/container-registry/container-registry-disable-authentication-as-arm')
    Policy        = @{ '42781ec6-6127-4c30-bdfa-fb423a0047d3' = 'Container registries should have ARM audience token authentication disabled.' }
    ResourceTypes = $acrType
    Evaluate      = {
        param($Record)
        $status = $Record.resource.properties.policies.azureADAuthenticationAsArmPolicy.status
        $evidence = [ordered]@{ azureADAuthenticationAsArmPolicy = $status }
        if ($status -eq 'disabled') { return New-Pass 'ARM audience tokens disabled' $evidence }
        New-Fail 'ARM audience tokens accepted' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ACR-005'
    Title         = 'Container registries do not use repository scoped access tokens'
    Category      = 'Identity management'
    Service       = 'Container Registry'
    Severity      = 'Low'
    Description   = 'Finds enabled repository scoped tokens on container registries.'
    Rationale     = 'Repository scoped tokens are passwords that are not tied to an Entra identity and bypass Conditional Access and RBAC reviews.'
    Remediation   = 'Replace tokens with Entra identities and ACR ABAC repository permissions, then disable or delete the tokens.'
    References    = @('https://learn.microsoft.com/azure/container-registry/container-registry-repository-scoped-permissions')
    Policy        = @{ 'ff05e24e-195c-447e-b322-5e90c9f9f366' = 'Container registries should have repository scoped access token disabled.' }
    ResourceTypes = $acrType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'tokens')) { return New-Unknown 'Tokens could not be listed' }
        $enabled = @(Get-Child $Record 'tokens' | Where-Object { $_ -and $_.properties.status -eq 'enabled' } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ enabledTokens = $enabled }
        if ($enabled) { return New-Fail "Enabled token(s): $($enabled -join ', ')" $evidence }
        New-Pass 'No enabled repository scoped tokens' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-CAPP-001'
    Title         = 'Container Apps only accept HTTPS'
    Category      = 'Data protection'
    Service       = 'Container Apps'
    Severity      = 'High'
    Description   = 'Checks that ingress of container apps does not allow insecure (HTTP) connections.'
    Rationale     = 'Allowing insecure connections exposes tokens, cookies and data to interception.'
    Remediation   = 'Set ingress allowInsecure to false (az containerapp ingress update --allow-insecure false ...).'
    References    = @('https://learn.microsoft.com/azure/container-apps/ingress-overview')
    Policy        = @{ '0e80e269-43a4-4ae9-b5bc-178126b8a5cb' = 'Container Apps should only be accessible over HTTPS' }
    ResourceTypes = @('Microsoft.App/containerApps')
    Evaluate      = {
        param($Record)
        $ingress = $Record.resource.properties.configuration.ingress
        if (-not $ingress) { return New-NotApplicable 'No ingress' }
        $evidence = [ordered]@{ allowInsecure = [bool]$ingress.allowInsecure; external = [bool]$ingress.external }
        if ($ingress.allowInsecure) { return New-Fail 'Insecure HTTP allowed' $evidence }
        New-Pass 'HTTPS only' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-CAPP-002'
    Title         = 'Container Apps ingress is not exposed externally unless required'
    Category      = 'Network security'
    Service       = 'Container Apps'
    Severity      = 'Low'
    Description   = 'Finds container apps with external ingress that has no IP security restrictions.'
    Rationale     = 'External ingress publishes the app to the Internet; internal services should use internal ingress, and public apps should sit behind a WAF or IP restrictions.'
    Remediation   = 'Use internal ingress for internal services, or add IP security restrictions / publish through Front Door with WAF.'
    References    = @('https://learn.microsoft.com/azure/container-apps/ip-restrictions')
    Policy        = @{ '783ea2a8-b8fd-46be-896a-9ae79643a0b1' = 'Container Apps should disable external network access' }
    ResourceTypes = @('Microsoft.App/containerApps')
    Evaluate      = {
        param($Record)
        $ingress = $Record.resource.properties.configuration.ingress
        if (-not $ingress) { return New-NotApplicable 'No ingress' }
        $restrictions = @($ingress.ipSecurityRestrictions | Where-Object { $_ })
        $evidence = [ordered]@{ external = [bool]$ingress.external; ipSecurityRestrictions = $restrictions.Count }
        if (-not $ingress.external) { return New-Pass 'Internal ingress' $evidence }
        if ($restrictions) { return New-Pass 'External ingress with IP restrictions' $evidence }
        New-Fail 'External ingress open to the Internet' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-ACI-001'
    Title         = 'Container instances are not exposed with a public IP address'
    Category      = 'Network security'
    Service       = 'Container Instances'
    Severity      = 'Medium'
    Description   = 'Finds container groups with a public IP address.'
    Rationale     = 'Public container groups have no network security group or WAF in front of them; every exposed port is reachable from the Internet.'
    Remediation   = 'Deploy the container group into a virtual network (private IP) and publish it through Application Gateway or a load balancer if it must be reachable.'
    References    = @('https://learn.microsoft.com/azure/container-instances/container-instances-vnet')
    ResourceTypes = @('Microsoft.ContainerInstance/containerGroups')
    Evaluate      = {
        param($Record)
        $address = $Record.resource.properties.ipAddress
        $evidence = [ordered]@{ ipAddressType = $address.type; ports = @($address.ports | ForEach-Object { "$($_.protocol)/$($_.port)" }) }
        if ($address.type -eq 'Public') { return New-Fail "Public IP with ports $($evidence.ports -join ', ')" $evidence }
        New-Pass $(if ($address) { 'Private IP address' } else { 'No IP address' }) $evidence
    }
}
