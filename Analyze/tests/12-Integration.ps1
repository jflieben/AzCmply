#Integration services: Service Bus and Event Hubs, API Management, Automation

Add-AzTest @{
    Id            = 'AZ-MSG-001'
    Title         = 'Service Bus and Event Hubs namespaces have no custom namespace level SAS rules'
    Category      = 'Privileged access'
    Service       = 'Messaging'
    Severity      = 'Medium'
    Description   = 'Finds namespace level shared access authorization rules other than RootManageSharedAccessKey on namespaces that allow local (SAS) authentication.'
    Rationale     = 'Namespace level rules grant access to every queue, topic or event hub in the namespace. Clients should get entity level rules or, better, Entra RBAC.'
    Remediation   = 'Replace namespace level rules with entity level rules or Entra ID RBAC data roles and delete them; consider disabling local authentication entirely.'
    References    = @('https://learn.microsoft.com/azure/service-bus-messaging/service-bus-sas')
    Frameworks    = @{ MCSB = @('PA-7', 'IM-8'); ALZ = @('Enforce-GR-ServiceBus0', 'Enforce-GR-EventHub0') }
    Defender      = @{ '077cc54b-eea9-e565-c72d-1ca6b5373728' = 'All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace' }
    Policy        = @{ 'a1817ec0-a368-432a-8057-8371e17ac6ee' = 'All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace'; 'b278e460-7cfc-4451-8294-cccc40a940d7' = 'All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace' }
    ResourceTypes = @('Microsoft.ServiceBus/namespaces', 'Microsoft.EventHub/namespaces')
    Evaluate      = {
        param($Record)
        if ($Record.resource.properties.disableLocalAuth -eq $true) { return New-Pass 'Local (SAS) authentication is disabled' }
        if (-not (Test-ChildCollected $Record 'authorizationRules')) { return New-Unknown 'Authorization rules could not be read' }
        $custom = @(Get-Child $Record 'authorizationRules' | Where-Object { $_ -and $_.name -ne 'RootManageSharedAccessKey' } | ForEach-Object { "$($_.name) ($(@($_.properties.rights) -join ','))" } | Sort-Object)
        $evidence = [ordered]@{ customRules = $custom }
        if ($custom) { return New-Fail "Namespace level rule(s): $($custom -join ', ')" $evidence }
        New-Pass 'Only RootManageSharedAccessKey' $evidence
    }
}

$apimType = @('Microsoft.ApiManagement/service')

Add-AzTest @{
    Id            = 'AZ-APIM-001'
    Title         = 'API Management direct management endpoint is disabled'
    Category      = 'Posture and vulnerability management'
    Service       = 'API Management'
    Severity      = 'Medium'
    Description   = 'Checks the tenant access setting that enables the legacy direct management REST API.'
    Rationale     = 'The direct management API uses shared access signatures instead of Entra ID and RBAC, bypassing Azure Resource Manager controls and logging.'
    Remediation   = 'Disable the direct management API (API Management > Management API > Enable API Management REST API: No).'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-howto-disable-management-api')
    Frameworks    = @{ MCSB = @('PV-2', 'IM-1'); ALZ = 'Enforce-GR-APIM0' }
    Defender      = @{ 'e2aeced9-6ef0-410e-b948-4aaa65ded9a7' = 'API Management direct management endpoint should not be enabled' }
    Policy        = @{ 'b741306c-968e-4b67-b916-5675e5c709f4' = 'API Management direct management endpoint should not be enabled' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'tenant/access')) { return New-Unknown 'Tenant access settings could not be read' }
        $enabled = [bool](Get-Child $Record 'tenant/access').properties.enabled
        if ($enabled) { return New-Fail 'Direct management API enabled' ([ordered]@{ enabled = $true }) }
        New-Pass 'Direct management API disabled' ([ordered]@{ enabled = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-002'
    Title         = 'API Management APIs only use encrypted protocols'
    Category      = 'Data protection'
    Service       = 'API Management'
    Severity      = 'High'
    Description   = 'Finds APIs that accept HTTP or WS instead of only HTTPS or WSS.'
    Rationale     = 'Unencrypted protocols expose subscription keys, tokens and payloads in transit.'
    Remediation   = 'Set the URL scheme of each API to HTTPS (and WSS for WebSocket APIs).'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-howto-manage-protocols-ciphers')
    Frameworks    = @{ MCSB = 'DP-3'; WAF = 'SE:07'; ALZ = 'Enforce-GR-APIM0' }
    Defender      = @{ '741b141d-8111-4d86-a4e0-f74b06270a74' = 'API Management APIs should use only encrypted protocols' }
    Policy        = @{ 'ee7495e7-3ba7-40b6-bfee-c29e22cc75d4' = 'API Management APIs should use only encrypted protocols' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'apis')) { return New-Unknown 'APIs could not be listed' }
        $insecure = @(Get-Child $Record 'apis' | Where-Object { $_ -and (@($_.properties.protocols) | Where-Object { $_ -in 'http', 'ws' }) } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ insecureApis = $insecure }
        if ($insecure) { return New-Fail "API(s) accepting HTTP/WS: $($insecure -join ', ')" $evidence }
        New-Pass 'All APIs use HTTPS/WSS only' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-003'
    Title         = 'API Management secret named values are stored in Key Vault'
    Category      = 'Identity management'
    Service       = 'API Management'
    Severity      = 'Medium'
    Description   = 'Finds named values marked as secret that are stored in API Management instead of referenced from Key Vault.'
    Rationale     = 'Secrets stored in API Management are not rotated centrally, not audited by Key Vault and are readable by anyone with API Management contributor rights.'
    Remediation   = 'Store the secrets in Key Vault and convert the named values to Key Vault references using the API Management managed identity.'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-howto-properties')
    Frameworks    = @{ MCSB = @('IM-8', 'DP-6'); WAF = 'SE:09'; ALZ = 'Enforce-GR-APIM0' }
    Policy        = @{ 'f1cc7827-022c-473e-836e-5a51cae0b249' = 'API Management secret named values should be stored in Azure Key Vault' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'namedValues')) { return New-Unknown 'Named values could not be listed' }
        $local = @(Get-Child $Record 'namedValues' | Where-Object { $_ -and $_.properties.secret -and -not $_.properties.keyVault } | ForEach-Object { $_.properties.displayName } | Sort-Object)
        $evidence = [ordered]@{ secretsNotInKeyVault = $local }
        if ($local) { return New-Fail "Secret named value(s) stored in API Management: $($local -join ', ')" $evidence }
        New-Pass 'All secret named values reference Key Vault' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-004'
    Title         = 'API Management subscriptions are not scoped to all APIs'
    Category      = 'Privileged access'
    Service       = 'API Management'
    Severity      = 'Medium'
    Description   = 'Finds subscriptions (other than the built-in master subscription) whose scope is all APIs.'
    Rationale     = 'An all-APIs subscription key grants access to every current and future API, including ones never intended for that consumer.'
    Remediation   = 'Scope subscriptions to products or individual APIs and regenerate or cancel all-APIs subscriptions.'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-subscriptions')
    Frameworks    = @{ MCSB = 'PA-7'; ALZ = 'Enforce-GR-APIM0' }
    Defender      = @{ '44aae697-8cc1-4ed1-a136-44a644bfd51f' = 'API Management subscriptions should not be scoped to all APIs' }
    Policy        = @{ '3aa03346-d8c5-4994-a5bc-7652c2a2aef1' = 'API Management subscriptions should not be scoped to all APIs' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'subscriptions')) { return New-Unknown 'Subscriptions could not be listed' }
        $wide = @(Get-Child $Record 'subscriptions' | Where-Object { $_ -and $_.name -ne 'master' -and $_.properties.state -eq 'active' -and [string]$_.properties.scope -match '/apis/?$' } | ForEach-Object { $_.properties.displayName } | Sort-Object)
        $evidence = [ordered]@{ allApisSubscriptions = $wide }
        if ($wide) { return New-Fail "Subscription(s) scoped to all APIs: $($wide -join ', ')" $evidence }
        New-Pass 'No active subscriptions scoped to all APIs' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-005'
    Title         = 'API Management validates backend certificates'
    Category      = 'Data protection'
    Service       = 'API Management'
    Severity      = 'Medium'
    Description   = 'Finds backends that disable certificate chain or certificate name validation.'
    Rationale     = 'Without certificate validation the gateway accepts any certificate, enabling man-in-the-middle attacks between API Management and the backend.'
    Remediation   = 'Enable validateCertificateChain and validateCertificateName on all backends and use certificates from a trusted CA.'
    References    = @('https://learn.microsoft.com/azure/api-management/backends')
    Frameworks    = @{ MCSB = @('IM-4', 'DP-3') }
    Defender      = @{ 'e0905114-2b51-4728-ab31-550f2058ec6c' = 'API Management calls to API backends should not bypass certificate thumbprint or name validation' }
    Policy        = @{ '92bb331d-ac71-416a-8c91-02f2cb734ce4' = 'API Management calls to API backends should not bypass certificate thumbprint or name validation' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'backends')) { return New-Unknown 'Backends could not be listed' }
        $bypass = @(Get-Child $Record 'backends' | Where-Object { $_ -and ($_.properties.tls.validateCertificateChain -eq $false -or $_.properties.tls.validateCertificateName -eq $false) } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ backendsWithoutValidation = $bypass }
        if ($bypass) { return New-Fail "Backend(s) without certificate validation: $($bypass -join ', ')" $evidence }
        New-Pass 'Backend certificates are validated' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-006'
    Title         = 'API Management disables legacy TLS and SSL protocols'
    Category      = 'Data protection'
    Service       = 'API Management'
    Severity      = 'Medium'
    Description   = 'Checks the gateway and backend protocol settings for SSL 3.0, TLS 1.0 and TLS 1.1.'
    Rationale     = 'Legacy protocols have known weaknesses and allow downgrade of client and backend connections.'
    Remediation   = 'Disable SSL 3.0, TLS 1.0 and TLS 1.1 for client and backend connections (Protocols + ciphers blade).'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-howto-manage-protocols-ciphers')
    Frameworks    = @{ MCSB = @('DP-3', 'NS-8'); ALZ = 'Enforce-TLS-SSL-Q225' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        $custom = $Record.resource.properties.customProperties
        $enabled = @($custom.PSObject.Properties | Where-Object { $_.Name -match 'Security\.(Backend\.)?Protocols\.(Tls10|Tls11|Ssl30)$' -and [string]$_.Value -eq 'True' } | ForEach-Object { $_.Name -replace '^.*Security\.', '' } | Sort-Object)
        $evidence = [ordered]@{ legacyProtocolsEnabled = $enabled }
        if ($enabled) { return New-Fail "Enabled: $($enabled -join ', ')" $evidence }
        New-Pass 'Legacy protocols disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APIM-007'
    Title         = 'API Management runs on the stv2 platform'
    Category      = 'Asset management'
    Service       = 'API Management'
    Severity      = 'High'
    Description   = 'Checks the compute platform version of API Management instances.'
    Rationale     = 'The stv1 platform was retired on 31 August 2024 and no longer receives support or security updates.'
    Remediation   = 'Migrate the instance to the stv2 platform.'
    References    = @('https://learn.microsoft.com/azure/api-management/migrate-stv1-to-stv2')
    Frameworks    = @{ MCSB = @('PV-2', 'AM-2') }
    Defender      = @{ 'e5f60ef8-3fcc-4fb5-bee7-7aaeb44c1509' = 'Azure API Management platform version should be stv2' }
    Policy        = @{ '1dc2fc00-2245-4143-99f4-874c937f13ef' = 'Azure API Management platform version should be stv2' }
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        $version = $Record.resource.properties.platformVersion
        $evidence = [ordered]@{ platformVersion = $version }
        if ($version -eq 'stv1') { return New-Fail 'Retired stv1 platform' $evidence }
        New-Pass "Platform $version" $evidence
    }
}

$automationType = @('Microsoft.Automation/automationAccounts')

Add-AzTest @{
    Id            = 'AZ-AUTO-001'
    Title         = 'Automation account variables are encrypted'
    Category      = 'Data protection'
    Service       = 'Automation'
    Severity      = 'High'
    Description   = 'Finds Automation variables that are not encrypted. The values of unencrypted variables are readable by anyone with Reader access.'
    Rationale     = 'Unencrypted variables are frequently used for passwords, keys and connection strings, which are then exposed through the Azure Resource Manager API and exports.'
    Remediation   = 'Recreate sensitive variables as encrypted variables (encryption cannot be added later) or move them to Key Vault, then delete the unencrypted ones.'
    References    = @('https://learn.microsoft.com/azure/automation/shared-resources/variables')
    Frameworks    = @{ MCSB = @('DP-4', 'IM-8'); WAF = 'SE:09'; ALZ = 'Enforce-GR-Automation0' }
    Defender      = @{ 'b12bc79e-4f12-44db-acda-571820191ddc' = 'Automation account variables should be encrypted' }
    Policy        = @{ '3657f5a0-770e-44a3-b44e-9431ba1e9735' = 'Automation account variables should be encrypted' }
    ResourceTypes = $automationType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'variables')) { return New-Unknown 'Variables could not be listed' }
        $plain = @(Get-Child $Record 'variables' | Where-Object { $_ -and -not $_.properties.isEncrypted } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ unencryptedVariables = $plain }
        if ($plain) { return New-Fail "Unencrypted variable(s): $($plain -join ', ')" $evidence }
        New-Pass 'All variables encrypted' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AUTO-002'
    Version       = 2
    Title         = 'Automation accounts use managed identities instead of Run As accounts'
    Category      = 'Identity management'
    Service       = 'Automation'
    Severity      = 'Medium'
    Description   = 'Checks that Automation accounts have a managed identity and no legacy Run As (AzureServicePrincipal) connections or certificates.'
    Rationale     = 'Run As accounts were retired on 30 September 2023; they rely on self-signed certificates stored in the account and usually hold Contributor on the whole subscription.'
    Remediation   = 'Enable a managed identity, grant it the minimal roles, update runbooks to Connect-AzAccount -Identity, then delete the Run As connection, certificate and application.'
    References    = @('https://learn.microsoft.com/azure/automation/migrate-run-as-accounts-managed-identity')
    Frameworks    = @{ MCSB = @('IM-3', 'IM-8'); WAF = 'SE:09' }
    Policy        = @{ 'dea83a72-443c-4292-83d5-54a2f98749c0' = 'Automation Account should have Managed Identity' }
    ResourceTypes = $automationType
    Evaluate      = {
        param($Record)
        $identity = $Record.resource.identity.type
        if (-not (Test-ChildCollected $Record 'connections') -or -not (Test-ChildCollected $Record 'certificates')) { return New-Unknown 'Automation connections or certificates could not be read' }
        $runAsConnections = @(Get-Child $Record 'connections' | Where-Object { $_ -and $_.properties.connectionType.name -eq 'AzureServicePrincipal' } | ForEach-Object name)
        $runAsCertificates = @(Get-Child $Record 'certificates' | Where-Object { $_ -and $_.name -match 'RunAs' } | ForEach-Object name)
        $evidence = [ordered]@{ identityType = $identity; runAsConnections = $runAsConnections; runAsCertificates = $runAsCertificates }
        if ($runAsConnections -or $runAsCertificates) { return New-Fail 'Legacy Run As account present' $evidence }
        if (-not $identity -or $identity -eq 'None') { return New-Fail 'No managed identity' $evidence }
        New-Pass "Managed identity ($identity)" $evidence
    }
}
