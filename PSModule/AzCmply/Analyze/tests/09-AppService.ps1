#App Service: web apps, function apps and their deployment slots

$siteTypes = @('Microsoft.Web/sites', 'Microsoft.Web/sites/slots')

function Get-SiteConfig {
    param($Record)
    $config = Get-Child $Record 'config/web'
    if ($config) { return $config.properties }
    return $null
}

Add-AzTest @{
    Id            = 'AZ-APP-001'
    Title         = 'App Service apps are only accessible over HTTPS'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = "Checks the 'HTTPS Only' setting of web apps, function apps and slots."
    Rationale     = 'Without HTTPS Only, clients can use plain HTTP, exposing session cookies, tokens and data to interception and manipulation.'
    Remediation   = 'Enable HTTPS Only (az webapp update --https-only true ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-ssl-bindings#enforce-https')
    Frameworks    = @{ MCSB = 'DP-3'; WAF = 'SE:07'; ALZ = @('Enforce-TLS-SSL-Q225', 'Enforce-GR-AppServices0') }
    Defender      = @{ '1b351b29-41ca-6df5-946c-c190a56be5fe' = 'Web Application should only be accessible over HTTPS'; 'cb0acdc6-0846-fd48-debe-9905af151b6d' = 'Function App should only be accessible over HTTPS' }
    Policy        = @{ 'a4af4a39-4135-47fb-b175-47fbdf85311d' = 'App Service apps should only be accessible over HTTPS'; '6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab' = 'Function apps should only be accessible over HTTPS' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.httpsOnly
        if ($value) { return New-Pass 'HTTPS only' ([ordered]@{ httpsOnly = $true }) }
        New-Fail 'HTTP allowed' ([ordered]@{ httpsOnly = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-002'
    Title         = 'App Service apps require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'Checks the minimum TLS version of the app and of its SCM (Kudu) site.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses; the SCM site handles deployment credentials and code and needs the same protection as the app.'
    Remediation   = 'Set the minimum inbound TLS version and SCM minimum TLS version to 1.2 or 1.3 (az webapp config set --min-tls-version 1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-tls')
    Frameworks    = @{ MCSB = @('DP-3', 'NS-8'); WAF = 'SE:07'; ALZ = @('Enforce-TLS-SSL-Q225', 'Enforce-GR-AppServices0') }
    Defender      = @{ '2a54c352-7ca4-4bae-ad46-47ecd9595bd2' = 'TLS should be updated to the latest version for web apps'; '15be5f3c-e0a4-c0fa-fbff-8e50339b4b22' = 'TLS should be updated to the latest version for function apps' }
    Policy        = @{ 'f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b' = 'App Service apps should use the latest TLS version' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ minTlsVersion = $config.minTlsVersion; scmMinTlsVersion = $config.scmMinTlsVersion }
        $problems = @()
        if (-not (Test-VersionAtLeast $config.minTlsVersion '1.2')) { $problems += "app minimum TLS $($config.minTlsVersion)" }
        if ($config.scmMinTlsVersion -and -not (Test-VersionAtLeast $config.scmMinTlsVersion '1.2')) { $problems += "SCM minimum TLS $($config.scmMinTlsVersion)" }
        if ($problems) { return New-Fail ($problems -join ', ') $evidence }
        New-Pass "Minimum TLS $($config.minTlsVersion)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-003'
    Title         = 'App Service apps disable FTP or require FTPS'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'Checks that the FTP state is Disabled or FtpsOnly.'
    Rationale     = 'Plain FTP sends deployment credentials and code in clear text.'
    Remediation   = 'Set the FTP state to Disabled (preferred) or FtpsOnly (az webapp config set --ftps-state Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/deploy-ftp#enforce-ftps')
    Frameworks    = @{ MCSB = @('DP-3', 'NS-8'); WAF = 'SE:08'; ALZ = 'Enforce-GR-AppServices0' }
    Defender      = @{ '19beaa2a-a126-b4dd-6d35-617f6cc83fca' = 'FTPS should be required in web apps'; '972a6579-f38f-c0b9-1b4b-a5bbeba3ab5b' = 'FTPS should be required in function apps' }
    Policy        = @{ '4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b' = 'App Service apps should require FTPS only'; '399b2637-a50f-4f95-96f8-3a145476eb15' = 'Function apps should require FTPS only' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ ftpsState = $config.ftpsState }
        if ($config.ftpsState -in 'Disabled', 'FtpsOnly') { return New-Pass "FTP state $($config.ftpsState)" $evidence }
        New-Fail "FTP state $($config.ftpsState)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-004'
    Title         = 'App Service basic authentication for FTP and SCM is disabled'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Medium'
    Description   = 'Checks the basic publishing credentials policies (ftp and scm) of apps and slots.'
    Rationale     = 'Basic authentication uses publishing profile passwords that are not bound to a user, bypass MFA and Conditional Access, and are easily leaked through publish profiles.'
    Remediation   = "Disable 'SCM Basic Auth Publishing Credentials' and 'FTP Basic Auth Publishing Credentials' and deploy with Entra authenticated methods (GitHub Actions OIDC, az webapp deploy)."
    References    = @('https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable')
    Frameworks    = @{ MCSB = @('IM-1', 'IM-3'); WAF = 'SE:05'; ALZ = 'Enforce-GR-AppServices0' }
    Policy        = @{ '871b205b-57cf-4e1e-a234-492616998bf7' = 'App Service apps should have local authentication methods disabled for FTP deployments'; 'aede300b-d67f-480a-ae26-4b3dfb1a1fdc' = 'App Service apps should have local authentication methods disabled for SCM site deployments' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'basicPublishingCredentialsPolicies')) { return New-Unknown 'Basic publishing credential policies could not be read' }
        $allowed = @(Get-Child $Record 'basicPublishingCredentialsPolicies' | Where-Object { $_ -and $_.properties.allow -ne $false } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ basicAuthAllowed = $allowed }
        if ($allowed) { return New-Fail "Basic authentication allowed for $($allowed -join ', ')" $evidence }
        New-Pass 'Basic authentication disabled for FTP and SCM' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-005'
    Title         = 'Remote debugging is turned off'
    Category      = 'Posture and vulnerability management'
    Service       = 'App Service'
    Severity      = 'Medium'
    Description   = 'Checks the remote debugging setting of apps and slots.'
    Rationale     = 'Remote debugging opens additional inbound ports and debugging endpoints; it should only be on temporarily during troubleshooting.'
    Remediation   = 'Turn off remote debugging (az webapp config set --remote-debugging-enabled false ...).'
    Frameworks    = @{ MCSB = @('PV-2', 'NS-8'); WAF = 'SE:08'; ALZ = 'Enforce-GR-AppServices0' }
    Defender      = @{ '64b8637e-4e1d-76a9-0fc9-c1e487a97ed8' = 'Remote debugging should be turned off for Web Applications'; '093c685b-56dd-13a3-8ed5-887a001837a2' = 'Remote debugging should be turned off for Function App' }
    Policy        = @{ 'cb510bfd-1cba-4d9f-a230-cb0976f4bb71' = 'App Service apps should have remote debugging turned off'; '0e60b895-3786-45da-8377-9c6b4b6ac5f9' = 'Function apps should have remote debugging turned off' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ remoteDebuggingEnabled = [bool]$config.remoteDebuggingEnabled; remoteDebuggingVersion = $config.remoteDebuggingVersion }
        if ($config.remoteDebuggingEnabled) { return New-Fail 'Remote debugging enabled' $evidence }
        New-Pass 'Remote debugging off' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-006'
    Title         = 'App Service apps use a managed identity'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that apps and slots have a system or user assigned managed identity.'
    Rationale     = 'Apps without a managed identity typically hold connection strings, keys or client secrets in their configuration to reach other services.'
    Remediation   = 'Enable a managed identity (az webapp identity assign ...), grant it RBAC roles on the target services and remove stored credentials.'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-managed-identity')
    Frameworks    = @{ MCSB = 'IM-3'; WAF = 'SE:09' }
    Defender      = @{ '4a3d7cd3-f17c-637a-1ffc-614a01dd03cf' = 'Managed identity should be enabled on web apps'; '23aa9cbe-c2fb-6a2f-6c97-885a6d48c4d1' = 'Managed identity should be enabled on function apps' }
    Policy        = @{ '2b9ad585-36bc-4615-b300-fd4435808332' = 'App Service apps should use managed identity' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $type = $Record.resource.identity.type
        $evidence = [ordered]@{ identityType = $type }
        if ($type -and $type -ne 'None') { return New-Pass "Managed identity ($type)" $evidence }
        New-Fail 'No managed identity' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-007'
    Title         = 'CORS does not allow every origin'
    Category      = 'Posture and vulnerability management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = "Checks the CORS allowed origins of apps and slots for the wildcard '*'."
    Rationale     = 'A wildcard CORS policy lets any website call the API from a victim browser and read responses, weakening protections against cross-site data theft.'
    Remediation   = 'Replace * with the specific origins that need access (az webapp cors remove --allowed-origins * ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-rest-api#add-cors-functionality')
    Frameworks    = @{ MCSB = 'PV-2'; WAF = 'SE:08' }
    Defender      = @{ 'df4d1739-47f0-60c7-1706-3731fea6ab03' = 'CORS should not allow every resource to access Web Applications'; '7b3d4796-9400-2904-692b-4a5ede7f0a1e' = 'CORS should not allow every resource to access Function Apps' }
    Policy        = @{ '5744710e-cc2f-4ee8-8809-3b11e89f4bc9' = 'App Service apps should not have CORS configured to allow every resource to access your apps' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $origins = @($config.cors.allowedOrigins | Where-Object { $_ })
        $evidence = [ordered]@{ allowedOrigins = $origins; supportCredentials = [bool]$config.cors.supportCredentials }
        if ($origins -contains '*') { return New-Fail 'CORS allows every origin' $evidence }
        New-Pass $(if ($origins) { "CORS limited to $($origins.Count) origin(s)" } else { 'No CORS origins configured' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-008'
    Title         = 'App Service apps restrict public network access'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that apps disable public network access or deny access by default with access restrictions. Internet facing apps should be published through Front Door or Application Gateway with WAF.'
    Rationale     = 'An app that is reachable directly from the Internet bypasses the WAF and any network controls in front of it; internal apps should not be public at all.'
    Remediation   = "Disable public network access and use private endpoints for internal apps; for public apps restrict inbound access to the Front Door or Application Gateway (service tag and X-Azure-FDID header)."
    References    = @('https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions')
    Frameworks    = @{ MCSB = 'NS-2'; WAF = 'SE:06'; ALZ = 'Deny-Public-Endpoints' }
    Policy        = @{ '1b5ef780-c53c-4a64-87f3-bb9c8c8094ba' = 'App Service apps should disable public network access'; '969ac98b-88a8-449f-883c-2e9adb123127' = 'Function apps should disable public network access' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        $access = if ($Record.resource.properties.publicNetworkAccess) { $Record.resource.properties.publicNetworkAccess } else { $config.publicNetworkAccess }
        $restrictions = @($config.ipSecurityRestrictions | Where-Object { $_ -and $_.action -eq 'Allow' -and $_.ipAddress -ne 'Any' })
        $evidence = [ordered]@{ publicNetworkAccess = $access; defaultAction = $config.ipSecurityRestrictionsDefaultAction; allowRules = $restrictions.Count }
        if ($access -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if ($config.ipSecurityRestrictionsDefaultAction -eq 'Deny' -or $restrictions) { return New-Pass 'Access restrictions limit inbound traffic' $evidence }
        New-Fail 'Reachable from any network' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-009'
    Version       = 2
    Title         = 'HTTP triggered functions do not allow anonymous access'
    Category      = 'Identity management'
    Service       = 'Azure Functions'
    Severity      = 'Low'
    Description   = "Finds HTTP triggered functions with authLevel 'anonymous'."
    Rationale     = 'Anonymous functions accept calls from anyone who knows the URL. Unless the function authenticates callers itself (for example webhook signatures or App Service authentication), it is an open endpoint.'
    Remediation   = "Use authLevel 'function' or enable App Service authentication (Easy Auth) with Entra ID, and validate signatures for webhooks."
    References    = @('https://learn.microsoft.com/azure/azure-functions/security-concepts#authorization-scopes-function-level')
    Frameworks    = @{ MCSB = @('IM-7', 'IM-5'); WAF = 'SE:05' }
    ResourceTypes = $siteTypes
    Filter        = { param($Record) [string]$Record.resource.kind -match 'functionapp' }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'functions')) { return New-Unknown 'Functions could not be listed' }
        if (-not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'App Service authentication settings could not be read' }
        $auth = (Get-Child $Record 'config/authsettingsV2').properties
        $enforced = [bool]$auth.platform.enabled -and $auth.globalValidation.requireAuthentication -eq $true
        $excluded = @($auth.globalValidation.excludedPaths | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('/').ToLowerInvariant() })
        $anonymous = foreach ($function in @(Get-Child $Record 'functions' | Where-Object { $_ -and -not $_.properties.isDisabled })) {
            $trigger = @($function.properties.config.bindings) | Where-Object { $_.type -eq 'httpTrigger' -and $_.authLevel -eq 'anonymous' } | Select-Object -First 1
            if (-not $trigger) { continue }
            $name = ($function.name -split '/')[-1]
            $route = "/api/$(if ($trigger.route) { $trigger.route } else { $name })".ToLowerInvariant()
            [pscustomobject]@{ Name = $name; Unprotected = (-not $enforced) -or [bool]($excluded | Where-Object { $route -eq $_ -or $route.StartsWith("$_/") }) }
        }
        $unprotected = @($anonymous | Where-Object Unprotected | ForEach-Object Name | Sort-Object)
        $evidence = [ordered]@{ anonymousFunctions = @($anonymous | ForEach-Object Name | Sort-Object); appServiceAuthenticationRequired = $enforced; excludedPaths = $excluded; unprotectedFunctions = $unprotected }
        if ($unprotected) { return New-Fail "Anonymous HTTP function(s) reachable without authentication: $($unprotected -join ', ')" $evidence }
        if ($anonymous) { return New-Pass 'Anonymous functions are behind required App Service authentication' $evidence }
        New-Pass 'No anonymous HTTP functions' $evidence
    }
}
