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
    Description   = "Checks the 'HTTPS Only' setting of web apps, function apps and their deployment slots."
    Rationale     = 'Without HTTPS Only, clients can use plain HTTP, exposing session cookies, tokens and data to interception and manipulation.'
    Remediation   = 'Enable HTTPS Only (az webapp update --https-only true ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-ssl-bindings#enforce-https')
    Defender      = @{ '1b351b29-41ca-6df5-946c-c190a56be5fe' = 'Web Application should only be accessible over HTTPS'; 'cb0acdc6-0846-fd48-debe-9905af151b6d' = 'Function App should only be accessible over HTTPS' }
    Policy        = @{ 'a4af4a39-4135-47fb-b175-47fbdf85311d' = 'App Service apps should only be accessible over HTTPS'; 'ae1b9a8c-dfce-4605-bd91-69213b4a26fc' = 'App Service app slots should only be accessible over HTTPS'; '6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab' = 'Function apps should only be accessible over HTTPS'; '5e5dbe3f-2702-4ffc-8b1e-0cae008a5c71' = 'Function app slots should only be accessible over HTTPS' }
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
    Version       = 2
    Title         = 'App Service apps require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'Checks the minimum inbound TLS version of web apps, function apps and their deployment slots. The deployment (SCM) site is AZ-APP-015.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses that allow traffic to be decrypted or manipulated.'
    Remediation   = 'Set the minimum inbound TLS version to 1.2 or 1.3 (az webapp config set --min-tls-version 1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-tls')
    Defender      = @{ '2a54c352-7ca4-4bae-ad46-47ecd9595bd2' = 'TLS should be updated to the latest version for web apps'; '15be5f3c-e0a4-c0fa-fbff-8e50339b4b22' = 'TLS should be updated to the latest version for function apps' }
    Policy        = @{ 'f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b' = 'App Service apps should use the latest TLS version'; '4ee5b817-627a-435a-8932-116193268172' = 'App Service app slots should use the latest TLS version'; 'f9d614c5-c173-4d56-95a7-b4437057d193' = 'Function apps should use the latest TLS version'; 'deb528de-8f89-4101-881c-595899253102' = 'Function app slots should use the latest TLS version' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ minTlsVersion = $config.minTlsVersion }
        if (Test-VersionAtLeast $config.minTlsVersion '1.2') { return New-Pass "Minimum TLS $($config.minTlsVersion)" $evidence }
        New-Fail "Minimum TLS $(if ($config.minTlsVersion) { $config.minTlsVersion } else { 'not set' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-015'
    Title         = 'App Service deployment (SCM) sites require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'Checks the minimum TLS version of the deployment (SCM, Kudu) site of web apps, function apps and their deployment slots.'
    Rationale     = 'The deployment site handles deployment credentials and code and needs the same protection as the app; TLS 1.0 and 1.1 have known weaknesses.'
    Remediation   = 'Set the SCM minimum TLS version to 1.2 or 1.3 (az webapp config set --generic-configurations ''{"scmMinTlsVersion":"1.2"}'' ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-tls')
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ scmMinTlsVersion = $config.scmMinTlsVersion }
        if (-not $config.scmMinTlsVersion) { return New-Unknown 'The SCM minimum TLS version is not in the site configuration' $evidence }
        if (Test-VersionAtLeast $config.scmMinTlsVersion '1.2') { return New-Pass "SCM minimum TLS $($config.scmMinTlsVersion)" $evidence }
        New-Fail "SCM minimum TLS $($config.scmMinTlsVersion)" $evidence
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
    Defender      = @{ '19beaa2a-a126-b4dd-6d35-617f6cc83fca' = 'FTPS should be required in web apps'; '972a6579-f38f-c0b9-1b4b-a5bbeba3ab5b' = 'FTPS should be required in function apps' }
    Policy        = @{ '4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b' = 'App Service apps should require FTPS only'; 'c285a320-8830-4665-9cc7-bbd05fc7c5c0' = 'App Service app slots should require FTPS only'; '399b2637-a50f-4f95-96f8-3a145476eb15' = 'Function apps should require FTPS only'; 'e1a09430-221d-4d4c-a337-1edb5a1fa9bb' = 'Function app slots should require FTPS only' }
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
    Version       = 2
    Title         = 'App Service basic authentication for FTP and SCM is disabled'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Medium'
    Description   = 'Checks the basic publishing credentials policies (ftp and scm) of web apps, function apps and their deployment slots. Both have to be read and set to allow false.'
    Rationale     = 'Basic authentication uses publishing profile passwords that are not bound to a user, bypass MFA and Conditional Access, and are easily leaked through publish profiles.'
    Remediation   = "Disable 'SCM Basic Auth Publishing Credentials' and 'FTP Basic Auth Publishing Credentials' and deploy with Entra authenticated methods (GitHub Actions OIDC, az webapp deploy)."
    References    = @('https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable')
    Policy        = @{ '871b205b-57cf-4e1e-a234-492616998bf7' = 'App Service apps should have local authentication methods disabled for FTP deployments'; 'aede300b-d67f-480a-ae26-4b3dfb1a1fdc' = 'App Service apps should have local authentication methods disabled for SCM site deployments'; 'ec71c0bc-6a45-4b1f-9587-80dc83e6898c' = 'App Service app slots should have local authentication methods disabled for FTP deployments'; '847ef871-e2fe-4e6e-907e-4adbf71de5cf' = 'App Service app slots should have local authentication methods disabled for SCM site deployments' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'basicPublishingCredentialsPolicies')) { return New-Unknown 'Basic publishing credential policies could not be read' }
        $policies = @(Get-Child $Record 'basicPublishingCredentialsPolicies' | Where-Object { $_ })
        $allowed = @($policies | Where-Object { $_.properties.allow -ne $false } | ForEach-Object name | Sort-Object)
        $names = @($policies | ForEach-Object { ([string]$_.name -split '/')[-1] })
        $missing = @('ftp', 'scm' | Where-Object { $_ -notin $names })
        $evidence = [ordered]@{ basicAuthAllowed = $allowed; notRead = $missing }
        if ($allowed) { return New-Fail "Basic authentication allowed for $($allowed -join ', ')" $evidence }
        if ($missing) { return New-Unknown "The $($missing -join ' and ') policy was not read" $evidence }
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
    Defender      = @{ '64b8637e-4e1d-76a9-0fc9-c1e487a97ed8' = 'Remote debugging should be turned off for Web Applications'; '093c685b-56dd-13a3-8ed5-887a001837a2' = 'Remote debugging should be turned off for Function App' }
    Policy        = @{ 'cb510bfd-1cba-4d9f-a230-cb0976f4bb71' = 'App Service apps should have remote debugging turned off'; 'a08ae1ab-8d1d-422b-a123-df82b307ba61' = 'App Service app slots should have remote debugging turned off'; '0e60b895-3786-45da-8377-9c6b4b6ac5f9' = 'Function apps should have remote debugging turned off'; '89691ef9-8c50-49a8-8950-9c7fba41699e' = 'Function app slots should have remote debugging turned off' }
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
    Defender      = @{ '4a3d7cd3-f17c-637a-1ffc-614a01dd03cf' = 'Managed identity should be enabled on web apps'; '23aa9cbe-c2fb-6a2f-6c97-885a6d48c4d1' = 'Managed identity should be enabled on function apps' }
    Policy        = @{ '2b9ad585-36bc-4615-b300-fd4435808332' = 'App Service apps should use managed identity'; '4a15c15f-90d5-4a1f-8b63-2903944963fd' = 'App Service app slots should use managed identity'; '0da106f2-4ca3-48e8-bc85-c638fe6aea8f' = 'Function apps should use managed identity' }
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
    Defender      = @{ 'df4d1739-47f0-60c7-1706-3731fea6ab03' = 'CORS should not allow every resource to access Web Applications'; '7b3d4796-9400-2904-692b-4a5ede7f0a1e' = 'CORS should not allow every resource to access Function Apps' }
    Policy        = @{ '5744710e-cc2f-4ee8-8809-3b11e89f4bc9' = 'App Service apps should not have CORS configured to allow every resource to access your apps'; 'cae7c12e-764b-4c87-841a-fdc6675d196f' = 'App Service app slots should not have CORS configured to allow every resource to access your apps'; '0820b7b9-23aa-4725-a1ce-ae4558f718e5' = 'Function apps should not have CORS configured to allow every resource to access your apps'; 'a1a22235-dd10-4062-bd55-7d62778f41b0' = 'Function app slots should not have CORS configured to allow every resource to access your apps' }
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

$functionAppFilter = { param($Record) [string]$Record.resource.kind -match 'functionapp' }

function Get-SiteAuthentication {
    #whether App Service authentication turns unauthenticated requests away: only when sign-in is required and the action
    #is not AllowAnonymous, which passes them to the app. Settings in a file inside the app are not in the ingestion.
    param($Record)
    $settings = (Get-Child $Record 'config/authsettingsV2').properties
    $action = [string]$settings.globalValidation.unauthenticatedClientAction
    $fromFile = [bool]$settings.platform.enabled -and [bool]$settings.platform.configFilePath
    [pscustomobject]@{
        Enforced      = [bool]$settings.platform.enabled -and $settings.globalValidation.requireAuthentication -eq $true -and $action -ne 'AllowAnonymous' -and -not $fromFile
        FromFile      = $fromFile
        Action        = $action
        ExcludedPaths = @($settings.globalValidation.excludedPaths | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('/').ToLowerInvariant() })
        Settings      = $settings
    }
}

function Get-SiteHttpFunctions {
    #enabled HTTP triggered functions: name, auth level ('function' when not set) and whether App Service authentication
    #turns unauthenticated calls to their route away
    param($Record, $Authentication)
    foreach ($function in @(Get-Child $Record 'functions' | Where-Object { $_ -and -not $_.properties.isDisabled })) {
        $trigger = @($function.properties.config.bindings | Where-Object { $_ -and $_.type -eq 'httpTrigger' }) | Select-Object -First 1
        if (-not $trigger) { continue }
        $name = ($function.name -split '/')[-1]
        $route = "/api/$(if ($trigger.route) { $trigger.route } else { $name })".ToLowerInvariant()
        $excluded = [bool]@($Authentication.ExcludedPaths | Where-Object { $route -eq $_ -or $route.StartsWith("$_/") }).Count
        [pscustomobject]@{ Name = $name; AuthLevel = if ($trigger.authLevel) { ([string]$trigger.authLevel).ToLowerInvariant() } else { 'function' }; Protected = $Authentication.Enforced -and -not $excluded }
    }
}

function Test-SiteOpenToAnyNetwork {
    #true when an app accepts connections from any address: public network access on and no access restriction (AZ-APP-008)
    param($Record)
    $config = Get-SiteConfig $Record
    $access = if ($Record.resource.properties.publicNetworkAccess) { $Record.resource.properties.publicNetworkAccess } else { $config.publicNetworkAccess }
    if ($access -eq 'Disabled') { return $false }
    return -not (Test-SiteRestricted $config.ipSecurityRestrictions $config.ipSecurityRestrictionsDefaultAction)
}

Add-AzTest @{
    Id            = 'AZ-APP-009'
    Version       = 3
    Title         = 'HTTP triggered functions do not allow anonymous access'
    Category      = 'Identity management'
    Service       = 'Azure Functions'
    Severity      = 'Low'
    Description   = "Finds HTTP triggered functions with authLevel 'anonymous' that App Service authentication does not protect. It protects them only when it requires sign-in and turns unauthenticated requests away: with the action AllowAnonymous they reach the function."
    Rationale     = 'Anonymous functions accept calls from anyone who knows the URL. Unless the function authenticates callers itself (for example webhook signatures or token validation in its code), it is an open endpoint.'
    Remediation   = "Use authLevel 'function', or require App Service authentication (Easy Auth) with Entra ID and set unauthenticated requests to HTTP 401 or 403, and validate signatures for webhooks."
    References    = @('https://learn.microsoft.com/azure/azure-functions/security-concepts#authorization-scopes-function-level', 'https://learn.microsoft.com/azure/app-service/overview-authentication-authorization')
    ResourceTypes = $siteTypes
    Filter        = $functionAppFilter
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'functions')) { return New-Unknown 'Functions could not be listed' }
        if (-not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'App Service authentication settings could not be read' }
        $authentication = Get-SiteAuthentication $Record
        $anonymous = @(Get-SiteHttpFunctions $Record $authentication | Where-Object { $_.AuthLevel -eq 'anonymous' })
        $unprotected = @($anonymous | Where-Object { -not $_.Protected } | ForEach-Object { $_.Name } | Sort-Object)
        $evidence = [ordered]@{ anonymousFunctions = @($anonymous | ForEach-Object { $_.Name } | Sort-Object); appServiceAuthenticationRequired = $authentication.Enforced; unauthenticatedClientAction = $authentication.Action; excludedPaths = $authentication.ExcludedPaths; unprotectedFunctions = $unprotected }
        if ($unprotected -and $authentication.FromFile) { return New-Unknown 'App Service authentication is configured in a file inside the app, which the ingestion cannot read' $evidence }
        if ($unprotected) { return New-Fail "Anonymous HTTP function(s) reachable without authentication: $($unprotected -join ', ')" $evidence }
        if ($anonymous) { return New-Pass 'Anonymous functions are behind required App Service authentication' $evidence }
        New-Pass 'No anonymous HTTP functions' $evidence
    }
}

function Test-SiteRestricted {
    #whether access restrictions limit who can connect: a deny default, or an allow rule for something narrower than any address
    param($Rules, [string]$DefaultAction)
    if ($DefaultAction -eq 'Deny') { return $true }
    return [bool]@($Rules | Where-Object { $_ -and $_.action -eq 'Allow' -and $_.ipAddress -ne 'Any' }).Count
}

function Get-HeaderValues {
    #values of one header of an access restriction rule, whatever the casing of its name
    param($Headers, [string]$Name)
    foreach ($header in @($Headers.PSObject.Properties)) { if ($header.Name -eq $Name) { @($header.Value | Where-Object { $_ }) } }
}

Add-AzTest @{
    Id            = 'AZ-APP-010'
    Title         = 'App Service access restrictions for Front Door check the Front Door id'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'For App Service apps and slots with an access restriction that allows the AzureFrontDoor.Backend service tag, on the app or on its deployment (SCM) site, checks that the rule also requires the X-Azure-FDID header of your own Front Door profile.'
    Rationale     = 'The AzureFrontDoor.Backend addresses are shared by every Front Door customer. Without the X-Azure-FDID check anyone can create a Front Door profile, point it at the app and reach it around the Web Application Firewall, rules and authentication of your own Front Door.'
    Remediation   = 'Add the X-Azure-FDID header with the id of your Front Door profile to the rule (az webapp config access-restriction add --service-tag AzureFrontDoor.Backend --http-header x-azure-fdid=<profile id> ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions#restrict-access-to-a-specific-azure-front-door-instance', 'https://learn.microsoft.com/azure/frontdoor/origin-security')
    ResourceTypes = @('Microsoft.Web/sites', 'Microsoft.Web/sites/slots')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web')) { return New-Unknown 'The site configuration could not be read' }
        $config = Get-SiteConfig $Record
        $frontDoorRules = @(@($config.ipSecurityRestrictions) + @($config.scmIpSecurityRestrictions) | Where-Object { $_ -and $_.action -eq 'Allow' -and [string]$_.ipAddress -like 'AzureFrontDoor.Backend*' })
        if (-not $frontDoorRules) { return $null }
        $unchecked = @($frontDoorRules | Where-Object { -not @(Get-HeaderValues $_.headers 'x-azure-fdid').Count } | ForEach-Object { $_.name } | Sort-Object -Unique)
        $evidence = [ordered]@{ frontDoorRules = @($frontDoorRules | ForEach-Object { $_.name } | Sort-Object -Unique); withoutFrontDoorId = $unchecked }
        if ($unchecked) { return New-Fail "Rule(s) $($unchecked -join ', ') admit every Front Door profile" $evidence }
        New-Pass 'Every Front Door rule checks the Front Door id' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-011'
    Title         = 'App Service deployment sites are not more open than the app'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'For App Service apps and slots whose own access is restricted, checks that the deployment (SCM, Kudu) site uses the same restrictions or has its own. Apps without public network access pass; apps reachable from any network are AZ-APP-008.'
    Rationale     = 'The deployment site deploys code, opens a console on the app and shows its environment, including connection strings and keys. When the app is restricted to a Front Door, a gateway or office addresses but the deployment site is not, stolen credentials and tokens reach the deployment site from anywhere, around the network controls of the app.'
    Remediation   = "Turn on 'Use main site rules' for the deployment site (scmIpSecurityRestrictionsUseMain), or add access restrictions to it that admit only your build agents and administrators."
    References    = @('https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions#restrict-access-to-an-scm-site')
    ResourceTypes = @('Microsoft.Web/sites', 'Microsoft.Web/sites/slots')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web')) { return New-Unknown 'The site configuration could not be read' }
        $config = Get-SiteConfig $Record
        $access = if ($Record.resource.properties.publicNetworkAccess) { $Record.resource.properties.publicNetworkAccess } else { $config.publicNetworkAccess }
        $evidence = [ordered]@{ publicNetworkAccess = $access; scmUsesMainRules = [bool]$config.scmIpSecurityRestrictionsUseMain; scmDefaultAction = $config.scmIpSecurityRestrictionsDefaultAction; scmAllowRules = @($config.scmIpSecurityRestrictions | Where-Object { $_ -and $_.action -eq 'Allow' -and $_.ipAddress -ne 'Any' }).Count }
        if ($access -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if (-not (Test-SiteRestricted $config.ipSecurityRestrictions $config.ipSecurityRestrictionsDefaultAction)) { return New-NotApplicable 'The app itself is reachable from any network (AZ-APP-008)' $evidence }
        if ($config.scmIpSecurityRestrictionsUseMain) { return New-Pass 'The deployment site uses the access restrictions of the app' $evidence }
        if (Test-SiteRestricted $config.scmIpSecurityRestrictions $config.scmIpSecurityRestrictionsDefaultAction) { return New-Pass 'The deployment site has its own access restrictions' $evidence }
        New-Fail 'The app is restricted, but its deployment site is reachable from any network' $evidence
    }
}

#runtimes fail this many days before their end of life, to leave time to upgrade and test
$runtimeWarningDays = 90
#identity providers whose accounts anyone can create
$socialProviders = @('legacyMicrosoftAccount', 'facebook', 'google', 'twitter', 'gitHub', 'apple')
#function apps, without Standard logic apps (functionapp,workflowapp), whose runtime and storage work differently
$functionsOnlyFilter = { param($Record) [string]$Record.resource.kind -match 'functionapp' -and [string]$Record.resource.kind -notmatch 'workflowapp' }

function Get-StackRuntimes {
    #runtime versions of an App Service runtime catalog ('web/functionAppStacks', 'web/webAppStacks'): stack, version,
    #operating system, runtime version string (Linux runtime or Java container) and the settings with the end of life
    param([string]$Catalog)
    $key = "#stacks|$Catalog"
    if (-not $script:Ingest.Cache.ContainsKey($key)) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($stack in @(Get-IngestData $Catalog | Where-Object { $_ })) {
            foreach ($major in @($stack.properties.majorVersions | Where-Object { $_ })) {
                foreach ($minor in @($major.minorVersions | Where-Object { $_ })) {
                    $settings = $minor.stackSettings
                    if ($settings.linuxRuntimeSettings) { $list.Add([pscustomobject]@{ Stack = [string]$stack.name; Version = [string]$minor.value; Os = 'linux'; RuntimeVersion = [string]$settings.linuxRuntimeSettings.runtimeVersion; Settings = $settings.linuxRuntimeSettings }) }
                    if ($settings.windowsRuntimeSettings) { $list.Add([pscustomobject]@{ Stack = [string]$stack.name; Version = [string]$minor.value; Os = 'windows'; RuntimeVersion = [string]$settings.windowsRuntimeSettings.runtimeVersion; Settings = $settings.windowsRuntimeSettings }) }
                    if ($settings.linuxContainerSettings) {
                        foreach ($property in @($settings.linuxContainerSettings.PSObject.Properties | Where-Object { $_ -and $_.Name -like '*Runtime' -and $_.Value -is [string] })) {
                            $list.Add([pscustomobject]@{ Stack = [string]$stack.name; Version = [string]$minor.value; Os = 'linux'; RuntimeVersion = [string]$property.Value; Settings = $settings.linuxContainerSettings })
                        }
                    }
                }
            }
        }
        $script:Ingest.Cache[$key] = $list
    }
    return $script:Ingest.Cache[$key]
}

function Get-SiteRuntime {
    #language runtime of an app and its entry in the runtime catalog: Label and Entry, or Reason when it cannot be told.
    #Flex Consumption apps name it, Linux apps have it in linuxFxVersion; on Windows the language of the functions tells
    #which site setting holds the version (PowerShell, Java, .NET isolated)
    param($Record)
    $config = Get-SiteConfig $Record
    $catalog = if ([string]$Record.resource.kind -match 'functionapp') { 'web/functionAppStacks' } else { 'web/webAppStacks' }
    $runtimes = @(Get-StackRuntimes $catalog)
    $flex = $Record.resource.properties.functionAppConfig.runtime
    if ($flex -and $flex.name) {
        $entry = @($runtimes | Where-Object { $_.Os -eq 'linux' -and @($_.Settings.Sku | Where-Object { $_ -and $_.skuCode -eq 'FC1' -and [string]$_.functionAppConfigProperties.runtime.name -eq [string]$flex.name -and [string]$_.functionAppConfigProperties.runtime.version -eq [string]$flex.version }).Count }) | Select-Object -First 1
        return [pscustomobject]@{ Label = "$($flex.name) $($flex.version)"; Entry = $entry; Reason = $null }
    }
    $linuxFx = [string]$config.linuxFxVersion
    if ($linuxFx) {
        $entry = @($runtimes | Where-Object { $_.Os -eq 'linux' -and $_.RuntimeVersion -and $_.RuntimeVersion -eq $linuxFx }) | Select-Object -First 1
        #Java SE and Tomcat containers ('JAVA|21-java21') carry no end of life; the Java version they run on does
        if ($entry -and -not $entry.Settings.endOfLifeDate -and $linuxFx -match '(?i)-(java|jre)(\d+)$') {
            $major = $Matches[2]
            $java = @($runtimes | Where-Object { $_.Stack -eq 'java' -and $_.Os -eq 'linux' -and $_.Settings.endOfLifeDate -and $_.Version -in "$major.0", "1.$major" }) | Select-Object -First 1
            if ($java) { $entry = $java }
        }
        return [pscustomobject]@{ Label = $linuxFx; Entry = $entry; Reason = $null }
    }
    $languages = @(Get-Child $Record 'functions' | Where-Object { $_ } | ForEach-Object { ([string]$_.properties.language).ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $languages) { return [pscustomobject]@{ Label = $null; Entry = $null; Reason = 'no function shows the language' } }
    if ($languages.Count -gt 1) { return [pscustomobject]@{ Label = $null; Entry = $null; Reason = "the functions use several languages ($($languages -join ', '))" } }
    $language = $languages[0]
    $windows = @($runtimes | Where-Object { $_.Os -eq 'windows' })
    if ($language -eq 'powershell') {
        $entry = @($windows | Where-Object { $_.Stack -eq 'powershell' -and [string]$_.Settings.siteConfigPropertiesDictionary.powerShellVersion -eq [string]$config.powerShellVersion }) | Select-Object -First 1
        return [pscustomobject]@{ Label = "PowerShell $($config.powerShellVersion)"; Entry = $entry; Reason = $null }
    }
    if ($language -eq 'java') {
        $entry = @($windows | Where-Object { $_.Stack -eq 'java' -and [string]$_.Settings.siteConfigPropertiesDictionary.javaVersion -eq [string]$config.javaVersion }) | Select-Object -First 1
        return [pscustomobject]@{ Label = "Java $($config.javaVersion)"; Entry = $entry; Reason = $null }
    }
    if ($language -eq 'dotnet-isolated') {
        $entry = @($windows | Where-Object { $_.Stack -eq 'dotnet' -and $_.Settings.appSettingsDictionary.FUNCTIONS_WORKER_RUNTIME -eq 'dotnet-isolated' -and $_.RuntimeVersion -eq [string]$config.netFrameworkVersion }) | Select-Object -First 1
        return [pscustomobject]@{ Label = ".NET isolated $($config.netFrameworkVersion)"; Entry = $entry; Reason = $null }
    }
    return [pscustomobject]@{ Label = $language; Entry = $null; Reason = "the $language version of a Windows function app is an app setting, which a Reader cannot read" }
}

function Test-RoleGrantsDataAction {
    #true when a role definition allows a data action in one of its permission blocks (dataActions minus notDataActions, with wildcards)
    param($Definition, [string]$Action)
    foreach ($permission in @($Definition.properties.permissions | Where-Object { $_ })) {
        if (-not @($permission.dataActions | Where-Object { $_ -and $Action -like $_ }).Count) { continue }
        if (@($permission.notDataActions | Where-Object { $_ -and $Action -like $_ }).Count) { continue }
        return $true
    }
    return $false
}

function Get-FunctionHostStorage {
    #storage accounts a function app runs from, found without its app settings: the deployment container of a Flex
    #Consumption app, or a content share named after the app (Consumption and Premium plans)
    param($Record)
    $url = ([string]$Record.resource.properties.functionAppConfig.deployment.storage.value).ToLowerInvariant()
    $appName = ([string]$Record.resource.name).ToLowerInvariant()
    $names = @(@($appName, $appName.Replace('-', '')) | Sort-Object -Unique)
    foreach ($storage in (Get-AzResourceRecords -Type 'Microsoft.Storage/storageAccounts')) {
        $name = ([string]$storage.resource.name).ToLowerInvariant()
        if ($url -and $url.StartsWith("https://$name.blob.")) {
            [pscustomobject]@{ Record = $storage; Via = 'deployment container' }
            continue
        }
        $share = @(Get-Child $storage 'fileServices/default/shares' | Where-Object { $_ } | ForEach-Object { ([string]$_.name).ToLowerInvariant() } | Where-Object {
                $shareName = $_
                [bool]@($names | Where-Object { $shareName -match "^$([regex]::Escape($_))-?[a-z0-9]{0,12}$" }).Count
            }) | Select-Object -First 1
        if ($share) { [pscustomobject]@{ Record = $storage; Via = "content share $share" } }
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-012'
    Title         = 'App Service and function apps run a supported language runtime'
    Category      = 'Posture and vulnerability management'
    Service       = 'App Service'
    Severity      = 'Medium'
    Description   = "Looks up the language runtime of function apps and Linux web apps in the App Service runtime catalog of Azure Resource Manager and fails when the version is deprecated or its end of life is less than $runtimeWarningDays days away or has passed. Flex Consumption apps name their runtime and Linux apps have it in linuxFxVersion; on Windows the PowerShell, Java and .NET isolated versions of function apps are read from the site configuration. Windows web apps, custom containers and Standard logic apps are not evaluated."
    Rationale     = 'A runtime past its end of life gets no security fixes and no support from App Service, so known vulnerabilities in the language runtime stay open. The last months before the date are the time to upgrade and test.'
    Remediation   = 'Upgrade the app to a supported version of its language (the stack settings of the app, or the runtime of a Flex Consumption app), test it, and plan upgrades by the end-of-life dates of the runtime catalog.'
    References    = @('https://learn.microsoft.com/azure/azure-functions/language-support-policy', 'https://learn.microsoft.com/azure/app-service/language-support-policy')
    Requires      = @('web/functionAppStacks', 'web/webAppStacks')
    ResourceTypes = $siteTypes
    Filter        = { param($Record) ([string]$Record.resource.kind -match 'functionapp|linux') -and [string]$Record.resource.kind -notmatch 'workflowapp' }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web')) { return New-Unknown 'The site configuration could not be read' }
        $config = Get-SiteConfig $Record
        $isFunction = [string]$Record.resource.kind -match 'functionapp'
        if (-not $isFunction -and [string]$config.linuxFxVersion -match '^(DOCKER|COMPOSE|KUBE)\|') { return New-NotApplicable 'Custom container: the runtime is in the image' }
        if (-not $isFunction -and -not $config.linuxFxVersion) { return New-Unknown 'The Linux runtime is not set in the site configuration' }
        if ($isFunction -and -not $Record.resource.properties.functionAppConfig.runtime -and -not $config.linuxFxVersion -and -not (Test-ChildCollected $Record 'functions')) { return New-Unknown 'Functions could not be listed, so the language is not known' }
        $runtime = Get-SiteRuntime $Record
        if ($runtime.Reason) { return New-Unknown "The runtime cannot be determined: $($runtime.Reason)" }
        if (-not $runtime.Entry) { return New-Unknown "Runtime $($runtime.Label) is not in the App Service runtime catalog" ([ordered]@{ runtime = $runtime.Label }) }
        $settings = $runtime.Entry.Settings
        $end = Format-UtcDate $settings.endOfLifeDate
        $day = if ($end) { $end.Substring(0, 10) } else { $null }
        $daysLeft = if ($end) { -1 * (Get-AgeInDays $settings.endOfLifeDate) } else { $null }
        $evidence = [ordered]@{ runtime = $runtime.Label; catalogEntry = "$($runtime.Entry.Stack) $($runtime.Entry.Version)"; endOfLife = $day; daysLeft = $daysLeft; deprecated = [bool]$settings.isDeprecated }
        if ($settings.isDeprecated -eq $true) { return New-Fail "$($runtime.Label) is deprecated" $evidence }
        if ($null -ne $daysLeft -and $daysLeft -le 0) { return New-Fail "$($runtime.Label) reached its end of life on $day" $evidence }
        if ($null -ne $daysLeft -and $daysLeft -lt $runtimeWarningDays) { return New-Fail "$($runtime.Label) reaches its end of life on $day, in $daysLeft days" $evidence }
        if ($null -eq $daysLeft) { return New-Pass "$($runtime.Label) has no end-of-life date" $evidence }
        New-Pass "$($runtime.Label) is supported until $day" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-013'
    Title         = 'App Service access restrictions do not trust shared Azure service tags'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'High'
    Description   = 'Finds allow rules in the access restrictions of apps and their deployment (SCM) sites for AzureCloud, AppService, or the service tag of a service that any Azure customer can make send requests (the tags of AZ-NET-026), including their regional variants. Front Door rules are AZ-APP-010.'
    Rationale     = 'These tags hold the addresses of platforms shared by all Azure customers. Anyone can create a Logic App, an availability test or a pipeline that sends requests from those addresses, so the restriction admits every Azure tenant and not only your own services (Tenable TRA-2024-19).'
    Remediation   = 'Allow the addresses or private endpoints of your own resources instead, or keep the tag only where the app also authenticates the caller.'
    References    = @('https://www.tenable.com/security/research/tra-2024-19', 'https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions')
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web')) { return New-Unknown 'The site configuration could not be read' }
        $config = Get-SiteConfig $Record
        $trusting = [System.Collections.Generic.List[string]]::new()
        foreach ($site in @(@{ Label = 'app'; Rules = $config.ipSecurityRestrictions }, @{ Label = 'deployment site'; Rules = $config.scmIpSecurityRestrictions })) {
            foreach ($rule in @($site.Rules | Where-Object { $_ -and $_.action -eq 'Allow' -and $_.tag -eq 'ServiceTag' })) {
                $tags = @(([string]$rule.ipAddress -split ',') | ForEach-Object { $_.Trim() } | Where-Object { ($_ -split '\.')[0] -in $sharedServiceTags })
                if ($tags) { $trusting.Add("$($site.Label) rule $($rule.name): $($tags -join ', ')") }
            }
        }
        $evidence = [ordered]@{ rules = @($trusting | Sort-Object) }
        if ($trusting.Count) { return New-Fail "Access restrictions trust shared service tags: $($evidence.rules -join '; ')" $evidence }
        New-Pass 'No access restriction trusts a shared service tag' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-014'
    Title         = 'App Service authentication only accepts identities of the own tenant'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Medium'
    Description   = 'For apps with App Service authentication, finds a Microsoft Entra ID provider with a multi-tenant issuer (common, organizations or consumers) that does not limit the allowed groups or identities, and enabled social providers with a client id (Microsoft account, Facebook, Google, X, GitHub, Apple).'
    Rationale     = 'When the app requires authentication it trusts every identity its providers accept. A multi-tenant issuer accepts accounts of every Entra tenant and a social provider anyone who creates an account, so the requirement keeps nobody out and the app has to authorize every caller itself.'
    Remediation   = 'Use the issuer of your own tenant (https://login.microsoftonline.com/<tenant id>/v2.0) or allow only specific groups or identities, and remove the social providers the app does not need.'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-authentication-provider-aad', 'https://learn.microsoft.com/azure/app-service/overview-authentication-authorization')
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'App Service authentication settings could not be read' }
        $authentication = Get-SiteAuthentication $Record
        $settings = $authentication.Settings
        if (-not $settings.platform.enabled) { return New-NotApplicable 'App Service authentication is off' }
        if ($authentication.FromFile) { return New-Unknown 'App Service authentication is configured in a file inside the app, which the ingestion cannot read' }
        $providers = $settings.identityProviders
        $outside = [System.Collections.Generic.List[string]]::new()
        $configured = 0
        $entra = $providers.azureActiveDirectory
        $issuer = [string]$entra.registration.openIdIssuer
        $entraUsed = $entra -and $entra.enabled -ne $false -and $entra.registration.clientId
        if ($entraUsed) {
            $configured++
            $allowed = $entra.validation.defaultAuthorizationPolicy.allowedPrincipals
            $limited = [bool]@(@($allowed.groups) + @($allowed.identities) + @($entra.validation.jwtClaimChecks.allowedGroups) | Where-Object { $_ }).Count
            if ($issuer -match '/(common|organizations|consumers)(/|$)' -and -not $limited) { $outside.Add("Microsoft Entra ID with the multi-tenant issuer $issuer") }
        }
        foreach ($name in $socialProviders) {
            $provider = $providers.$name
            $registration = $provider.registration
            if ($provider -and $provider.enabled -ne $false -and ($registration.clientId -or $registration.appId -or $registration.consumerKey)) {
                $configured++
                $outside.Add("$name sign-in")
            }
        }
        $evidence = [ordered]@{ issuer = $issuer; acceptsOutsideTenant = @($outside | Sort-Object) }
        if ($outside.Count) { return New-Fail "Accepts identities outside the own tenant: $($evidence.acceptsOutsideTenant -join '; ')" $evidence }
        if (-not $configured) { return New-NotApplicable 'No identity provider is configured' $evidence }
        if ($entraUsed -and -not $issuer) { return New-Unknown 'The Microsoft Entra ID provider names no issuer, so the tenants it accepts are not known' $evidence }
        New-Pass 'Only accepts identities of its own tenant' $evidence
    }
}

function Test-FunctionSite {
    #true for a function app (also Logic App Standard) or a slot of one, by its own kind or that of its app
    param($Record)
    $kind = [string]$Record.resource.kind
    if (-not $kind -and $Record.type -eq 'Microsoft.Web/sites/slots' -and $Record.id -match '(?i)^(.+/providers/Microsoft\.Web/sites/[^/]+)/slots/') {
        $parent = Get-AzResourceRecord $Matches[1]
        if ($parent) { $kind = [string]$parent.resource.kind }
    }
    return $kind -match 'functionapp'
}

function Get-SitePlanTier {
    #pricing tier of the plan an app or slot runs on: the sku the site reports, else that of its plan; $null when unknown
    param($Record)
    if ($Record.resource.properties.sku) { return [string]$Record.resource.properties.sku }
    $planId = [string]$Record.resource.properties.serverFarmId
    if (-not $planId) { return $null }
    $plan = Get-AzResourceRecord $planId
    if ($plan) { return [string]$plan.resource.sku.tier }
    return $null
}

function Get-SiteOutboundRouting {
    #outbound routing through the virtual network integration: outboundVnetRouting in newer API versions, the vnet* flags in
    #older ones (allTraffic turns on every route, applicationTraffic is the former vnetRouteAllEnabled)
    param($Record)
    $p = $Record.resource.properties
    $routing = $p.outboundVnetRouting
    $config = Get-SiteConfig $Record
    $all = $routing.allTraffic -eq $true
    [pscustomobject]@{
        ApplicationRead = $null -ne $routing -or $null -ne $p.vnetRouteAllEnabled -or $null -ne $config.vnetRouteAllEnabled
        Application     = $all -or $routing.applicationTraffic -eq $true -or $p.vnetRouteAllEnabled -eq $true -or $config.vnetRouteAllEnabled -eq $true
        ConfigRead      = $null -ne $routing -or $null -ne $p.vnetImagePullEnabled -or $null -ne $p.vnetContentShareEnabled
        ImagePull       = $all -or $routing.imagePullTraffic -eq $true -or $p.vnetImagePullEnabled -eq $true
        ContentShare    = $all -or $routing.contentShareTraffic -eq $true -or $p.vnetContentShareEnabled -eq $true
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-016'
    Title         = 'App Service apps use HTTP 2.0'
    Category      = 'Posture and vulnerability management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = "Checks the 'HTTP version' setting (http20Enabled) of web apps, function apps and their deployment slots."
    Rationale     = 'HTTP 2.0 brings security and performance improvements over HTTP 1.1, such as header compression and multiplexed requests over one TLS connection.'
    Remediation   = 'Set the HTTP version to 2.0 (az webapp config set --http20-enabled true ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-common#configure-general-settings')
    Defender      = @{ '8d2253ca-6536-d471-25f3-36fdc3be945e' = "App Service apps should use latest 'HTTP Version'"; '5b1cff8c-61d7-905d-c159-ac194648fc16' = "App Service app slots should use latest 'HTTP Version'"; 'c2a4e670-a179-4c1b-bac0-e8729ac5d93b' = "Function apps should use latest 'HTTP Version'"; '89496206-66cf-ecc8-4bc5-0e115ac09462' = "Function app slots should use latest 'HTTP Version'" }
    Policy        = @{ '8c122334-9d20-4eb8-89ea-ac9a705b74ae' = "App Service apps should use latest 'HTTP Version'"; '4dcfb8b5-05cd-4090-a931-2ec29057e1fc' = "App Service app slots should use latest 'HTTP Version'"; 'e2c1c086-2d84-4019-bff3-c44ccd95113c' = "Function apps should use latest 'HTTP Version'"; 'fa98f1b1-1f56-4179-9faf-93ad82f3458f' = "Function app slots should use latest 'HTTP Version'" }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $config = Get-SiteConfig $Record
        if (-not $config) { return New-Unknown 'Site configuration could not be read' }
        $evidence = [ordered]@{ http20Enabled = $config.http20Enabled }
        if ($config.http20Enabled -eq $true) { return New-Pass 'HTTP 2.0 enabled' $evidence }
        New-Fail 'HTTP version 1.1' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-017'
    Title         = 'App Service apps use end-to-end TLS encryption'
    Category      = 'Data protection'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks the end-to-end TLS encryption setting (endToEndEncryptionEnabled) of web apps, function apps and their deployment slots.'
    Rationale     = 'Without it, TLS ends at the App Service front ends and requests travel unencrypted from the front ends to the workers that run the app.'
    Remediation   = 'Enable end-to-end TLS encryption (az resource update --set properties.endToEndEncryptionEnabled=true ... --resource-type Microsoft.Web/sites).'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-tls#end-to-end-tls-encryption')
    Policy        = @{ 'af1d7e88-c1c8-4ea8-be1f-87bff0df9101' = 'App Service apps should enable end to end encryption'; '123aed70-491a-4f07-a569-e1f3a8dd651e' = 'App Service app slots should enable end to end encryption'; '387140f1-6da9-4741-bcee-3b5edcdfd9ec' = 'Function apps should enable end to end encryption'; 'cbe0e5eb-fea9-491d-ab20-a62cf049c5ae' = 'Function app slots should enable end to end encryption' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.endToEndEncryptionEnabled
        $evidence = [ordered]@{ endToEndEncryptionEnabled = $value }
        if ($value -eq $true) { return New-Pass 'End-to-end TLS encryption enabled' $evidence }
        New-Fail 'Traffic from the front ends to the workers is not encrypted' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-018'
    Title         = 'App Service apps require incoming client certificates'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that incoming client certificates are enabled (clientCertEnabled) and required (clientCertMode Required) on web apps, function apps and their deployment slots. Apps that do not use client certificates fail as well.'
    Rationale     = 'With required client certificates only clients that present a valid certificate reach the app (mutual TLS); optional modes let clients without one through.'
    Remediation   = "Set 'Client certificate mode' to Required (az webapp update --set clientCertEnabled=true clientCertMode=Required ...), and validate the certificate in the app."
    References    = @('https://learn.microsoft.com/azure/app-service/app-service-web-configure-tls-mutual-auth')
    Defender      = @{ 'd468ae35-b97c-72d0-1f0c-f1797717e10b' = 'App Service apps should have Client Certificates (Incoming client certificates) enabled'; '7954a30c-7011-778a-d893-145fe2fb5e73' = 'App Service app slots should have Client Certificates (Incoming client certificates) enabled'; 'c2ab4bea-c663-3259-a4cd-03a8feb02825' = 'Function apps should have Client Certificates (Incoming client certificates) enabled' }
    Policy        = @{ '5c8eef54-2020-4bd6-921c-7470989dee37' = 'App Service apps should have Client Certificates (Incoming client certificates) enabled'; '4583ece0-19ca-441a-b37d-0c2ad8e0e693' = 'App Service app slots should have Client Certificates (Incoming client certificates) enabled'; '3978e137-4c94-4056-824c-c03c2616faad' = 'Function apps should have Client Certificates (Incoming client certificates) enabled'; 'f123aa67-1877-4e49-9aa6-33b38fa0bfe4' = 'Function app slots should have Client Certificates (Incoming client certificates) enabled' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ clientCertEnabled = $p.clientCertEnabled; clientCertMode = $p.clientCertMode }
        if ($p.clientCertEnabled -eq $true -and [string]$p.clientCertMode -eq 'Required') { return New-Pass 'Client certificates required' $evidence }
        if ($p.clientCertEnabled -eq $true) { return New-Fail "Client certificate mode $($p.clientCertMode)" $evidence }
        New-Fail 'Incoming client certificates are not enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-019'
    Title         = 'App Service authentication is enabled'
    Category      = 'Identity management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that App Service authentication (Easy Auth, platform.enabled in the authentication settings) is on for web apps, function apps and their deployment slots. Whether it turns unauthenticated requests away is AZ-APP-009, which identities it accepts AZ-APP-014.'
    Rationale     = 'App Service authentication signs users in with an identity provider before a request reaches the app, so an app without its own authentication is not open to anonymous callers.'
    Remediation   = 'Enable App Service authentication with Microsoft Entra ID (az webapp auth update --enabled true ...) and require authentication for unauthenticated requests.'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-authentication-authorization')
    Defender      = @{ 'a8e611c6-d894-6402-57f7-c69daad86acd' = 'App Service apps should have authentication enabled'; '815f8b16-543f-8b8b-3328-de8113c508ce' = 'Function apps should have authentication enabled' }
    Policy        = @{ '95bccee9-a7f8-4bec-9ee9-62c3473701fc' = 'App Service apps should have authentication enabled'; 'ae4cd8c5-2387-41af-9c0b-52992fc37c83' = 'App Service app slots should have authentication enabled'; 'c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8' = 'Function apps should have authentication enabled'; 'b95f146e-2721-4579-a04c-3852b66514bd' = 'Function app slots should have authentication enabled' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'App Service authentication settings could not be read' }
        $settings = (Get-Child $Record 'config/authsettingsV2').properties
        $evidence = [ordered]@{ enabled = $settings.platform.enabled; configFilePath = [bool]$settings.platform.configFilePath }
        if ($settings.platform.enabled -eq $true) { return New-Pass 'App Service authentication enabled' $evidence }
        New-Fail 'App Service authentication is off' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-020'
    Title         = 'App Service apps disable public network access'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that public network access is Disabled on web apps, function apps and their deployment slots (the site setting, or the site configuration when the site does not return it). Access restrictions do not count here; AZ-APP-008 accepts them.'
    Rationale     = 'With public network access disabled the app is only reachable through private endpoints, so it cannot be reached or attacked from the Internet at all.'
    Remediation   = 'Create a private endpoint for the app and set public network access to Disabled (az webapp update --set publicNetworkAccess=Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/networking-features')
    Policy        = @{ '1b5ef780-c53c-4a64-87f3-bb9c8c8094ba' = 'App Service apps should disable public network access'; '701a595d-38fb-4a66-ae6d-fb3735217622' = 'App Service app slots should disable public network access'; '969ac98b-88a8-449f-883c-2e9adb123127' = 'Function apps should disable public network access'; '11c82d0c-db9f-4d7b-97c5-f3f9aa957da2' = 'Function app slots should disable public network access' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $access = $Record.resource.properties.publicNetworkAccess
        if (-not $access) {
            if (-not (Test-ChildCollected $Record 'config/web')) { return New-Unknown 'The site does not return public network access and its configuration could not be read' }
            $access = (Get-SiteConfig $Record).publicNetworkAccess
        }
        $evidence = [ordered]@{ publicNetworkAccess = $access }
        if ($access -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($access) { $access } else { 'not set (enabled by default)' })" $evidence
    }
}

#App Service plan tiers and sizes that support private endpoints, as CIS lists them
$privateEndpointPlanTiers = @('Basic', 'Standard', 'ElasticPremium', 'Premium', 'PremiumV2', 'Premium0V3', 'PremiumV3', 'PremiumMV3', 'IsolatedV2', 'IsolatedMV2', 'WorkflowStandard', 'FlexConsumption')
$privateEndpointPlanSizes = @('B1', 'B2', 'B3', 'S1', 'S2', 'S3', 'EP1', 'EP2', 'EP3', 'P1', 'P2', 'P3', 'P1V2', 'P2V2', 'P3V2', 'P0V3', 'P1V3', 'P2V3', 'P3V3', 'P1MV3', 'P2MV3', 'P3MV3', 'P4MV3', 'P5MV3', 'I1V2', 'I2V2', 'I3V2', 'I4V2', 'I5V2', 'I6V2', 'I1MV2', 'I2MV2', 'I3MV2', 'I4MV2', 'I5MV2', 'WS1', 'WS2', 'WS3', 'FC1')
$webAppFilter = { param($Record) [string]$Record.resource.kind -notmatch 'functionapp' }

Add-AzTest @{
    Id            = 'AZ-APP-021'
    Title         = 'Web apps run on an App Service plan that supports private endpoints'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks the tier and size of the App Service plan of web apps against the plans that support private endpoints (Basic and higher). Function apps are not evaluated.'
    Rationale     = 'Free and Shared plans cannot have private endpoints, so the app can only be reached over its public endpoint.'
    Remediation   = 'Move the app to a plan of the Basic tier or higher, such as Premium v3 (az appservice plan update --sku P1V3 ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/networking/private-endpoint')
    Policy        = @{ '546fe8d2-368d-4029-a418-6af48a7f61e5' = 'App Service apps should use a SKU that supports private link' }
    ResourceTypes = @('Microsoft.Web/sites')
    Filter        = $webAppFilter
    Evaluate      = {
        param($Record)
        $planId = [string]$Record.resource.properties.serverFarmId
        if (-not $planId) { return New-Unknown 'The app names no App Service plan' }
        $plan = Get-AzResourceRecord $planId
        if (-not $plan) { return New-Unknown 'The App Service plan of the app was not read' ([ordered]@{ plan = $planId }) }
        $evidence = [ordered]@{ plan = $plan.resource.name; tier = $plan.resource.sku.tier; size = $plan.resource.sku.name }
        if ([string]$plan.resource.sku.tier -in $privateEndpointPlanTiers -and [string]$plan.resource.sku.name -in $privateEndpointPlanSizes) { return New-Pass "Plan $($plan.resource.sku.name) ($($plan.resource.sku.tier)) supports private endpoints" $evidence }
        New-Fail "Plan $($plan.resource.sku.name) ($($plan.resource.sku.tier)) does not support private endpoints" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-022'
    Title         = 'Web apps are accessed through a private endpoint'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that web apps have at least one approved private endpoint connection. Function apps are not evaluated.'
    Rationale     = 'A private endpoint gives the app an address in your virtual network, so clients reach it without crossing the Internet and public access can be turned off.'
    Remediation   = 'Create a private endpoint for the app in a virtual network (az network private-endpoint create --group-id sites ...) with a private DNS zone.'
    References    = @('https://learn.microsoft.com/azure/app-service/networking/private-endpoint')
    Policy        = @{ '687aa49d-0982-40f8-bf6b-66d1da97a04b' = 'App Service apps should use private link' }
    ResourceTypes = @('Microsoft.Web/sites')
    Filter        = $webAppFilter
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'privateEndpointConnections')) { return New-Unknown 'Private endpoint connections could not be read' }
        $connections = @(Get-Child $Record 'privateEndpointConnections' | Where-Object { $_ })
        $approved = @($connections | Where-Object { [string]$_.properties.privateLinkServiceConnectionState.status -eq 'Approved' })
        $evidence = [ordered]@{ privateEndpointConnections = $connections.Count; approved = $approved.Count }
        if ($approved.Count) { return New-Pass "$($approved.Count) approved private endpoint connection(s)" $evidence }
        New-Fail 'No approved private endpoint connection' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-023'
    Title         = 'App Service apps are integrated with a virtual network'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Checks that web apps, function apps and their deployment slots have regional virtual network integration (virtualNetworkSubnetId). Function apps on the Consumption plan, which does not support it, are not applicable; gateway-required integration does not count.'
    Rationale     = 'Virtual network integration lets the app reach resources over private addresses and subjects its outbound traffic to network security groups, route tables and firewalls.'
    Remediation   = 'Integrate the app with a delegated subnet (az webapp vnet-integration add --vnet <vnet> --subnet <subnet> ...).'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-vnet-integration')
    Defender      = @{ '286ae383-1dd6-578a-f42d-ee4ce88610f8' = 'App Service apps should be injected into a virtual network'; '4166945a-0127-1f05-9249-1d656e48697c' = 'App Service app slots should be injected into a virtual network' }
    Policy        = @{ '72d04c29-f87d-4575-9731-419ff16a2757' = 'App Service apps should be injected into a virtual network'; '24b7a1c6-44fe-40cc-a2e6-242d2ef70e98' = 'App Service app slots should be injected into a virtual network' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        $subnet = [string]$Record.resource.properties.virtualNetworkSubnetId
        $evidence = [ordered]@{ virtualNetworkSubnetId = $subnet }
        if ($subnet) { return New-Pass "Integrated with subnet $(($subnet -split '/')[-1]) of $(($subnet -split '/')[-3])" $evidence }
        if (Test-FunctionSite $Record) {
            $tier = Get-SitePlanTier $Record
            $evidence.planTier = $tier
            if ($tier -eq 'Dynamic') { return New-NotApplicable 'The Consumption plan does not support virtual network integration' $evidence }
            if (-not $tier) { return New-Unknown 'No virtual network integration, and the plan of the function app is not known' $evidence }
        }
        New-Fail 'No regional virtual network integration' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-024'
    Title         = 'App Service configuration traffic is routed through the virtual network'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'For web apps, function apps and their deployment slots with virtual network integration, checks that container image pulls and content share access are routed through the virtual network (vnetImagePullEnabled and vnetContentShareEnabled, or the imagePullTraffic and contentShareTraffic routes of outboundVnetRouting).'
    Rationale     = 'Without it the app pulls its container image and reaches its content share over the public route, so the storage account and registry have to stay reachable from the Internet.'
    Remediation   = 'Route image pulls and content share traffic through the integration (az resource update --set properties.outboundVnetRouting.imagePullTraffic=true properties.outboundVnetRouting.contentShareTraffic=true ... --resource-type Microsoft.Web/sites).'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-vnet-integration-routing#configuration-routing')
    Policy        = @{ '801543d1-1953-4a90-b8b0-8cf6d41473a5' = 'App Service apps should enable configuration routing to Azure Virtual Network'; '5747353b-1ca9-42c1-a4dd-b874b894f3d4' = 'App Service app slots should enable configuration routing to Azure Virtual Network'; '5e57f5ad-995a-485b-9f42-4748935ee5d9' = 'Function apps should enable configuration routing to Azure Virtual Network'; 'f380edf5-de79-4862-bd57-ee407d8bd8b6' = 'Function app slots should enable configuration routing to Azure Virtual Network' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not $Record.resource.properties.virtualNetworkSubnetId) { return New-NotApplicable 'No virtual network integration (AZ-APP-023)' }
        $routing = Get-SiteOutboundRouting $Record
        $evidence = [ordered]@{ imagePull = $routing.ImagePull; contentShare = $routing.ContentShare }
        if (-not $routing.ConfigRead) { return New-Unknown 'The configuration routing settings are not in the resource' }
        if ($routing.ImagePull -and $routing.ContentShare) { return New-Pass 'Image pulls and content share traffic use the virtual network' $evidence }
        $public = @()
        if (-not $routing.ImagePull) { $public += 'image pulls' }
        if (-not $routing.ContentShare) { $public += 'content share' }
        New-Fail "Over the public route: $($public -join ', ')" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-025'
    Title         = 'App Service outbound traffic is routed through the virtual network'
    Category      = 'Network security'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'For web apps, function apps and their deployment slots with virtual network integration, checks that all outbound application traffic is routed through the virtual network (vnetRouteAllEnabled, or the allTraffic or applicationTraffic route of outboundVnetRouting).'
    Rationale     = 'Otherwise only traffic to private addresses uses the integration; traffic to the Internet bypasses the network security groups, route tables and firewall of the virtual network.'
    Remediation   = 'Route all outbound traffic through the integration (az webapp config set --vnet-route-all-enabled true ..., or outboundVnetRouting.applicationTraffic=true).'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-vnet-integration-routing#configure-application-routing')
    Policy        = @{ 'a691eacb-474d-47e4-b287-b4813ca44222' = 'App Service apps should enable outbound application traffic routing to Azure Virtual Network'; 'f5c0bfb3-acea-47b1-b477-b0edcdf6edc1' = 'App Service app slots should enable outbound application traffic routing to Azure Virtual Network'; '32a913ec-5ed7-4b31-a5b0-198450d8fb13' = 'Function apps should enable outbound application traffic routing to Azure Virtual Network'; '75c42c42-dfb3-453d-8fd5-9f978e1b1106' = 'Function app slots should enable outbound application traffic routing to Azure Virtual Network' }
    ResourceTypes = $siteTypes
    Evaluate      = {
        param($Record)
        if (-not $Record.resource.properties.virtualNetworkSubnetId) { return New-NotApplicable 'No virtual network integration (AZ-APP-023)' }
        $routing = Get-SiteOutboundRouting $Record
        $evidence = [ordered]@{ routeAll = $routing.Application }
        if (-not $routing.ApplicationRead) { return New-Unknown 'The application routing setting is not in the resource' }
        if ($routing.Application) { return New-Pass 'All outbound traffic uses the virtual network' $evidence }
        New-Fail 'Only traffic to private addresses uses the virtual network' $evidence
    }
}

#App Service Environments
function Get-AseClusterSetting {
    #value of a cluster setting of an App Service Environment, whatever the casing of its name; $null when not set
    param($Record, [string]$Name)
    $setting = @($Record.resource.properties.clusterSettings | Where-Object { $_ -and [string]$_.name -eq $Name }) | Select-Object -First 1
    if ($setting) { return [string]$setting.value }
    return $null
}

$aseType = @('Microsoft.Web/hostingEnvironments')
#the cipher suite order CIS prescribes for the front ends
$aseCipherSuiteOrder = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'

Add-AzTest @{
    Id            = 'AZ-APP-026'
    Title         = 'App Service Environments use an internal load balancer'
    Category      = 'Network security'
    Service       = 'App Service Environment'
    Severity      = 'Medium'
    Description   = 'Checks that the virtual IP of App Service Environments is internal (internalLoadBalancingMode other than None).'
    Rationale     = 'An External App Service Environment publishes every app on a public address; with an internal load balancer the apps are only reachable from the virtual network.'
    Remediation   = 'Deploy a new App Service Environment with an internal virtual IP and move the apps to it; publish public apps through Application Gateway or Front Door with WAF.'
    References    = @('https://learn.microsoft.com/azure/app-service/environment/networking')
    Policy        = @{ '2d048aca-6479-4923-88f5-e2ac295d9af3' = 'App Service Environment apps should not be reachable over public internet' }
    ResourceTypes = $aseType
    Evaluate      = {
        param($Record)
        $mode = $Record.resource.properties.internalLoadBalancingMode
        $evidence = [ordered]@{ internalLoadBalancingMode = $mode }
        if ($null -eq $mode -or [string]$mode -eq '') { return New-Unknown 'The load balancing mode is not in the resource' $evidence }
        if ([string]$mode -ne 'None') { return New-Pass "Internal load balancer ($mode)" $evidence }
        New-Fail 'External virtual IP' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-027'
    Title         = 'App Service Environments are version 3 or higher'
    Category      = 'Posture and vulnerability management'
    Service       = 'App Service Environment'
    Severity      = 'High'
    Description   = 'Checks the version (kind) of App Service Environments.'
    Rationale     = 'App Service Environment v1 and v2 were retired on 31 August 2024 and no longer receive security updates or support.'
    Remediation   = 'Migrate to App Service Environment v3 (in-place or side-by-side migration).'
    References    = @('https://learn.microsoft.com/azure/app-service/environment/migration-alternatives')
    ResourceTypes = $aseType
    Evaluate      = {
        param($Record)
        $kind = [string]$Record.resource.kind
        $evidence = [ordered]@{ kind = $kind }
        if ($kind -match '(?i)^ASEV(\d+)$') {
            if ([int]$Matches[1] -ge 3) { return New-Pass "App Service Environment $kind" $evidence }
            return New-Fail "Retired App Service Environment $kind" $evidence
        }
        New-Unknown 'The version is not in the resource' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-028'
    Title         = 'App Service Environments encrypt internal traffic'
    Category      = 'Data protection'
    Service       = 'App Service Environment'
    Severity      = 'Low'
    Description   = "Checks the InternalEncryption cluster setting of App Service Environments for the value 'true'."
    Rationale     = 'Internal encryption encrypts the traffic between the front ends and workers and the page files and disks inside the environment, which are otherwise unencrypted.'
    Remediation   = "Set the cluster setting InternalEncryption to 'true' (Configuration, Internal encryption)."
    References    = @('https://learn.microsoft.com/azure/app-service/environment/app-service-app-service-environment-custom-settings')
    Defender      = @{ '623689e0-47c5-73a9-0c6a-f334928d0b3e' = 'App Service Environment should have internal encryption enabled' }
    Policy        = @{ 'fb74e86f-d351-4b8d-b034-93da7391c01f' = 'App Service Environment should have internal encryption enabled' }
    ResourceTypes = $aseType
    Evaluate      = {
        param($Record)
        $value = Get-AseClusterSetting $Record 'InternalEncryption'
        $evidence = [ordered]@{ InternalEncryption = $value }
        if ($value -eq 'true') { return New-Pass 'Internal encryption enabled' $evidence }
        New-Fail 'Internal encryption not enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-029'
    Title         = 'App Service Environments disable TLS 1.0 and 1.1'
    Category      = 'Data protection'
    Service       = 'App Service Environment'
    Severity      = 'Medium'
    Description   = "Checks the DisableTls1.0 cluster setting of App Service Environments for the value '1'."
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses; by default the front ends of an App Service Environment accept them for every app.'
    Remediation   = "Set the cluster setting DisableTls1.0 to '1' (Configuration, Allow TLS 1.0 and 1.1 Off)."
    References    = @('https://learn.microsoft.com/azure/app-service/environment/app-service-app-service-environment-custom-settings')
    Policy        = @{ 'd6545c6b-dd9d-4265-91e6-0b451e2f1c50' = 'App Service Environment should have TLS 1.0 and 1.1 disabled' }
    ResourceTypes = $aseType
    Evaluate      = {
        param($Record)
        $value = Get-AseClusterSetting $Record 'DisableTls1.0'
        $evidence = [ordered]@{ 'DisableTls1.0' = $value }
        if ($value -eq '1') { return New-Pass 'TLS 1.0 and 1.1 disabled' $evidence }
        New-Fail 'TLS 1.0 and 1.1 allowed' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-APP-030'
    Title         = 'App Service Environments set the TLS cipher suite order'
    Category      = 'Data protection'
    Service       = 'App Service Environment'
    Severity      = 'Low'
    Description   = "Checks the FrontEndSSLCipherSuiteOrder cluster setting of App Service Environments for the order $aseCipherSuiteOrder."
    Rationale     = 'Without a configured order the front ends negotiate weaker cipher suites that clients offer; this order only allows TLS 1.3 and ECDHE AES-GCM suites.'
    Remediation   = "Set the cluster setting FrontEndSSLCipherSuiteOrder to $aseCipherSuiteOrder (Resource Explorer or az resource update)."
    References    = @('https://learn.microsoft.com/azure/app-service/environment/app-service-app-service-environment-custom-settings')
    Policy        = @{ '817dcf37-e83d-4999-a472-644eada2ea1e' = 'App Service Environment should be configured with strongest TLS Cipher suites' }
    ResourceTypes = $aseType
    Evaluate      = {
        param($Record)
        $value = Get-AseClusterSetting $Record 'FrontEndSSLCipherSuiteOrder'
        $evidence = [ordered]@{ FrontEndSSLCipherSuiteOrder = $value }
        if ($value -and $value.Replace(' ', '') -eq $aseCipherSuiteOrder) { return New-Pass 'Cipher suite order configured' $evidence }
        New-Fail $(if ($value) { 'Another cipher suite order is configured' } else { 'No cipher suite order configured' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-FUNC-001'
    Version       = 2
    Title         = 'Only those who can change a function app can change the storage it runs from'
    Category      = 'Privileged access'
    Service       = 'Azure Functions'
    Severity      = 'High'
    Description   = 'Finds the storage account a function app or Logic App (Standard) app runs from (the deployment container of a Flex Consumption app, or the content share named after the app) and lists the principals, other than the identities of the app itself, that can list its keys or write its blobs or files without being able to change the app. Role assignments are compared per assigned principal. The storage of apps on dedicated plans cannot be found without the app settings and is reported as unknown.'
    Rationale     = 'The storage account holds the code package or content share (for a Logic App (Standard) app, the workflow definitions) and the function keys. Whoever can write there can replace the code or a workflow and run it as the app, with its managed identity and keys, which turns storage rights into the rights of the function (Orca Security, 2023; NetSPI).'
    Remediation   = 'Take storage write and key rights away from principals that should not control the function, give the app a storage account of its own in its own resource group with the same owners, and disable shared key access (AZ-STG-005).'
    References    = @('https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/', 'https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-function-apps/', 'https://learn.microsoft.com/azure/azure-functions/storage-considerations')
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions')
    ResourceTypes = @('Microsoft.Web/sites')
    Filter        = $functionAppFilter
    Evaluate      = {
        param($Record)
        $hosts = @(Get-FunctionHostStorage $Record)
        if (-not $hosts) { return New-Unknown 'The storage account the app runs from cannot be identified without its app settings' }
        $own = @(Get-ResourceIdentityPrincipals $Record)
        $roles = Get-RoleDefinitionMap
        $assignments = @(Get-ActiveRoleAssignments)
        $appWriters = @{}
        foreach ($assignment in $assignments) {
            if (-not (Test-ScopeCovers $assignment.properties.scope @($Record.id.ToLowerInvariant()))) { continue }
            $definition = $roles[(Get-RoleDefinitionGuid $assignment.properties.roleDefinitionId)]
            if (-not $definition -or (Test-RoleGrantsAction $definition 'Microsoft.Web/sites/write')) { $appWriters[([string]$assignment.properties.principalId).ToLowerInvariant()] = $true }
        }
        $takeover = [System.Collections.Generic.List[string]]::new()
        foreach ($storage in $hosts) {
            foreach ($assignment in $assignments) {
                $principal = ([string]$assignment.properties.principalId).ToLowerInvariant()
                if ($principal -in $own -or $appWriters.ContainsKey($principal)) { continue }
                if (-not (Test-ScopeCovers $assignment.properties.scope @($storage.Record.id.ToLowerInvariant()))) { continue }
                $definition = $roles[(Get-RoleDefinitionGuid $assignment.properties.roleDefinitionId)]
                $grants = -not $definition -or (Test-RoleGrantsAction $definition 'Microsoft.Storage/storageAccounts/listKeys/action') -or (Test-RoleGrantsDataAction $definition 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write') -or (Test-RoleGrantsDataAction $definition 'Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write')
                if ($grants) { $takeover.Add("$(Get-PrincipalLabel $assignment.properties.principalId): $(Get-RoleName $assignment.properties.roleDefinitionId) on $(Get-ScopeLabel $assignment.properties.scope) ($($storage.Record.resource.name))") }
            }
        }
        $evidence = [ordered]@{
            hostStorage     = @($hosts | ForEach-Object { "$($_.Record.resource.name) ($($_.Via))" } | Sort-Object)
            sharedKeyAccess = @($hosts | ForEach-Object { "$($_.Record.resource.name): $(if ($_.Record.resource.properties.allowSharedKeyAccess -eq $false) { 'disabled' } else { 'allowed' })" } | Sort-Object)
            takeover        = @($takeover | Sort-Object -Unique)
        }
        if ($evidence.takeover) { return New-Fail "Can take the app over through its storage: $($evidence.takeover -join '; ')" $evidence }
        New-Pass 'Only principals that can change the app can change its storage' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-FUNC-002'
    Title         = 'Flex Consumption apps read their deployment package with a managed identity'
    Category      = 'Identity management'
    Service       = 'Azure Functions'
    Severity      = 'Medium'
    Description   = 'Checks how Flex Consumption apps authenticate to the storage container that holds their deployment package: with a system or user assigned managed identity, or with a storage connection string in an app setting.'
    Rationale     = 'The connection string holds a key of the storage account, which gives full access to it. Everyone who can read the app settings, or finds the key elsewhere, can replace the package and run code as the app, and the key keeps shared key access on the storage account necessary.'
    Remediation   = 'Set the deployment storage authentication to the managed identity of the app, grant it Storage Blob Data Owner on the storage account (or Contributor on the container), remove the connection string app setting and disable shared key access on the storage account (AZ-STG-005).'
    References    = @('https://learn.microsoft.com/azure/azure-functions/flex-consumption-how-to', 'https://learn.microsoft.com/azure/azure-functions/flex-consumption-plan')
    ResourceTypes = @('Microsoft.Web/sites')
    Filter        = { param($Record) $null -ne $Record.resource.properties.functionAppConfig.deployment.storage }
    Evaluate      = {
        param($Record)
        $storage = $Record.resource.properties.functionAppConfig.deployment.storage
        $type = [string]$storage.authentication.type
        $evidence = [ordered]@{ deploymentStorage = ([string]$storage.value -replace '\?.*$', ''); authenticationType = $type }
        if ($type -in 'SystemAssignedIdentity', 'UserAssignedIdentity') { return New-Pass "Reads its deployment package with a managed identity ($type)" $evidence }
        if ($type -eq 'StorageAccountConnectionString') { return New-Fail 'Reads its deployment package with a storage account connection string (key)' $evidence }
        New-Fail "Reads its deployment package with authentication type '$type'" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-FUNC-003'
    Version       = 2
    Title         = 'Functions that anyone can call have no write access in Azure'
    Category      = 'Privileged access'
    Service       = 'Azure Functions'
    Severity      = 'High'
    Description   = 'For function apps that accept connections from any network (AZ-APP-008) and have anonymous HTTP functions that App Service authentication does not protect (AZ-APP-009), lists the write capable role assignments of the system and user assigned managed identities of the app, including assignments through groups whose members were collected.'
    Rationale     = 'The caller decides the input of the function, and the function acts on it with the rights of its managed identity. Unless the code authorizes every caller correctly, anyone on the Internet can use those rights, without an account, MFA or Conditional Access, and the activity log names the managed identity instead of the caller.'
    Remediation   = 'Protect the functions (App Service authentication that turns unauthenticated requests away, keys or network restrictions), or take the write access away from the identity and leave the privileged work to a function that is not publicly callable.'
    References    = @('https://learn.microsoft.com/azure/azure-functions/security-concepts', 'https://learn.microsoft.com/azure/app-service/overview-managed-identity')
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions')
    ResourceTypes = $siteTypes
    Filter        = $functionsOnlyFilter
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web') -or -not (Test-ChildCollected $Record 'functions') -or -not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'The site configuration, functions or authentication settings could not be read' }
        $authentication = Get-SiteAuthentication $Record
        $open = @(Get-SiteHttpFunctions $Record $authentication | Where-Object { $_.AuthLevel -eq 'anonymous' -and -not $_.Protected } | ForEach-Object { $_.Name } | Sort-Object)
        if (-not $open -or -not (Test-SiteOpenToAnyNetwork $Record)) { return New-NotApplicable 'No anonymous function that anyone can reach (AZ-APP-008, AZ-APP-009)' }
        if ($authentication.FromFile) { return New-Unknown 'App Service authentication is configured in a file inside the app, which the ingestion cannot read' }
        $evidence = [ordered]@{ anonymousFunctions = $open; identityType = $Record.resource.identity.type; writeAssignments = @() }
        $principals = @(Get-ResourceIdentityPrincipals $Record)
        if (-not $principals) { return New-Pass 'Anyone can call it, but the app has no managed identity' $evidence }
        $evidence.writeAssignments = @(Get-PrincipalWriteGrants $principals)
        if ($evidence.writeAssignments) { return New-Fail "Anyone can call $($open -join ', '), and the app acts with $($evidence.writeAssignments -join '; ')" $evidence }
        New-Pass 'Anyone can call it, but its managed identity has no write access' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-FUNC-004'
    Title         = 'HTTP functions do not rely on function keys alone'
    Category      = 'Identity management'
    Service       = 'Azure Functions'
    Severity      = 'Medium'
    Description   = 'For function apps that accept connections from any network (AZ-APP-008), finds HTTP triggered functions with a key auth level (function or admin; function when not set) that App Service authentication does not protect. Anonymous functions are AZ-APP-009.'
    Rationale     = 'A function key is a static secret, sent in the URL or a header, that works from any address and is not tied to an identity. It ends up in callers, scripts and logs, is readable by everyone who can list the keys of the app or read its storage, and stays valid until it is rotated.'
    Remediation   = 'Limit inbound access (access restrictions, a private endpoint, or a gateway in front that authenticates callers), or require App Service authentication with Microsoft Entra ID for these routes, and rotate the keys.'
    References    = @('https://learn.microsoft.com/azure/azure-functions/function-keys-how-to', 'https://learn.microsoft.com/azure/azure-functions/security-concepts')
    ResourceTypes = $siteTypes
    Filter        = $functionsOnlyFilter
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'config/web') -or -not (Test-ChildCollected $Record 'functions') -or -not (Test-ChildCollected $Record 'config/authsettingsV2')) { return New-Unknown 'The site configuration, functions or authentication settings could not be read' }
        $authentication = Get-SiteAuthentication $Record
        $keyed = @(Get-SiteHttpFunctions $Record $authentication | Where-Object { $_.AuthLevel -in 'function', 'admin' })
        $evidence = [ordered]@{ keyFunctions = @($keyed | ForEach-Object { $_.Name } | Sort-Object); keyOnly = @() }
        if (-not $keyed) { return New-NotApplicable 'No key protected HTTP functions' $evidence }
        if (-not (Test-SiteOpenToAnyNetwork $Record)) { return New-Pass 'Network access to the app is restricted' $evidence }
        $evidence.keyOnly = @($keyed | Where-Object { -not $_.Protected } | ForEach-Object { $_.Name } | Sort-Object)
        if ($evidence.keyOnly -and $authentication.FromFile) { return New-Unknown 'App Service authentication is configured in a file inside the app, which the ingestion cannot read' $evidence }
        if ($evidence.keyOnly) { return New-Fail "Reachable from any network with only a function key: $($evidence.keyOnly -join ', ')" $evidence }
        New-Pass 'App Service authentication protects the key protected functions' $evidence
    }
}
