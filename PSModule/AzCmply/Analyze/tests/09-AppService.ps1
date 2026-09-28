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

Add-AzTest @{
    Id            = 'AZ-FUNC-001'
    Title         = 'Only those who can change a function app can change the storage it runs from'
    Category      = 'Privileged access'
    Service       = 'Azure Functions'
    Severity      = 'High'
    Description   = 'Finds the storage account a function app runs from (the deployment container of a Flex Consumption app, or the content share named after the app) and lists the principals, other than the identities of the app itself, that can list its keys or write its blobs or files without being able to change the app. Role assignments are compared per assigned principal. The storage of apps on dedicated plans cannot be found without the app settings and is reported as unknown.'
    Rationale     = 'The storage account holds the code package or content share and the function keys. Whoever can write there can replace the code and run it as the app, with its managed identity and keys, which turns storage rights into the rights of the function (Orca Security, 2023; NetSPI).'
    Remediation   = 'Take storage write and key rights away from principals that should not control the function, give the app a storage account of its own in its own resource group with the same owners, and disable shared key access (AZ-STG-005).'
    References    = @('https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/', 'https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-function-apps/', 'https://learn.microsoft.com/azure/azure-functions/storage-considerations')
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions')
    ResourceTypes = @('Microsoft.Web/sites')
    Filter        = $functionsOnlyFilter
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
