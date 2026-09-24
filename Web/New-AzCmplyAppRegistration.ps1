#Requires -Version 7.2
<#
    .SYNOPSIS
    Creates (or updates) the Entra ID app registration the AzCmply web page signs in with.
    .DESCRIPTION
    The web page runs in the browser and signs in as the user, so it needs an app registration of the single-page
    application type with these delegated, read-only permissions:
    - Azure Service Management: user_impersonation (reads the subscription with the user's own Azure RBAC, Reader is enough)
    - Microsoft Graph: User.Read, Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All, Policy.Read.All (Entra ID checks)
    The app has no secret and no application permissions: it can never do more than the signed in user.

    Run once per tenant for your own app (single tenant), or once by the publisher for a multi-tenant app that other
    tenants consent to. Running it again with the same display name updates the redirect URIs and permissions instead of
    creating a second app. Sign-in uses a device code with the Microsoft Graph Command Line Tools app; the account needs
    to be allowed to create app registrations (Application Developer or higher).
    .PARAMETER RedirectUri
    Address(es) the page is served from, registered as single-page application redirect URIs.
    Default http://localhost:8400/ (Start-AzCmplyWeb.ps1).
    .PARAMETER DisplayName
    Name of the app registration. Default 'AzCmply'.
    .PARAMETER MultiTenant
    Lets accounts of other tenants sign in (after an administrator of that tenant consents).
    .PARAMETER GrantAdminConsent
    Also grants the permissions for every user of this tenant, so nobody sees a consent prompt. Needs a Global
    Administrator or Privileged Role Administrator.
    .PARAMETER TenantId
    Tenant to create the app in. Default: the home tenant of the account you sign in with.
    .PARAMETER Environment
    Azure cloud. Default AzureCloud.
    .EXAMPLE
    .\New-AzCmplyAppRegistration.ps1 -GrantAdminConsent
    .EXAMPLE
    .\New-AzCmplyAppRegistration.ps1 -RedirectUri 'https://azcmply.contoso.com/' -GrantAdminConsent
    .EXAMPLE
    .\New-AzCmplyAppRegistration.ps1 -DisplayName 'AzCmply (JSolve)' -MultiTenant -RedirectUri 'https://azcmply.jsolve.nl/'
    .NOTES
    Author: Jos Lieben / JSolve B.V.
    Website: https://www.lieben.nu
    Free for non-commercial use. Commercial use requires a license:
    https://jsolve.nl/commercial-use.html
#>
[CmdletBinding()]
Param(
    [ValidatePattern('^https://|^http://localhost(:\d+)?/')][string[]]$RedirectUri = @('http://localhost:8400/'),
    [string]$DisplayName = 'AzCmply',
    [switch]$MultiTenant,
    [switch]$GrantAdminConsent,
    [string]$TenantId = 'organizations',
    [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud')][string]$Environment = 'AzureCloud'
)

$ErrorActionPreference = 'Stop'
$cloud = @{
    AzureCloud        = @{ Login = 'https://login.microsoftonline.com'; Graph = 'https://graph.microsoft.com' }
    AzureUSGovernment = @{ Login = 'https://login.microsoftonline.us'; Graph = 'https://graph.microsoft.us' }
    AzureChinaCloud   = @{ Login = 'https://login.chinacloudapi.cn'; Graph = 'https://microsoftgraph.chinacloudapi.cn' }
}[$Environment]
$graphCliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$graphAppId = '00000003-0000-0000-c000-000000000000'
$armAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
$graphScopes = @('User.Read', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Policy.Read.All')
$armScopes = @('user_impersonation')

#region sign-in (device code)

$scope = "$($cloud.Graph)/Application.ReadWrite.All"
if ($GrantAdminConsent) { $scope += " $($cloud.Graph)/DelegatedPermissionGrant.ReadWrite.All" }
$device = Invoke-RestMethod -Method POST -Uri "$($cloud.Login)/$TenantId/oauth2/v2.0/devicecode" -Body @{ client_id = $graphCliAppId; scope = $scope }
Write-Host $device.message -ForegroundColor Cyan
$deadline = [DateTime]::UtcNow.AddSeconds([int]$device.expires_in)
$token = $null
while (-not $token -and [DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Seconds ([int]$device.interval)
    try {
        $token = (Invoke-RestMethod -Method POST -Uri "$($cloud.Login)/$TenantId/oauth2/v2.0/token" -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $graphCliAppId
                device_code = $device.device_code
            }).access_token
    } catch {
        $problem = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($problem.error -notin 'authorization_pending', 'slow_down') { throw "Sign-in failed: $($problem.error_description ?? $_.Exception.Message)" }
    }
}
if (-not $token) { throw 'The device code expired before the sign-in completed.' }
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

function Invoke-Graph {
    param([string]$Method = 'GET', [string]$Path, $Body)
    $request = @{ Method = $Method; Uri = "$($cloud.Graph)/v1.0$Path"; Headers = $headers }
    if ($null -ne $Body) { $request.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    try { return Invoke-RestMethod @request }
    catch {
        $detail = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
        throw "$Method $Path failed: $($detail ?? $_.Exception.Message)"
    }
}

#endregion

#region permissions

function Get-ScopeAccess {
    #delegated permission ids of an API, looked up by name so no id is hard coded
    param([string]$AppId, [string[]]$Names)
    $servicePrincipal = Invoke-Graph -Path "/servicePrincipals(appId='$AppId')?`$select=id,displayName,oauth2PermissionScopes"
    $access = foreach ($name in $Names) {
        $permission = $servicePrincipal.oauth2PermissionScopes | Where-Object value -eq $name
        if (-not $permission) { throw "$($servicePrincipal.displayName) has no delegated permission '$name'" }
        [ordered]@{ id = $permission.id; type = 'Scope' }
    }
    return [pscustomobject]@{ ServicePrincipalId = $servicePrincipal.id; Resource = [ordered]@{ resourceAppId = $AppId; resourceAccess = @($access) } }
}

$graph = Get-ScopeAccess -AppId $graphAppId -Names $graphScopes
$arm = Get-ScopeAccess -AppId $armAppId -Names $armScopes

#endregion

#region app registration

$audience = if ($MultiTenant) { 'AzureADMultipleOrgs' } else { 'AzureADMyOrg' }
$filter = [uri]::EscapeDataString("displayName eq '$($DisplayName.Replace("'", "''"))'")
$existing = @((Invoke-Graph -Path "/applications?`$filter=$filter&`$select=id,appId,displayName,spa,requiredResourceAccess,signInAudience").value)
if ($existing.Count -gt 1) { throw "There are $($existing.Count) app registrations named '$DisplayName'; pass a unique -DisplayName." }
if ($existing.Count -eq 1) {
    $app = $existing[0]
    $uris = @(@($app.spa.redirectUris) + $RedirectUri | Where-Object { $_ } | Sort-Object -Unique)
    #keep permissions of other APIs, replace the entries for Graph and ARM with the required ones
    $access = @(@($app.requiredResourceAccess | Where-Object { $_.resourceAppId -notin $graphAppId, $armAppId }) + $graph.Resource + $arm.Resource)
    Invoke-Graph -Method PATCH -Path "/applications/$($app.id)" -Body @{ signInAudience = $audience; spa = @{ redirectUris = $uris }; requiredResourceAccess = $access } | Out-Null
    Write-Host "Updated app registration '$DisplayName' ($($app.appId))"
} else {
    $app = Invoke-Graph -Method POST -Path '/applications' -Body @{
        displayName            = $DisplayName
        signInAudience         = $audience
        spa                    = @{ redirectUris = @($RedirectUri) }
        requiredResourceAccess = @($graph.Resource, $arm.Resource)
        notes                  = 'AzCmply web: read only security assessment of Azure subscriptions, signed in as the user. Delegated permissions only, no secrets.'
    }
    Write-Host "Created app registration '$DisplayName' ($($app.appId))"
}

#the enterprise application (service principal) of the app in this tenant; new apps take a moment to replicate
$servicePrincipal = $null
for ($attempt = 1; -not $servicePrincipal -and $attempt -le 10; $attempt++) {
    $found = @((Invoke-Graph -Path "/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id").value)
    if ($found.Count) { $servicePrincipal = $found[0]; break }
    try { $servicePrincipal = Invoke-Graph -Method POST -Path '/servicePrincipals' -Body @{ appId = $app.appId } }
    catch { if ($attempt -eq 10) { throw }; Start-Sleep -Seconds 3 }
}

if ($GrantAdminConsent) {
    foreach ($grant in @(@{ Resource = $graph.ServicePrincipalId; Scope = $graphScopes -join ' ' }, @{ Resource = $arm.ServicePrincipalId; Scope = $armScopes -join ' ' })) {
        $current = @((Invoke-Graph -Path "/oauth2PermissionGrants?`$filter=clientId eq '$($servicePrincipal.id)' and resourceId eq '$($grant.Resource)' and consentType eq 'AllPrincipals'").value)
        if ($current.Count) {
            Invoke-Graph -Method PATCH -Path "/oauth2PermissionGrants/$($current[0].id)" -Body @{ scope = $grant.Scope } | Out-Null
        } else {
            Invoke-Graph -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = $servicePrincipal.id; consentType = 'AllPrincipals'; resourceId = $grant.Resource; scope = $grant.Scope } | Out-Null
        }
    }
    Write-Host 'Admin consent granted for all users of this tenant'
}

#endregion

$tenant = (Invoke-Graph -Path '/organization?$select=id').value[0].id
$consentTenant = if ($MultiTenant) { 'organizations' } else { $tenant }
$consentUrl = "$($cloud.Login)/$consentTenant/adminconsent?client_id=$($app.appId)&redirect_uri=$([uri]::EscapeDataString($RedirectUri[0]))"
Write-Host ''
Write-Host "Application (client) id: $($app.appId)"
Write-Host "Tenant id:               $tenant"
Write-Host "Redirect URIs:           $($RedirectUri -join ', ')"
if (-not $GrantAdminConsent) { Write-Host "Admin consent:           $consentUrl" }
Write-Host ''
Write-Host 'On the page, open "App registration and tenant", enter the application id (and the tenant id for a single tenant app) and sign in.'
[pscustomobject]@{ ClientId = $app.appId; TenantId = $tenant; RedirectUris = $RedirectUri; MultiTenant = [bool]$MultiTenant; AdminConsentUrl = $consentUrl }
