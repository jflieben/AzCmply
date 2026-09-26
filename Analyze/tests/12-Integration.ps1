#Integration services: Service Bus and Event Hubs, API Management, Automation, Logic Apps (Consumption) and API connections

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

function Test-PolicyValidatesToken {
    #whether an API Management policy document validates a JSON web token
    param($Policy)
    return ([string]$Policy.properties.value -match '<validate-(jwt|azure-ad-token)\b')
}

Add-AzTest @{
    Id            = 'AZ-APIM-008'
    Title         = 'API Management APIs without a subscription key validate a token'
    Category      = 'Identity management'
    Service       = 'API Management'
    Severity      = 'High'
    Description   = 'For APIs that do not require a subscription key, checks that the API or the global policy validates a token (validate-jwt or validate-azure-ad-token).'
    Rationale     = 'An API without a subscription requirement and without token validation is open to anyone who finds the gateway address: API Management forwards every request to the backend, which often trusts the gateway and does no authentication of its own.'
    Remediation   = 'Require a subscription key on the API, or add a validate-jwt or validate-azure-ad-token policy that checks the issuer, audience and required claims of the caller.'
    References    = @('https://learn.microsoft.com/azure/api-management/api-management-subscriptions', 'https://learn.microsoft.com/azure/api-management/validate-jwt-policy')
    ResourceTypes = $apimType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'apis') -or -not (Test-ChildCollected $Record 'apis/*/policies') -or -not (Test-ChildCollected $Record 'policies')) { return New-Unknown 'APIs or policies could not be read' }
        $globalValidation = [bool]@(Get-Child $Record 'policies' | Where-Object { $_ -and (Test-PolicyValidatesToken $_) }).Count
        $open = @(Get-Child $Record 'apis' | Where-Object { $_ -and $_.properties.subscriptionRequired -eq $false })
        if (-not $open) { return New-Pass 'Every API requires a subscription key' ([ordered]@{ apisWithoutSubscription = @() }) }
        $apiPolicies = @(Get-Child $Record 'apis/*/policies' | Where-Object { $_ })
        $unprotected = @(foreach ($api in $open) {
                $prefix = "$($api.id)/".ToLowerInvariant()
                $validated = $globalValidation -or [bool]@($apiPolicies | Where-Object { ([string]$_.id).ToLowerInvariant().StartsWith($prefix) -and (Test-PolicyValidatesToken $_) }).Count
                if (-not $validated) { $api.name }
            })
        $evidence = [ordered]@{ apisWithoutSubscription = @($open | ForEach-Object name | Sort-Object); withoutTokenValidation = @($unprotected | Sort-Object) }
        if ($unprotected) { return New-Fail "API(s) open without a key or token: $($evidence.withoutTokenValidation -join ', ')" $evidence }
        New-Pass 'Every API without a subscription key validates a token' $evidence
    }
}

#region Logic Apps (Consumption) and API connections

$workflowType = @('Microsoft.Logic/workflows')
$connectionType = @('Microsoft.Web/connections')
#runs fail when, in the $logicFailureDays days before the ingestion, at least $logicFailureMinimum and $logicFailurePercent percent of them failed
$logicFailureDays = 30
$logicFailureMinimum = 5
$logicFailurePercent = 10
#a workflow without runs for this many days is unused; the ingestion collects run metrics for as many days
$logicIdleDays = 75
$credentialHeaderPattern = '^(authorization|x-api-key|api-key|apikey|ocp-apim-subscription-key|x-functions-key|x-auth-token|x-access-token|private-token)$'
$credentialQueryPattern = '(?i)[?&](code|sig|key|apikey|api_key|api-key|subscription-key|access_token|token)=([^&]*)'

function Get-WorkflowActions {
    #actions and the actions nested in them (scopes, conditions, switches, loops)
    param($Actions)
    if ($null -eq $Actions) { return }
    foreach ($property in @($Actions.PSObject.Properties)) {
        if (-not $property -or $property.Value -isnot [System.Management.Automation.PSCustomObject]) { continue }
        $action = $property.Value
        [pscustomobject]@{ Name = $property.Name; Kind = 'action'; Type = [string]$action.type; Step = $action }
        Get-WorkflowActions $action.actions
        Get-WorkflowActions $action.else.actions
        Get-WorkflowActions $action.default.actions
        if ($null -ne $action.cases) {
            foreach ($case in @($action.cases.PSObject.Properties)) { if ($case) { Get-WorkflowActions $case.Value.actions } }
        }
    }
}

function Get-WorkflowSteps {
    #triggers and actions of a workflow definition, nested actions included: name, kind, type and definition
    param($Definition)
    if ($null -eq $Definition) { return }
    if ($null -ne $Definition.triggers) {
        foreach ($property in @($Definition.triggers.PSObject.Properties)) {
            if ($property -and $property.Value -is [System.Management.Automation.PSCustomObject]) { [pscustomobject]@{ Name = $property.Name; Kind = 'trigger'; Type = [string]$property.Value.type; Step = $property.Value } }
        }
    }
    Get-WorkflowActions $Definition.actions
}

function Get-WorkflowConnectionMap {
    #entries of the $connections parameter: key > connector (last segment of the managed API id) and connection id, lowercase
    param($Record)
    $map = [ordered]@{}
    $parameter = @($Record.resource.properties.parameters.PSObject.Properties | Where-Object { $_ -and $_.Name -eq '$connections' }) | Select-Object -First 1
    if (-not $parameter) { return $map }
    foreach ($entry in @($parameter.Value.value.PSObject.Properties)) {
        if (-not $entry) { continue }
        $api = if ($entry.Value.id) { Get-ResourceName ([string]$entry.Value.id) } else { $entry.Name }
        $map[$entry.Name] = [pscustomobject]@{ Api = $api.ToLowerInvariant(); ConnectionId = ([string]$entry.Value.connectionId).ToLowerInvariant() }
    }
    return $map
}

function Get-StepConnector {
    #connector of an ApiConnection trigger or action ('keyvault'), from the $connections entry it names
    param($Step, $Connections)
    $name = [string]$Step.inputs.host.connection.name
    if ($name -notmatch "\[\s*'([^']+)'\s*\]") { return $null }
    $key = $Matches[1]
    if ($Connections.Contains($key)) { return $Connections[$key].Api }
    return $key.ToLowerInvariant()
}

function Get-WorkflowParameterType {
    #declared type of a workflow parameter ('SecureString', 'String'), from the definition or the workflow parameters
    param($Record, [string]$Name)
    $p = $Record.resource.properties
    foreach ($source in @($p.definition.parameters, $p.parameters)) {
        if ($null -eq $source) { continue }
        $parameter = @($source.PSObject.Properties | Where-Object { $_ -and $_.Name -eq $Name }) | Select-Object -First 1
        if ($parameter -and $parameter.Value.type) { return [string]$parameter.Value.type }
    }
    return $null
}

function Test-WorkflowExpression {
    #true for values that Logic Apps evaluates: '@...' (but not the escaped '@@') or text with '@{...}'
    param($Value)
    if ($Value -isnot [string]) { return $false }
    return (($Value.StartsWith('@') -and -not $Value.StartsWith('@@')) -or $Value.Contains('@{'))
}

function Get-WorkflowValueSource {
    #where a value in a workflow definition comes from, and the step whose output it uses
    param($Value, $Record, [string[]]$SecretSteps = @())
    if (-not (Test-WorkflowExpression $Value)) { return [pscustomobject]@{ Label = 'a literal value'; Step = $null } }
    $text = [string]$Value
    if ($text -match "parameters\('([^']+)'\)") {
        $label = if ((Get-WorkflowParameterType $Record $Matches[1]) -match '^secure') { 'a secure parameter' } else { 'a parameter' }
        return [pscustomobject]@{ Label = $label; Step = $null }
    }
    if ($text -match "(?:body|outputs|actions)\('([^']+)'\)") {
        $step = $Matches[1]
        $label = if ($step -in $SecretSteps) { 'a Key Vault secret' } else { 'the output of another step' }
        return [pscustomobject]@{ Label = $label; Step = $step }
    }
    return [pscustomobject]@{ Label = 'an expression'; Step = $null }
}

function New-StepCredential {
    #Credential: a shared secret rather than a managed identity or service principal; SignIn: used to sign in (not a
    #value in the body); Hidden: not counted as visible in run history (Authorization header, authentication settings);
    #PlainLiteral: written into the definition
    param([string]$Kind, $Value, $Record, [string[]]$SecretSteps, [bool]$Credential, [bool]$SignIn, [bool]$Hidden)
    $source = if ($Credential) { Get-WorkflowValueSource $Value $Record $SecretSteps } else { $null }
    [pscustomobject]@{
        Kind         = $Kind
        Source       = if ($source) { $source.Label } else { $null }
        From         = if ($source) { $source.Step } else { $null }
        Credential   = $Credential
        SignIn       = $SignIn
        Hidden       = $Hidden
        PlainLiteral = [bool]($source -and $source.Label -eq 'a literal value' -and (Test-PlainSecretValue $Value))
    }
}

function Get-StepCredentials {
    #how an HTTP, HTTP webhook or API Management step authenticates, and the credentials it sends
    param($Step, $Record, [string[]]$SecretSteps = @())
    $inputs = $Step.Step.inputs
    $targets = @()
    if ($Step.Type -eq 'Http') { $targets = @($inputs) }
    elseif ($Step.Type -eq 'HttpWebhook') { $targets = @($inputs.subscribe, $inputs.unsubscribe) }
    foreach ($target in @($targets | Where-Object { $_ })) {
        $authentication = $target.authentication
        if ($authentication -is [string]) {
            New-StepCredential 'authentication from an expression' $authentication $Record $SecretSteps $true $true $true
        } elseif ($null -ne $authentication) {
            switch ([string]$authentication.type) {
                'ManagedServiceIdentity' { New-StepCredential 'managed identity' $null $Record $SecretSteps $false $true $true }
                'ActiveDirectoryOAuth' { New-StepCredential 'service principal' $null $Record $SecretSteps $false $true $true }
                'Basic' { New-StepCredential 'Basic authentication' $authentication.password $Record $SecretSteps $true $true $true }
                'ClientCertificate' { New-StepCredential 'client certificate' $authentication.pfx $Record $SecretSteps $true $true $true }
                'Raw' { New-StepCredential 'raw authorization value' $authentication.value $Record $SecretSteps $true $true $true }
            }
        }
        if ($null -ne $target.headers) {
            foreach ($header in @($target.headers.PSObject.Properties)) {
                if (-not $header -or $header.Name -notmatch $credentialHeaderPattern -or -not $header.Value) { continue }
                New-StepCredential "header $($header.Name)" $header.Value $Record $SecretSteps $true $true ($header.Name -eq 'Authorization')
            }
        }
        if ($target.uri -is [string] -and $target.uri -match $credentialQueryPattern) {
            $name = $Matches[1]
            $value = $Matches[2]
            New-StepCredential "$name in the URL" $value $Record $SecretSteps $true $true $false
        }
        $body = $target.body
        if ($body -is [string] -and $body -match '(?i)\b(client_secret|client_assertion|password|api_?key|refresh_token)=([^&]*)') {
            $name = $Matches[1]
            $value = $Matches[2]
            New-StepCredential "body field $name" $value $Record $SecretSteps $true $false $false
        } elseif ($body -is [System.Management.Automation.PSCustomObject]) {
            foreach ($field in @($body.PSObject.Properties)) {
                if ($field -and $field.Value -is [string] -and $field.Value -and (Test-SecretName $field.Name)) { New-StepCredential "body field $($field.Name)" $field.Value $Record $SecretSteps $true $false $false }
            }
        }
    }
    if ($Step.Type -eq 'ApiManagement' -and $inputs.subscriptionKey) { New-StepCredential 'API Management subscription key' $inputs.subscriptionKey $Record $SecretSteps $true $true $false }
}

function Get-SecretReadSteps {
    #steps whose outputs hold a secret: Key Vault secret reads (connector or HTTP) and access token requests
    param($Steps, $Connections)
    foreach ($step in @($Steps | Where-Object { $_ })) {
        $inputs = $step.Step.inputs
        if ($step.Type -eq 'ApiConnection' -and (Get-StepConnector $step.Step $Connections) -eq 'keyvault' -and [string]$inputs.path -match '(?i)^/secrets/.+/value$') {
            [pscustomobject]@{ Step = $step; Reason = 'reads a Key Vault secret' }
        } elseif ($step.Type -eq 'Http' -and [string]$inputs.uri -match '(?i)\.vault\.(azure\.net|azure\.cn|usgovcloudapi\.net)/secrets/') {
            [pscustomobject]@{ Step = $step; Reason = 'reads a Key Vault secret' }
        } elseif ($step.Type -eq 'Http' -and [string]$inputs.uri -match '(?i)/oauth2/(v2\.0/)?token') {
            [pscustomobject]@{ Step = $step; Reason = 'requests an access token' }
        }
    }
}

function Test-StepSecured {
    #whether secure inputs or outputs ('inputs', 'outputs') are on for a step
    param($Step, [string]$Property)
    return (@($Step.Step.runtimeConfiguration.secureData.properties) -contains $Property)
}

function Get-RequestTriggerExposure {
    #who can call the Request triggers of a workflow; $null when it has none
    param($Record)
    $p = $Record.resource.properties
    $triggers = @(Get-WorkflowSteps $p.definition | Where-Object { $_.Kind -eq 'trigger' -and $_.Type -eq 'Request' })
    if (-not $triggers) { return $null }
    $access = $p.accessControl.triggers
    $rangesSet = $null -ne $access -and @($access.PSObject.Properties.Name) -contains 'allowedCallerIpAddresses' -and $null -ne $access.allowedCallerIpAddresses
    $ranges = @($access.allowedCallerIpAddresses | Where-Object { $_ } | ForEach-Object { [string]$_.addressRange } | Where-Object { $_ } | Sort-Object)
    $wide = @($ranges | Where-Object { $_ -in '0.0.0.0-255.255.255.255', '0.0.0.0/0', '::/0', '*' })
    $policies = @()
    if ($null -ne $access.openAuthenticationPolicies.policies) { $policies = @($access.openAuthenticationPolicies.policies.PSObject.Properties | Where-Object { $_ } | ForEach-Object { $_.Name } | Sort-Object) }
    $sasDisabled = [string]$access.sasAuthenticationPolicy.state -eq 'Disabled'
    $restriction = if (-not $rangesSet) { 'none' } elseif (-not $ranges) { 'other Logic Apps only' } else { 'address ranges' }
    $evidence = [ordered]@{
        requestTriggers     = @($triggers | ForEach-Object { if ($_.Step.kind) { "$($_.Name) ($($_.Step.kind))" } else { $_.Name } })
        callerRestriction   = $restriction
        allowedCallerRanges = $ranges
        sasAuthentication   = if ($sasDisabled) { 'Disabled' } else { 'Enabled' }
        entraIdPolicies     = $policies
        state               = $p.state
    }
    $reason = $null
    if ($restriction -eq 'other Logic Apps only') { $reason = 'Only other Logic Apps can call the request trigger' }
    elseif ($restriction -eq 'address ranges' -and -not $wide) { $reason = "Callers are limited to $($ranges.Count) address range(s)" }
    elseif ($sasDisabled -and $policies) { $reason = 'SAS is disabled; callers need a Microsoft Entra ID token' }
    elseif ($sasDisabled) { $reason = 'SAS is disabled and no Microsoft Entra ID policy is set, so nobody can call the trigger' }
    return [pscustomobject]@{ Open = -not $reason; Disabled = $p.state -in 'Disabled', 'Suspended'; Reason = $reason; Evidence = $evidence }
}

function Get-ConnectionConnector {
    #display name of the connector of an API connection
    param($Record)
    $api = $Record.resource.properties.api
    if ($api.displayName) { return [string]$api.displayName }
    if ($api.name) { return [string]$api.name }
    if ($api.id) { return Get-ResourceName ([string]$api.id) }
    return 'unknown connector'
}

function Get-ManagedApiMap {
    #managed API (connector) id, lowercase > connector metadata collected by the ingestion
    if (-not $script:Ingest.Cache.ContainsKey('#managedApis')) {
        $map = @{}
        foreach ($api in @(Get-IngestData 'web/managedApis' | Where-Object { $_ })) { $map[([string]$api.id).ToLowerInvariant()] = $api }
        $script:Ingest.Cache['#managedApis'] = $map
    }
    return $script:Ingest.Cache['#managedApis']
}

function Get-ConnectionUseMap {
    #API connection id, lowercase > names of the workflows whose $connections parameter uses it
    if (-not $script:Ingest.Cache.ContainsKey('#connectionUse')) {
        $map = @{}
        foreach ($workflow in (Get-AzResourceRecords -Type $workflowType)) {
            foreach ($entry in @((Get-WorkflowConnectionMap $workflow).Values)) {
                if (-not $entry -or -not $entry.ConnectionId) { continue }
                if (-not $map.ContainsKey($entry.ConnectionId)) { $map[$entry.ConnectionId] = [System.Collections.Generic.List[string]]::new() }
                $map[$entry.ConnectionId].Add((Get-ResourceName $workflow.id))
            }
        }
        $script:Ingest.Cache['#connectionUse'] = $map
    }
    return $script:Ingest.Cache['#connectionUse']
}

function Get-WorkflowAutomationUse {
    #workflows that alerts start through a Defender for Cloud workflow automation or an Azure Monitor action group:
    #Map (workflow id, lowercase > what starts it) and Missing (sources that could not be read)
    if (-not $script:Ingest.Cache.ContainsKey('#workflowUse')) {
        $map = @{}
        $missing = [System.Collections.Generic.List[string]]::new()
        $starters = [System.Collections.Generic.List[object]]::new()
        if (Test-IngestSection 'defender/automations') {
            foreach ($automation in @(Get-IngestData 'defender/automations' | Where-Object { $_ })) {
                foreach ($action in @($automation.properties.actions | Where-Object { $_ -and $_.actionType -eq 'LogicApp' -and $_.logicAppResourceId })) {
                    $starters.Add([pscustomobject]@{ Id = [string]$action.logicAppResourceId; Label = "Defender for Cloud workflow automation $($automation.name)" })
                }
            }
        } else {
            $missing.Add('Defender for Cloud workflow automations')
        }
        foreach ($group in (Get-AzResourceRecords -Type 'Microsoft.Insights/actionGroups')) {
            foreach ($receiver in @($group.resource.properties.logicAppReceivers | Where-Object { $_ -and $_.resourceId })) {
                $starters.Add([pscustomobject]@{ Id = [string]$receiver.resourceId; Label = "action group $(Get-ResourceName $group.id)" })
            }
        }
        if (Get-FailedResourceIds -Type 'Microsoft.Insights/actionGroups') { $missing.Add('Azure Monitor action groups') }
        foreach ($starter in $starters) {
            $key = $starter.Id.ToLowerInvariant()
            if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[string]]::new() }
            $map[$key].Add($starter.Label)
        }
        $script:Ingest.Cache['#workflowUse'] = [pscustomobject]@{ Map = $map; Missing = @($missing) }
    }
    return $script:Ingest.Cache['#workflowUse']
}

function Test-AlertTriggered {
    #true when a workflow starts on a Microsoft Sentinel or Defender for Cloud alert, incident or assessment
    param($Record)
    $connections = Get-WorkflowConnectionMap $Record
    foreach ($step in @(Get-WorkflowSteps $Record.resource.properties.definition | Where-Object { $_.Kind -eq 'trigger' -and $_.Type -eq 'ApiConnectionWebhook' })) {
        if ((Get-StepConnector $step.Step $connections) -match '^(azuresentinel|ascalert|ascassessment)$') { return $true }
    }
    return $false
}

function Get-WorkflowMetricTotals {
    #totals of the daily run metrics the ingestion collected, over the given number of days before the ingestion
    param($Record, [int]$Days)
    $totals = [ordered]@{ RunsStarted = 0; RunsCompleted = 0; RunsFailed = 0; TriggersCompleted = 0; TriggersFailed = 0 }
    #one metrics response per query window
    foreach ($metric in @(Get-Child $Record 'metrics' | Where-Object { $_ } | ForEach-Object { $_.value } | Where-Object { $_ })) {
        $name = [string]$metric.name.value
        if (-not $totals.Contains($name)) { continue }
        foreach ($point in @($metric.timeseries | Where-Object { $_ } | ForEach-Object { $_.data } | Where-Object { $_ })) {
            $age = Get-AgeInDays $point.timeStamp
            if ($null -ne $age -and $age -ge $Days) { continue }
            #counts; whole numbers keep the evidence the same in PowerShell and the browser
            if ($null -ne $point.total) { $totals[$name] += [int]$point.total }
        }
    }
    return $totals
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-001'
    Title         = 'Logic App request triggers restrict who can call them'
    Category      = 'Identity management'
    Service       = 'Logic Apps'
    Severity      = 'Medium'
    Description   = 'For enabled Consumption workflows with a Request trigger (HTTP, Power Apps, Teams and the other request kinds), checks that callers are limited to address ranges or to other Logic Apps, or that shared access signature (SAS) authentication is disabled so that callers need a Microsoft Entra ID token. A Microsoft Entra ID policy next to SAS does not count, because the trigger then accepts either.'
    Rationale     = 'The callback URL of a Request trigger carries a SAS signature that works from any address, does not expire and is not tied to an identity. It ends up in callers, scripts, alert rules, tickets and logs; anyone who has it can start the workflow with input of their choice until the access keys are regenerated.'
    Remediation   = "Limit 'Allowed inbound IP addresses' of the triggers to the callers (or to other Logic Apps only), or require Microsoft Entra ID OAuth and disable SAS (accessControl.triggers.sasAuthenticationPolicy.state Disabled). Regenerate the access keys when a URL may have leaked."
    References    = @('https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        if (-not $Record.resource.properties.definition) { return New-Unknown 'The workflow definition was not returned' }
        $exposure = Get-RequestTriggerExposure $Record
        if (-not $exposure) { return New-NotApplicable 'No request trigger' }
        if ($exposure.Disabled) { return New-NotApplicable "The workflow is $($exposure.Evidence.state)" $exposure.Evidence }
        if ($exposure.Open) { return New-Fail "$($exposure.Evidence.requestTriggers -join ', ') can be called with the signed URL from any address" $exposure.Evidence }
        New-Pass $exposure.Reason $exposure.Evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-002'
    Title         = 'Logic Apps that anyone can call have no write access in Azure'
    Category      = 'Privileged access'
    Service       = 'Logic Apps'
    Severity      = 'High'
    Description   = 'For enabled Consumption workflows whose Request trigger can be called from any address with its signed URL (AZ-LOGIC-001), lists the write capable role assignments of their system and user assigned managed identities, including assignments through groups whose members were collected.'
    Rationale     = 'The caller decides the input of the run, and the workflow acts on that input with the rights of its managed identity. A leaked trigger URL then gives anyone on the Internet write access to Azure, without an account, MFA or Conditional Access, and the activity log names the managed identity instead of the caller.'
    Remediation   = 'Restrict the trigger (allowed caller addresses, or Microsoft Entra ID OAuth with SAS disabled), or take the write access away from the identity and leave the privileged work to a workflow without a public trigger.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app', 'https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity')
    Requires      = @('rbac/roleAssignments', 'rbac/roleDefinitions')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        if (-not $Record.resource.properties.definition) { return New-Unknown 'The workflow definition was not returned' }
        $exposure = Get-RequestTriggerExposure $Record
        if (-not $exposure -or $exposure.Disabled -or -not $exposure.Open) { return New-NotApplicable 'Not callable from any address (AZ-LOGIC-001)' }
        $principals = @(Get-ResourceIdentityPrincipals $Record)
        $evidence = [ordered]@{ identityType = $Record.resource.identity.type; writeAssignments = @() }
        if (-not $principals) { return New-Pass 'Callable from any address, but without a managed identity' $evidence }
        $evidence.writeAssignments = @(Get-PrincipalWriteGrants $principals)
        if ($evidence.writeAssignments) { return New-Fail "Anyone with the trigger URL can start it, and it acts with $($evidence.writeAssignments -join '; ')" $evidence }
        New-Pass 'Callable from any address, but its managed identity has no write access' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-003'
    Title         = 'Logic App HTTP steps sign in with a managed identity or service principal'
    Category      = 'Identity management'
    Service       = 'Logic Apps'
    Severity      = 'Medium'
    Description   = 'Finds HTTP and HTTP webhook triggers and actions of Consumption workflows, nested ones included, that sign in with Basic authentication, a client certificate, a raw authorization value, a credential header (Authorization, API key, subscription key or function key headers) or a key in the URL, and API Management actions with a subscription key. Managed identity and Microsoft Entra ID OAuth (service principal) authentication pass. API connections are AZ-LOGIC-005 and AZ-LOGIC-006.'
    Rationale     = 'Passwords, API keys and certificates in a workflow are shared secrets: not tied to an identity, outside Conditional Access, rarely rotated and available to everyone who can edit or export the workflow. A managed identity has no secret to leak.'
    Remediation   = 'Use the managed identity of the workflow (authentication type ManagedServiceIdentity) for services that accept Microsoft Entra ID tokens, or a service principal; where a service only accepts a key, keep it in Key Vault and read it with the managed identity.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity', 'https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        $definition = $Record.resource.properties.definition
        if (-not $definition) { return New-Unknown 'The workflow definition was not returned' }
        $steps = @(Get-WorkflowSteps $definition)
        $secretSteps = @(Get-SecretReadSteps $steps (Get-WorkflowConnectionMap $Record) | ForEach-Object { $_.Step.Name })
        $credentials = [System.Collections.Generic.List[string]]::new()
        $identitySignIns = 0
        foreach ($step in $steps) {
            foreach ($credential in @(Get-StepCredentials $step $Record $secretSteps | Where-Object { $_.SignIn })) {
                if ($credential.Credential) { $credentials.Add("$($step.Name): $($credential.Kind) from $($credential.Source)") } else { $identitySignIns++ }
            }
        }
        $evidence = [ordered]@{ credentials = @($credentials | Sort-Object); identitySignIns = $identitySignIns }
        if ($credentials.Count) { return New-Fail "Signs in with credentials: $($evidence.credentials -join '; ')" $evidence }
        if ($identitySignIns) { return New-Pass "$identitySignIns sign-in(s) with a managed identity or service principal" $evidence }
        New-NotApplicable 'No step signs in to another service' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-004'
    Title         = 'Logic App steps that handle secrets hide them from run history'
    Category      = 'Data protection'
    Service       = 'Logic Apps'
    Severity      = 'High'
    Description   = 'Finds steps of Consumption workflows that read a Key Vault secret (Key Vault connector or HTTP) or request an access token without secure outputs, and steps that send a credential in a header, the URL or the body without secure inputs. Not counted: the Authorization header and inputs that use secured outputs, which the platform hides, and the authentication settings of HTTP steps.'
    Rationale     = 'Run history keeps the inputs and outputs of every step for 90 days and shows them to everyone who can read the workflow, Reader and Logic App Operator included. A secret read from Key Vault without secure outputs is readable there by all of them, which undoes keeping it in Key Vault.'
    Remediation   = "Turn on 'Secure outputs' for steps that read secrets or tokens and 'Secure inputs' for steps that send them (runtimeConfiguration.secureData.properties). Steps that use secured outputs get their inputs hidden, but not their own outputs; secure those where they return the secret."
    References    = @('https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        $definition = $Record.resource.properties.definition
        if (-not $definition) { return New-Unknown 'The workflow definition was not returned' }
        $steps = @(Get-WorkflowSteps $definition)
        $reads = @(Get-SecretReadSteps $steps (Get-WorkflowConnectionMap $Record))
        $secretSteps = @($reads | ForEach-Object { $_.Step.Name })
        $securedReads = @($reads | Where-Object { Test-StepSecured $_.Step 'outputs' } | ForEach-Object { $_.Step.Name })
        $exposed = [System.Collections.Generic.List[string]]::new()
        $handling = 0
        foreach ($read in $reads) {
            $handling++
            if ($read.Step.Name -notin $securedReads) { $exposed.Add("$($read.Step.Name) $($read.Reason) without secure outputs") }
        }
        foreach ($step in $steps) {
            $sent = @(Get-StepCredentials $step $Record $secretSteps | Where-Object { $_.Credential -and -not $_.Hidden -and -not ($_.From -and $_.From -in $securedReads) })
            if (-not $sent) { continue }
            $handling++
            if (-not (Test-StepSecured $step 'inputs')) { $exposed.Add("$($step.Name) sends $((@($sent | ForEach-Object { $_.Kind } | Sort-Object -Unique)) -join ', ') without secure inputs") }
        }
        $evidence = [ordered]@{ exposed = @($exposed | Sort-Object); stepsHandlingSecrets = $handling }
        if ($exposed.Count) { return New-Fail "Secrets visible in run history: $($evidence.exposed -join '; ')" $evidence }
        if ($handling) { return New-Pass "$handling step(s) that handle secrets hide them" $evidence }
        New-NotApplicable 'No step reads or sends a secret' $evidence
    }
}

function Get-ConnectionAuthentication {
    #how an API connection signs in, from the connection and the metadata of its connector. Method: 'user', 'managed
    #identity', 'service principal', 'shared secret', 'none' or 'unknown' (Reason says why)
    param($Record)
    $p = $Record.resource.properties
    $setName = [string]$p.parameterValueSet.name
    $result = [pscustomobject]@{ Method = 'unknown'; User = [string]$p.authenticatedUser.name; ParameterSet = if ($setName) { $setName } else { 'default' }; SecretParameters = @(); Reason = $null }
    if ($result.User) { $result.Method = 'user'; return $result }
    if ($p.parameterValueType -eq 'Alternative') { $result.Method = 'managed identity'; return $result }
    $connector = Get-ConnectionConnector $Record
    $api = (Get-ManagedApiMap)[([string]$p.api.id).ToLowerInvariant()]
    if (-not $api) { $result.Reason = "the metadata of connector $connector could not be read"; return $result }
    $parameters = $api.properties.connectionParameters
    if ($setName) {
        $set = @($api.properties.connectionParameterSets.values | Where-Object { $_ -and $_.name -eq $setName }) | Select-Object -First 1
        if (-not $set) { $result.Reason = "connector $connector has no parameter set $setName"; return $result }
        $parameters = $set.parameters
    }
    $declared = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $parameters) {
        foreach ($parameter in @($parameters.PSObject.Properties)) { if ($parameter) { $declared.Add([pscustomobject]@{ Name = $parameter.Name; Type = [string]$parameter.Value.type }) } }
    }
    if (@($declared | Where-Object { $_.Type -eq 'managedIdentity' })) { $result.Method = 'managed identity'; return $result }
    #a client id marks a service principal: always in a parameter set, and in the values of a default connection
    $values = @($p.parameterValues, $p.nonSecretParameterValues | Where-Object { $_ } | ForEach-Object { $_.PSObject.Properties } | Where-Object { $_ -and $_.Value })
    $clientIdDeclared = [bool]@($declared | Where-Object { $_.Name -eq 'token:clientId' })
    $clientIdSet = [bool]@($values | Where-Object { $_.Name -eq 'token:clientId' -or ($_.Name -eq 'token:grantType' -and $_.Value -eq 'client_credentials') })
    if ($clientIdDeclared -and ($setName -or $clientIdSet)) { $result.Method = 'service principal'; return $result }
    #OAuth without a client id signs in on behalf of a user, unless the connection goes through an on-premises gateway
    #with a user name and password; Azure does not name the user for every connector (Outlook.com, for one)
    $result.SecretParameters = @($declared | Where-Object { $_.Type -in 'securestring', 'secureobject' -and $_.Name -notlike 'token:*' } | ForEach-Object { $_.Name } | Sort-Object)
    $oauth = [bool]@($declared | Where-Object { $_.Type -eq 'oauthSetting' })
    $gateway = [bool]@($values | Where-Object { $_.Name -eq 'gateway' })
    if ($oauth -and -not $gateway) { $result.Method = 'user'; $result.SecretParameters = @() }
    elseif ($result.SecretParameters) { $result.Method = 'shared secret' }
    else { $result.Method = 'none' }
    return $result
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-005'
    Title         = 'API connections do not sign in as a user'
    Category      = 'Identity management'
    Service       = 'Logic Apps'
    Severity      = 'High'
    Description   = 'Finds API connections (of Consumption and Standard logic apps) that sign in with a user account: OAuth on behalf of the person who signed in when the connection was created or repaired. Azure names that user for most connectors; for the others, the metadata of the connector shows that it signs in on behalf of a user.'
    Rationale     = 'Every workflow that uses the connection, and everyone who may use it in a workflow of their own (Microsoft.Web/connections/join/action, part of Contributor), acts as that person: reads their mail and files, sends as them and uses their permissions in the connected service. The refresh token keeps working outside MFA and Conditional Access, and the automation breaks, or keeps running on a personal account, when the person leaves.'
    Remediation   = 'Recreate the connection with the managed identity of the workflow or a service principal where the connector supports it. For connectors without that option, call the service (for Microsoft 365, Microsoft Graph) from an HTTP action with the managed identity and scoped application permissions, then delete the user connection.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity')
    ResourceTypes = $connectionType
    Evaluate      = {
        param($Record)
        $auth = Get-ConnectionAuthentication $Record
        $evidence = [ordered]@{ connector = Get-ConnectionConnector $Record; kind = $Record.resource.kind; method = $auth.Method; authenticatedUser = $auth.User; displayName = [string]$Record.resource.properties.displayName }
        if ($auth.Method -eq 'user' -and $auth.User) { return New-Fail "Signs in to $($evidence.connector) as $($auth.User)" $evidence }
        if ($auth.Method -eq 'user') { return New-Fail "Signs in to $($evidence.connector) as a user; the connection does not name the user" $evidence }
        if ($auth.Method -eq 'unknown') { return New-Unknown "Whether it signs in as a user is not known: $($auth.Reason)" $evidence }
        New-Pass "Does not sign in as a user ($($auth.Method))" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-006'
    Title         = 'API connections sign in with a managed identity or service principal'
    Category      = 'Identity management'
    Service       = 'Logic Apps'
    Severity      = 'Medium'
    Description   = 'Finds API connections whose authentication stores a shared secret: an access key, connection string, password or API key, which are the parameters the connector marks as secure. Connections with a managed identity or a service principal pass; connections that sign in as a user are AZ-LOGIC-005.'
    Rationale     = 'The secret is stored in the connection and used by every workflow that can join it. It is not tied to an identity, cannot be limited by Conditional Access, is rarely rotated and keeps working after the workflows that needed it are gone.'
    Remediation   = 'Recreate the connection with the managed identity of the workflow or a service principal, grant that identity a data role on the target, then delete the connection with the stored secret and rotate the secret.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity')
    Requires      = @('web/managedApis')
    ResourceTypes = $connectionType
    Evaluate      = {
        param($Record)
        $auth = Get-ConnectionAuthentication $Record
        $connector = Get-ConnectionConnector $Record
        $evidence = [ordered]@{ connector = $connector; parameterSet = $auth.ParameterSet; method = $auth.Method; secretParameters = $auth.SecretParameters }
        if ($auth.Method -eq 'user') { return New-NotApplicable 'Signs in as a user (AZ-LOGIC-005)' $evidence }
        if ($auth.Method -eq 'unknown') { return New-Unknown "How it signs in is not known: $($auth.Reason)" $evidence }
        if ($auth.Method -in 'managed identity', 'service principal') { return New-Pass "Signs in with a $($auth.Method)" $evidence }
        if ($auth.Method -eq 'shared secret') { return New-Fail "Stores a secret for $connector ($($auth.SecretParameters -join ', '))" $evidence }
        New-NotApplicable "Stores no secret for $connector" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-007'
    Title         = 'API connections are authorized and working'
    Category      = 'Asset management'
    Service       = 'Logic Apps'
    Severity      = 'Medium'
    Description   = 'Finds API connections with status Error: never authorized, consent withdrawn, or a token that can no longer be refreshed (expired, password changed, account disabled or deleted).'
    Rationale     = 'A broken connection stops every workflow that uses it, usually without an alert, and often points to the credentials of someone who left or changed role. Repairing it by signing in again moves the connection to the account of whoever repairs it.'
    Remediation   = 'Find the workflows that use the connection. Delete it when none needs it; otherwise recreate it with a managed identity or service principal (AZ-LOGIC-006) instead of authorizing it again with a personal account.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app')
    ResourceTypes = $connectionType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $statuses = @($p.statuses | Where-Object { $_ })
        if (-not $statuses -and -not $p.overallStatus) { return New-Unknown 'The connection reports no status' }
        $errors = @($statuses | Where-Object { $_.status -eq 'Error' })
        $codes = @($errors | ForEach-Object { if ($_.error.code) { [string]$_.error.code } elseif ($_.error.properties.code) { [string]$_.error.properties.code } } | Where-Object { $_ } | Sort-Object -Unique)
        $message = @($errors | ForEach-Object { if ($_.error.message) { [string]$_.error.message } elseif ($_.error.properties.message) { [string]$_.error.properties.message } } | Where-Object { $_ }) | Select-Object -First 1
        if ($message) { $message = ($message -replace '\s+', ' ').Trim(); if ($message.Length -gt 200) { $message = $message.Substring(0, 200) } }
        $evidence = [ordered]@{ connector = Get-ConnectionConnector $Record; overallStatus = $p.overallStatus; statuses = @($statuses | ForEach-Object { [string]$_.status }); errorCodes = $codes; errorMessage = $message }
        if ($errors -or $p.overallStatus -eq 'Error') { return New-Fail "Status Error$(if ($codes) { " ($($codes -join ', '))" })" $evidence }
        New-Pass "Status $(if ($p.overallStatus) { $p.overallStatus } else { $evidence.statuses[0] })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-008'
    Title         = 'API connections are used by a Logic App'
    Category      = 'Asset management'
    Service       = 'Logic Apps'
    Severity      = 'Medium'
    Description   = 'Finds API connections of Consumption Logic Apps (V1) that no workflow in the subscription uses. Connections of Standard logic apps (V2) are referenced from the files of the app, which the ingestion does not read, and are not evaluated.'
    Rationale     = 'The designer creates a connection, with its credential, as soon as an action is added, and the connection stays when the workflow is deleted or never saved. An unused connection is a stored token or secret without an owner that anyone who can join it can still use; until January 2025 even Readers could call the connected service through it (Binary Security).'
    Remediation   = 'Delete connections that no workflow uses, and revoke or rotate the credential they held.'
    References    = @('https://www.binarysecurity.no/posts/2025/03/api-connections', 'https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app')
    ResourceTypes = $connectionType
    Filter        = { param($Record) [string]$Record.resource.kind -ne 'V2' }
    Evaluate      = {
        param($Record)
        $users = @((Get-ConnectionUseMap)[$Record.id.ToLowerInvariant()] | Where-Object { $_ } | Sort-Object -Unique)
        $evidence = [ordered]@{ connector = Get-ConnectionConnector $Record; createdTime = Format-UtcDate $Record.resource.properties.createdTime; usedBy = $users }
        if ($users) { return New-Pass "Used by $($users -join ', ')" $evidence }
        if (Get-FailedResourceIds -Type $workflowType) { return New-Unknown 'Not every workflow could be read, so one of them may use the connection' $evidence }
        New-Fail "No workflow in the subscription uses this $($evidence.connector) connection" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-009'
    Title         = 'Logic App runs and triggers succeed'
    Category      = 'Asset management'
    Service       = 'Logic Apps'
    Severity      = 'Low'
    Description   = "For Consumption workflows, reads the run metrics of the $logicFailureDays days before the ingestion and fails when at least $logicFailureMinimum runs, and at least $logicFailurePercent percent of the completed runs, failed. The same applies to trigger evaluations, because a polling trigger with a broken connection fails without starting runs."
    Rationale     = 'Workflows that keep failing often run on expired or revoked credentials, or on permissions that were taken away, and nobody notices. When the workflow is a response playbook or an integration, its work silently does not happen.'
    Remediation   = 'Look up the failing runs in the run history, fix the cause (credentials, permissions, target) and add an alert on Runs Failed and Triggers Failed; delete the workflow when it is no longer needed.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/monitor-logic-apps-overview', 'https://learn.microsoft.com/azure/azure-monitor/reference/supported-metrics/microsoft-logic-workflows-metrics')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'metrics')) { return New-Unknown 'The run metrics could not be read' }
        $totals = Get-WorkflowMetricTotals $Record $logicFailureDays
        $runs = [math]::Max($totals.RunsCompleted, $totals.RunsFailed)
        $triggers = [math]::Max($totals.TriggersCompleted, $totals.TriggersFailed)
        $evidence = [ordered]@{ days = $logicFailureDays; runsCompleted = $runs; runsFailed = $totals.RunsFailed; triggersCompleted = $triggers; triggersFailed = $totals.TriggersFailed; startedBy = @((Get-WorkflowAutomationUse).Map[$Record.id.ToLowerInvariant()] | Where-Object { $_ } | Sort-Object) }
        if (-not $runs -and -not $triggers) { return New-NotApplicable "No runs or trigger activity in the last $logicFailureDays days" $evidence }
        $problems = @()
        if ($totals.RunsFailed -ge $logicFailureMinimum -and $totals.RunsFailed * 100 -ge $runs * $logicFailurePercent) { $problems += "$($totals.RunsFailed) of $runs runs" }
        if ($totals.TriggersFailed -ge $logicFailureMinimum -and $totals.TriggersFailed * 100 -ge $triggers * $logicFailurePercent) { $problems += "$($totals.TriggersFailed) of $triggers trigger evaluations" }
        if ($problems) { return New-Fail "$($problems -join ' and ') failed in the last $logicFailureDays days" $evidence }
        New-Pass "$($totals.RunsFailed) of $runs runs failed in the last $logicFailureDays days" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-LOGIC-010'
    Title         = 'Logic Apps are in use'
    Category      = 'Asset management'
    Service       = 'Logic Apps'
    Severity      = 'Low'
    Description   = "Finds Consumption workflows older than $logicIdleDays days that are disabled and were not changed for $logicIdleDays days, or that are enabled without a run in the last $logicIdleDays days. Workflows that start on a Microsoft Sentinel or Defender for Cloud alert or incident, or from a Defender for Cloud workflow automation or an Azure Monitor action group, only run when an alert fires and are not evaluated."
    Rationale     = 'An unused workflow keeps its managed identity and role assignments, its API connections with their tokens and secrets, and its callable trigger URL, and nobody watches it. Removing it removes that access.'
    Remediation   = 'Delete workflows that are no longer needed, together with their API connections and the role assignments of their managed identity. Document the ones kept for rare events.'
    References    = @('https://learn.microsoft.com/azure/logic-apps/manage-logic-apps-with-azure-portal')
    ResourceTypes = $workflowType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ state = $p.state; createdDaysAgo = Get-AgeInDays $p.createdTime; changedDaysAgo = Get-AgeInDays $p.changedTime; days = $logicIdleDays; runsStarted = $null }
        if ($null -ne $evidence.createdDaysAgo -and $evidence.createdDaysAgo -lt $logicIdleDays) { return New-NotApplicable "Created $($evidence.createdDaysAgo) day(s) ago" $evidence }
        if ($p.state -in 'Disabled', 'Suspended') {
            if ($null -eq $evidence.changedDaysAgo) { return New-Unknown "$($p.state), and when it was last changed is not known" $evidence }
            if ($evidence.changedDaysAgo -ge $logicIdleDays) { return New-Fail "$($p.state) and not changed for $($evidence.changedDaysAgo) days" $evidence }
            return New-NotApplicable "$($p.state) since $($evidence.changedDaysAgo) day(s)" $evidence
        }
        if (-not (Test-ChildCollected $Record 'metrics')) { return New-Unknown 'The run metrics could not be read' $evidence }
        $evidence.runsStarted = (Get-WorkflowMetricTotals $Record $logicIdleDays).RunsStarted
        if ($evidence.runsStarted) { return New-Pass "$($evidence.runsStarted) run(s) in the last $logicIdleDays days" $evidence }
        if (Test-AlertTriggered $Record) { return New-NotApplicable 'Starts on a Microsoft Sentinel or Defender for Cloud alert or incident' $evidence }
        $use = Get-WorkflowAutomationUse
        $startedBy = @($use.Map[$Record.id.ToLowerInvariant()] | Where-Object { $_ } | Sort-Object)
        if ($startedBy) { return New-NotApplicable "Started by $($startedBy -join ', ')" $evidence }
        if ($use.Missing) { return New-Unknown "No runs in the last $logicIdleDays days, and whether an alert starts it is not known: $($use.Missing -join ', ') could not be read" $evidence }
        New-Fail "No runs in the last $logicIdleDays days" $evidence
    }
}

#endregion
