#Exposed credentials: deployment history, runbook source and resource configuration. Evidence names the location and pattern, never the value.

function Test-SecretName {
    #true for parameter/setting names that normally hold a credential
    param([string]$Name)
    $name = $Name.ToLowerInvariant()
    if ($name -match '(name|names|uri|url|id|ids|enabled|type|version|expiry|expiration|expiresin|length|publickey|keysource|keyvault|keyvaultname|vault)$' -or $name -match '^(is|enable|use|allow)') { return $false }
    return ($name -match 'password|passwd|pwd|secret|apikey|api_key|accesskey|accountkey|primarykey|secondarykey|masterkey|connectionstring|connstr|sastoken|sas_token|privatekey|credential|authtoken|accesstoken')
}

function Test-PlainSecretValue {
    #a value that looks like a real credential rather than a reference, placeholder or empty value
    param($Value)
    if ($Value -isnot [string]) { return $false }
    if ($Value.Length -lt 8) { return $false }
    if ($Value -match '^@Microsoft\.KeyVault\(|^\[|^\$\(|^\*+$|^<.*>$|^/subscriptions/|^https?://[^@]*$|^\{\{.*\}\}$') { return $false }
    return $true
}

function Get-NamedSecretFindings {
    #names of entries whose name looks like a credential and whose value is a plain credential
    param($Object, [string]$Prefix)
    if ($null -eq $Object) { return }
    foreach ($property in $Object.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [System.Management.Automation.PSCustomObject] -and $value.PSObject.Properties.Name -contains 'value') {
            if ($value.type -notmatch '^secure' -and (Test-SecretName $property.Name) -and (Test-PlainSecretValue $value.value)) { "$Prefix$($property.Name)" }
        } elseif ((Test-SecretName $property.Name) -and (Test-PlainSecretValue $value)) {
            "$Prefix$($property.Name)"
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-SEC-001'
    Title       = 'Deployment history does not contain plaintext secrets'
    Category    = 'Identity management'
    Service     = 'Azure Resource Manager'
    Severity    = 'High'
    Description = 'Scans the parameters and outputs of subscription and resource group deployments for credentials passed as plain strings (named like passwords, keys or connection strings, or matching credential patterns).'
    Rationale   = 'Deployment parameters and outputs are stored in the deployment history and are readable by anyone with Reader access. Secrets passed or returned as plain strings are exposed to them indefinitely.'
    Remediation = 'Use secureString/secureObject parameters and Key Vault references, never output secrets, rotate the exposed credentials and delete the affected deployments from the history.'
    References  = @('https://learn.microsoft.com/azure/azure-resource-manager/templates/best-practices#parameters')
    Frameworks  = @{ MCSB = @('IM-8', 'DS-6'); WAF = 'SE:09' }
    Requires    = @('subscription/deployments')
    Run         = {
        $deployments = @(Get-IngestData 'subscription/deployments' | Where-Object { $_ })
        foreach ($group in (Get-ResourceGroupRecords)) { $deployments += @($group.deployments | Where-Object { $_ }) }
        $findings = foreach ($deployment in $deployments) {
            $p = $deployment.properties
            $named = @(Get-NamedSecretFindings -Object $p.parameters -Prefix 'parameter ') + @(Get-NamedSecretFindings -Object $p.outputs -Prefix 'output ')
            $patterns = @(Find-Secrets (($p.parameters, $p.outputs) | ConvertTo-Json -Depth 30 -Compress))
            if (-not ($named -or $patterns)) { continue }
            $evidence = [ordered]@{ fields = @($named | Sort-Object -Unique); patterns = @($patterns | Sort-Object -Unique); timestamp = Format-UtcDate $p.timestamp }
            New-Finding -ResourceId $deployment.id -ResourceType 'Microsoft.Resources/deployments' -ResourceName $deployment.name -Result (New-Fail "Possible secret(s) in $((@($named) + @($patterns)) -join ', ')" $evidence)
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass "No plaintext secrets found in $($deployments.Count) deployment(s)") }
        $findings
    }
}

Add-AzTest @{
    Id            = 'AZ-SEC-002'
    Title         = 'Runbooks do not contain hardcoded credentials'
    Category      = 'Identity management'
    Service       = 'Automation'
    Severity      = 'High'
    Description   = 'Scans published Automation runbook source for hardcoded passwords, keys, client secrets, SAS tokens, connection strings and private keys.'
    Rationale     = 'Runbook source is readable by anyone with Reader access on the Automation account and is often copied to source control; embedded credentials are exposed to all of them.'
    Remediation   = 'Use the Automation account managed identity, encrypted Automation credentials/variables or Key Vault instead of literals, and rotate the exposed credentials.'
    References    = @('https://learn.microsoft.com/azure/automation/automation-security-overview')
    Frameworks    = @{ MCSB = @('IM-8', 'DS-6'); WAF = 'SE:09' }
    ResourceTypes = @('Microsoft.Automation/automationAccounts/runbooks')
    Evaluate      = {
        param($Record)
        $content = $Record.textContent.content
        if ($null -eq $content) { return New-NotApplicable 'No published content' }
        $patterns = @(Find-Secrets $content)
        $evidence = [ordered]@{ runbookType = $Record.resource.properties.runbookType; patterns = $patterns }
        if ($patterns) { return New-Fail "Possible credential(s): $($patterns -join ', ')" $evidence }
        New-Pass 'No credential patterns found' $evidence
    }
}

function Convert-FromBase64Utf8 {
    #decoded UTF-8 text of a base64 string, or $null when it is not valid printable base64 (binary/compressed data is skipped)
    param([string]$Value)
    if (-not $Value -or $Value.Length -lt 12 -or ($Value.Length % 4) -ne 0 -or $Value -notmatch '^[A-Za-z0-9+/]+={0,2}$') { return $null }
    try { $bytes = [Convert]::FromBase64String($Value) } catch { return $null }
    if (-not $bytes.Length) { return $null }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    if (([regex]::Matches($text, '[\x00-\x08\x0E-\x1F]')).Count -gt [math]::Max(2, $text.Length * 0.01)) { return $null }
    return $text
}

Add-AzTest @{
    Id            = 'AZ-SEC-004'
    Version       = 2
    Title         = 'Virtual machine custom data and script extensions do not contain plaintext secrets'
    Category      = 'Identity management'
    Service       = 'Virtual Machines'
    Severity      = 'High'
    Description   = 'Decodes the base64 userData and OS custom data of virtual machines and scale sets, and the base64 scripts of Custom Script Extensions, and scans the decoded content for credentials. This catches secrets that plain text configuration scanning (AZ-SEC-003) cannot see because the content is base64 encoded.'
    Rationale     = 'userData and Custom Script Extension scripts are returned by the management API to every reader of the machine and run at boot with high privilege; operators routinely embed passwords, keys and SAS URLs in them. Custom data is write only in most responses but is scanned when present.'
    Remediation   = 'Pass bootstrap secrets through the VM managed identity and Key Vault, or through the extension protectedSettings, instead of embedding them in userData, custom data or script content, and rotate any exposed credentials.'
    References     = @('https://learn.microsoft.com/azure/virtual-machines/user-data')
    Frameworks    = @{ MCSB = 'IM-8'; WAF = 'SE:09' }
    ResourceTypes = @('Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $profile = if ($Record.type -eq 'Microsoft.Compute/virtualMachineScaleSets') { $p.virtualMachineProfile } else { $p }
        #base64 surfaces only; plain extension settings are covered by AZ-SEC-003
        $surfaces = [ordered]@{}
        if ($profile.userData) { $surfaces['userData'] = [string]$profile.userData }
        if ($profile.osProfile.customData) { $surfaces['custom data'] = [string]$profile.osProfile.customData }
        if (-not (Test-MachineExtensionsCollected $Record)) { return New-Unknown 'Installed extensions could not be read, so script extension content was not scanned' }
        $extensions = @(Get-Child $Record 'extensions' | Where-Object { $_ }) + @($profile.extensionProfile.extensions | Where-Object { $_ })
        foreach ($extension in $extensions) {
            $type = if ($extension.properties.type) { $extension.properties.type } else { $extension.type }
            if ($type -notmatch 'CustomScript') { continue }
            $script = Get-Prop $extension.properties.settings 'script'
            if ($script) { $surfaces["extension $($extension.name) script"] = [string]$script }
        }
        if (-not $surfaces.Count) { return New-NotApplicable 'No userData, custom data or script extensions' }
        $hits = foreach ($name in $surfaces.Keys) {
            $decoded = Convert-FromBase64Utf8 $surfaces[$name]
            if ($decoded -and (Find-Secrets $decoded)) { $name }
        }
        $evidence = [ordered]@{ scanned = @($surfaces.Keys) }
        if ($hits) { return New-Fail "Possible secret(s) in $((@($hits)) -join ', ')" $evidence }
        New-Pass "No credential patterns in $($surfaces.Count) location(s)" $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-SEC-003'
    Version     = 2
    Title       = 'Resource configuration does not contain plaintext secrets'
    Category    = 'Identity management'
    Service     = 'Multiple'
    Severity    = 'High'
    Description = 'Scans VM and scale set extension settings, container instance and Container Apps environment variables, Logic App definitions and parameters, and resource tags for credentials stored in plain text.'
    Rationale   = 'These settings are returned by the management API to every reader of the resource and are logged in deployment history; secrets belong in protected settings, secret references or Key Vault.'
    Remediation = 'Move secrets to protectedSettings, secureValue / secretRef or Key Vault references, and rotate the exposed credentials.'
    References  = @('https://learn.microsoft.com/azure/virtual-machines/extensions/overview')
    Frameworks  = @{ MCSB = 'IM-8'; WAF = 'SE:09' }
    Run         = {
        $findings = foreach ($record in (Get-AzResourceRecords)) {
            $locations = [System.Collections.Generic.List[string]]::new()
            $p = $record.resource.properties
            foreach ($tag in @($record.resource.tags.PSObject.Properties)) { if (Find-Secrets ([string]$tag.Value)) { $locations.Add("tag $($tag.Name)") } }
            switch ($record.type) {
                { $_ -in 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets', 'Microsoft.HybridCompute/machines' } {
                    if (-not (Test-MachineExtensionsCollected $record)) {
                        New-Finding -Record $record -Result (New-Unknown 'Installed extensions could not be read, so their settings were not scanned')
                        continue
                    }
                    $extensions = @(Get-Child $record 'extensions' | Where-Object { $_ }) + @($p.virtualMachineProfile.extensionProfile.extensions | Where-Object { $_ })
                    foreach ($extension in $extensions) {
                        $settings = $extension.properties.settings
                        $hits = @(Find-Secrets ($settings | ConvertTo-Json -Depth 20 -Compress)) + @(Get-NamedSecretFindings -Object $settings)
                        if ($hits) { $locations.Add("extension $($extension.name) settings ($(($hits | Sort-Object -Unique) -join ', '))") }
                    }
                }
                { $_ -in 'Microsoft.Compute/virtualMachines/extensions', 'Microsoft.HybridCompute/machines/extensions' } {
                    $hits = @(Find-Secrets ($p.settings | ConvertTo-Json -Depth 20 -Compress)) + @(Get-NamedSecretFindings -Object $p.settings)
                    if ($hits) { $locations.Add("settings ($(($hits | Sort-Object -Unique) -join ', '))") }
                }
                'Microsoft.ContainerInstance/containerGroups' {
                    foreach ($container in @($p.containers | Where-Object { $_ })) {
                        foreach ($variable in @($container.properties.environmentVariables | Where-Object { $_ -and $null -ne $_.value })) {
                            if (((Test-SecretName $variable.name) -and (Test-PlainSecretValue $variable.value)) -or (Find-Secrets $variable.value)) { $locations.Add("container $($container.name) environment variable $($variable.name)") }
                        }
                    }
                }
                'Microsoft.App/containerApps' {
                    foreach ($container in @($p.template.containers | Where-Object { $_ })) {
                        foreach ($variable in @($container.env | Where-Object { $_ -and $null -ne $_.value })) {
                            if (((Test-SecretName $variable.name) -and (Test-PlainSecretValue $variable.value)) -or (Find-Secrets $variable.value)) { $locations.Add("container $($container.name) environment variable $($variable.name)") }
                        }
                    }
                }
                'Microsoft.Logic/workflows' {
                    $hits = @(Find-Secrets ($p.definition | ConvertTo-Json -Depth 50 -Compress)) + @(Get-NamedSecretFindings -Object $p.parameters -Prefix 'parameter ')
                    if ($hits) { $locations.Add("workflow ($(($hits | Sort-Object -Unique) -join ', '))") }
                }
            }
            if ($locations.Count) { New-Finding -Record $record -Result (New-Fail "Possible secret(s) in $($locations -join '; ')" ([ordered]@{ locations = @($locations) })) }
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No plaintext secrets found in scanned resource configuration') }
        $findings
    }
}
