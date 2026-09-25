#AI services: Azure AI Services / Azure OpenAI (Foundry) accounts, Azure Machine Learning workspaces and Azure AI Bot Service

$aiType = @('Microsoft.CognitiveServices/accounts')
$mlType = @('Microsoft.MachineLearningServices/workspaces')

Add-AzTest @{
    Id            = 'AZ-AI-001'
    Title         = 'Azure AI Services accounts disable key access'
    Category      = 'Identity management'
    Service       = 'Azure AI Services'
    Severity      = 'High'
    Description   = 'Checks disableLocalAuth on Azure AI Services, Azure OpenAI and Foundry accounts.'
    Rationale     = 'API keys are shared secrets that end up in code and prompts tooling; anyone holding a key can use the models and data connections at your cost and under your identity, without RBAC or Conditional Access.'
    Remediation   = 'Move clients to Entra ID (Cognitive Services OpenAI User and similar roles with managed identities) and disable local authentication (az cognitiveservices account update --custom-domain ... --api-properties disableLocalAuth=true, or set properties.disableLocalAuth).'
    References    = @('https://learn.microsoft.com/azure/ai-services/disable-local-auth')
    Policy        = @{ '71ef260a-8f18-47b7-abcb-62d0673d94dc' = 'Azure AI Services resources should have key access disabled (disable local authentication)' }
    ResourceTypes = $aiType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableLocalAuth
        if ($value -eq $true) { return New-Pass 'Key access disabled' ([ordered]@{ disableLocalAuth = $true; kind = $Record.resource.kind }) }
        New-Fail 'Key access enabled' ([ordered]@{ disableLocalAuth = $value; kind = $Record.resource.kind })
    }
}

Add-AzTest @{
    Id            = 'AZ-AI-002'
    Title         = 'Azure AI Services accounts restrict network access'
    Category      = 'Network security'
    Service       = 'Azure AI Services'
    Severity      = 'Medium'
    Description   = 'Checks that public network access is disabled or the network ACL denies access by default.'
    Rationale     = 'An open endpoint lets a leaked key or token be used from anywhere and exposes the models and any grounded data to the Internet.'
    Remediation   = 'Use private endpoints and disable public network access, or set the default network action to Deny with specific IP and virtual network rules.'
    References    = @('https://learn.microsoft.com/azure/ai-services/cognitive-services-virtual-networks')
    Policy        = @{ '037eea7a-bd0a-46c5-9a66-03aea78705d3' = 'Azure AI Services resources should restrict network access'; 'd6759c02-b87f-42b7-892e-71b3f471d782' = 'Azure AI Services resources should use Azure Private Link' }
    ResourceTypes = $aiType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; defaultAction = $p.networkAcls.defaultAction }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if ($p.networkAcls.defaultAction -eq 'Deny') { return New-Pass 'Default network action Deny' $evidence }
        New-Fail 'Open to all networks' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-AI-003'
    Title         = 'Azure AI Services accounts restrict outbound access'
    Category      = 'AI security'
    Service       = 'Azure AI Services'
    Severity      = 'Low'
    Description   = 'Checks restrictOutboundNetworkAccess with an allowed FQDN list, which limits the endpoints the service can reach (for example for grounding, tools and data sources).'
    Rationale     = 'Unrestricted egress lets prompt injection or a misconfigured data connection send data to arbitrary destinations.'
    Remediation   = 'Enable outbound restrictions and list only the required FQDNs (properties.restrictOutboundNetworkAccess and allowedFqdnList).'
    References    = @('https://learn.microsoft.com/azure/ai-services/cognitive-services-data-loss-prevention')
    ResourceTypes = $aiType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ restrictOutboundNetworkAccess = [bool]$p.restrictOutboundNetworkAccess; allowedFqdns = @($p.allowedFqdnList).Count }
        if ($p.restrictOutboundNetworkAccess) { return New-Pass "Outbound access limited to $(@($p.allowedFqdnList).Count) FQDN(s)" $evidence }
        New-Fail 'Outbound access unrestricted' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-AI-004'
    Version     = 2
    Title       = 'AI model deployments use content filtering and prompt shields'
    Category    = 'AI security'
    Service     = 'Azure AI Services'
    Severity    = 'High'
    Description = 'Checks each model deployment for a content filter (RAI) policy. Default Microsoft policies pass; custom policies fail when a harm category filter or the jailbreak (prompt shield) filter is disabled or not blocking.'
    Rationale   = 'Content filters and prompt shields block harmful output and jailbreak or prompt injection attempts; disabling them removes a primary AI safety layer.'
    Remediation = 'Assign Microsoft.DefaultV2 or a custom content filter with all harm categories and jailbreak detection enabled in blocking mode. Filter modifications require an approved exception from Microsoft and should be documented.'
    References  = @('https://learn.microsoft.com/azure/ai-foundry/openai/concepts/content-filter')
    Policy      = @{ 'af253d37-136a-42f8-a1fc-30010c083d41' = '[Preview]: Cognitive Services Deployments should only use allowed completion content filtering'; 'f3a9c2e0-7b4d-4d8f-9c3a-2e1f6b9a8d4e' = '[Preview]: Cognitive Services Deployments should only use allowed prompt content filtering' }
    Run         = {
        foreach ($account in (Get-AzResourceRecords -Type 'Microsoft.CognitiveServices/accounts')) {
            if (-not (Test-ChildCollected $account 'deployments')) { New-Finding -Record $account -Result (New-Unknown 'Model deployments could not be listed'); continue }
            $policiesCollected = Test-ChildCollected $account 'raiPolicies'
            $policies = @{}
            foreach ($policy in @(Get-Child $account 'raiPolicies' | Where-Object { $_ })) { $policies[$policy.name.ToLowerInvariant()] = $policy }
            foreach ($deployment in @(Get-Child $account 'deployments' | Where-Object { $_ })) {
                $name = $deployment.properties.raiPolicyName
                $evidence = [ordered]@{ account = $account.resource.name; model = "$($deployment.properties.model.name) $($deployment.properties.model.version)"; raiPolicyName = $name }
                $policy = if ($name) { $policies[$name.ToLowerInvariant()] } else { $null }
                if (-not $name -or $name -like 'Microsoft.*') {
                    $result = New-Pass "Default content filter ($(if ($name) { $name } else { 'Microsoft.Default' }))" $evidence
                } elseif (-not $policy) {
                    #a custom policy name whose definition was not read says nothing about how strict it is
                    $result = if ($policiesCollected) { New-Unknown "Custom content filter '$name' is not among the account's policies" $evidence } else { New-Unknown "Custom content filter '$name' could not be read" $evidence }
                } else {
                    $weak = @($policy.properties.contentFilters | Where-Object { $_ -and ($_.enabled -eq $false -or ($_.PSObject.Properties.Name -contains 'blocking' -and $_.blocking -eq $false)) } | ForEach-Object { "$($_.source) $($_.name)" } | Sort-Object)
                    $jailbreak = @($policy.properties.contentFilters | Where-Object { $_ -and $_.name -match 'jailbreak' -and $_.enabled -and $_.blocking -ne $false })
                    $evidence.weakenedFilters = $weak
                    $evidence.jailbreakBlocking = [bool]$jailbreak
                    $result = if ($weak -or -not $jailbreak) { New-Fail "Custom filter $name weakens protection$(if ($weak) { ": $($weak -join ', ')" })$(if (-not $jailbreak) { ' (no blocking prompt shield)' })" $evidence } else { New-Pass "Custom filter $name keeps all filters blocking" $evidence }
                }
                New-Finding -ResourceId $deployment.id -ResourceType 'Microsoft.CognitiveServices/accounts/deployments' -ResourceName "$($account.resource.name)/$($deployment.name)" -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-AI-005'
    Title         = 'Machine Learning and Foundry hub workspaces disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Machine Learning'
    Severity      = 'Medium'
    Description   = 'Checks public network access of Azure Machine Learning and Foundry hub workspaces.'
    Rationale     = 'Workspaces hold data connections, credentials for datastores and model artifacts; a public endpoint exposes them to token theft from any network.'
    Remediation   = 'Use private endpoints and set public network access to Disabled (az ml workspace update --public-network-access Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/machine-learning/how-to-configure-private-link')
    Policy        = @{ '438c38d2-3772-465a-a9cc-7a6666a275ce' = 'Azure Machine Learning Workspaces should disable public network access'; '45e05259-1eb5-4f70-9574-baf73e9d219b' = 'Azure Machine Learning workspaces should use private link' }
    ResourceTypes = $mlType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.publicNetworkAccess
        if ($value -eq 'Disabled') { return New-Pass 'Public network access disabled' ([ordered]@{ publicNetworkAccess = $value }) }
        New-Fail 'Public network access enabled' ([ordered]@{ publicNetworkAccess = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-AI-006'
    Title         = 'Machine Learning managed networks only allow approved outbound traffic'
    Category      = 'Network security'
    Service       = 'Azure Machine Learning'
    Severity      = 'Medium'
    Description   = "Checks that the workspace managed virtual network uses isolation mode 'AllowOnlyApprovedOutbound'."
    Rationale     = 'Without outbound restrictions, compute running untrusted code, notebooks or models can exfiltrate training data and credentials to any Internet destination.'
    Remediation   = "Set the managed network isolation mode to AllowOnlyApprovedOutbound and add outbound rules for required destinations."
    References    = @('https://learn.microsoft.com/azure/machine-learning/how-to-managed-network')
    Policy        = @{ '6ddb1705-c8cf-450e-aa4b-19ad6703c440' = 'Azure Machine Learning and Ai Studio should use Allow Only Approved Outbound Managed Vnet mode' }
    ResourceTypes = $mlType
    Evaluate      = {
        param($Record)
        $mode = $Record.resource.properties.managedNetwork.isolationMode
        $evidence = [ordered]@{ isolationMode = $mode }
        if ($mode -eq 'AllowOnlyApprovedOutbound') { return New-Pass 'Only approved outbound traffic' $evidence }
        New-Fail "Isolation mode $(if ($mode) { $mode } else { 'Disabled' })" $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-AI-007'
    Title       = 'Machine Learning compute disables local authentication and public access'
    Category    = 'Identity management'
    Service     = 'Azure Machine Learning'
    Severity    = 'Medium'
    Description = 'Checks Machine Learning compute instances and clusters for local authentication, public SSH access and node public IP addresses.'
    Rationale   = 'Local accounts and public SSH give access to compute that holds workspace credentials, data and managed identity tokens, bypassing Entra ID.'
    Remediation = 'Recreate compute with local authentication disabled, SSH public access disabled and no public IP (in a managed virtual network).'
    References  = @('https://learn.microsoft.com/azure/machine-learning/how-to-secure-training-vnet')
    Policy      = @{ 'e96a9a5f-07ca-471b-9bc5-6a0f33cbd68f' = 'Azure Machine Learning Computes should have local authentication methods disabled' }
    Run         = {
        foreach ($workspace in (Get-AzResourceRecords -Type 'Microsoft.MachineLearningServices/workspaces')) {
            #without the compute list, "no compute in scope" cannot be distinguished from "compute unknown"
            if (-not (Test-ChildCollected $workspace 'computes')) { New-Finding -Record $workspace -Result (New-Unknown 'Machine Learning compute could not be listed'); continue }
            foreach ($compute in @(Get-Child $workspace 'computes' | Where-Object { $_ -and $_.properties.computeType -in 'ComputeInstance', 'AmlCompute' })) {
                $p = $compute.properties
                $inner = $p.properties
                $problems = @()
                if ($p.disableLocalAuth -ne $true) { $problems += 'local authentication enabled' }
                if ($inner.sshSettings.sshPublicAccess -eq 'Enabled' -or $inner.remoteLoginPortPublicAccess -eq 'Enabled') { $problems += 'public SSH access' }
                if ($inner.enableNodePublicIp -ne $false) { $problems += 'public IP' }
                $evidence = [ordered]@{ workspace = $workspace.resource.name; computeType = $p.computeType; disableLocalAuth = $p.disableLocalAuth; sshPublicAccess = if ($inner.sshSettings) { $inner.sshSettings.sshPublicAccess } else { $inner.remoteLoginPortPublicAccess }; enableNodePublicIp = $inner.enableNodePublicIp }
                $result = if ($problems) { New-Fail ($problems -join ', ') $evidence } else { New-Pass 'Local authentication and public access disabled' $evidence }
                New-Finding -ResourceId $compute.id -ResourceType 'Microsoft.MachineLearningServices/workspaces/computes' -ResourceName "$($workspace.resource.name)/$($compute.name)" -Result $result
            }
        }
    }
}

$botType = @('Microsoft.BotService/botServices')

Add-AzTest @{
    Id            = 'AZ-BOT-001'
    Title         = 'Bot Service bots are isolated from the Internet'
    Category      = 'Network security'
    Service       = 'Azure AI Bot Service'
    Severity      = 'Medium'
    Description   = 'Checks Azure AI Bot Service bots for disabled public network access (isolated mode) and an approved private endpoint.'
    Rationale     = 'In isolated mode the bot only talks to clients through Direct Line App Service Extension over private endpoints, and channels that need the public Internet are turned off. Conversations and the bot credentials then stay on private networks.'
    Remediation   = 'Create a private endpoint for the bot, move clients to the Direct Line App Service Extension, then set public network access to Disabled.'
    References    = @('https://learn.microsoft.com/azure/bot-service/dl-network-isolation-concept')
    ResourceTypes = $botType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $approved = @($p.privateEndpointConnections | Where-Object { $_ -and $_.properties.privateLinkServiceConnectionState.status -eq 'Approved' })
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; approvedPrivateEndpoints = $approved.Count }
        if ($p.publicNetworkAccess -ne 'Disabled') { return New-Fail "Public network access $(if ($p.publicNetworkAccess) { $p.publicNetworkAccess } else { 'Enabled (default)' })" $evidence }
        if (-not $approved) { return New-Fail 'Public network access disabled, but no approved private endpoint' $evidence }
        New-Pass 'Isolated: public network access disabled, reachable through a private endpoint' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BOT-002'
    Title         = 'Bot Service bots disable local authentication'
    Category      = 'Identity management'
    Service       = 'Azure AI Bot Service'
    Severity      = 'Medium'
    Description   = 'Checks Azure AI Bot Service bots for disabled local authentication, so that the bot and its channels authenticate with Microsoft Entra ID only.'
    Rationale     = 'Local authentication accepts channel keys and secrets that are not tied to an identity and are not covered by Conditional Access or sign-in logs.'
    Remediation   = 'Move the clients and channels to Microsoft Entra ID authentication, then disable local authentication on the bot.'
    References    = @('https://learn.microsoft.com/azure/bot-service/bot-service-resources-bot-framework-faq')
    ResourceTypes = $botType
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ disableLocalAuth = $Record.resource.properties.disableLocalAuth }
        if ($Record.resource.properties.disableLocalAuth -eq $true) { return New-Pass 'Local authentication disabled' $evidence }
        New-Fail 'Local authentication enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-BOT-003'
    Title         = 'Bot Service messaging endpoints use HTTPS'
    Category      = 'Data protection'
    Service       = 'Azure AI Bot Service'
    Severity      = 'Medium'
    Description   = 'Checks that the messaging endpoint of Azure AI Bot Service bots is an HTTPS URI.'
    Rationale     = 'The Bot Connector service sends every user message and the bearer token that authenticates it to the messaging endpoint. Over plain HTTP both can be read and changed on the way.'
    Remediation   = 'Serve the bot over HTTPS with a valid certificate and set the messaging endpoint to its https:// address.'
    References    = @('https://learn.microsoft.com/azure/bot-service/bot-builder-security-guidelines')
    ResourceTypes = $botType
    Evaluate      = {
        param($Record)
        $endpoint = [string]$Record.resource.properties.endpoint
        $evidence = [ordered]@{ endpoint = $endpoint }
        if (-not $endpoint) { return New-NotApplicable 'No messaging endpoint configured' $evidence }
        if ($endpoint -like 'https://*') { return New-Pass 'Messaging endpoint uses HTTPS' $evidence }
        New-Fail 'Messaging endpoint does not use HTTPS' $evidence
    }
}
