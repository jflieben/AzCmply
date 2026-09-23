#Governance: security baseline assignment, exemptions, locks and asset hygiene

$mcsbInitiatives = @{
    'e3ec7e09-768c-4b64-882c-fcada3772047' = 'Microsoft cloud security benchmark v2'
    '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' = 'Microsoft cloud security benchmark'
}

function Get-McsbAssignments {
    Get-PolicyAssignments | Where-Object { (($_.properties.policyDefinitionId -split '/')[-1]).ToLowerInvariant() -in $mcsbInitiatives.Keys }
}

Add-AzTest @{
    Id          = 'AZ-GOV-001'
    Title       = 'The Microsoft cloud security benchmark initiative is assigned'
    Category    = 'Posture and vulnerability management'
    Service     = 'Azure Policy'
    Severity    = 'Medium'
    Description = 'Checks that the Microsoft cloud security benchmark (v2 or v1) policy initiative is assigned to the subscription or an ancestor management group.'
    Rationale   = 'The benchmark initiative is the security baseline that Defender for Cloud uses for recommendations and secure score. Without it, misconfigurations are not measured continuously.'
    Remediation = 'Assign the Microsoft cloud security benchmark v2 initiative (e3ec7e09-768c-4b64-882c-fcada3772047) at the management group or subscription, or enable it as a standard in Defender for Cloud > Environment settings > Security policies.'
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/concept-regulatory-compliance-standards')
    Frameworks  = @{ MCSB = @('PV-1', 'PV-2'); CIS = '8.1.11'; WAF = 'SE:01'; ALZ = @('Deploy-MCSB2-Monitoring', 'Deploy-ASC-Monitoring') }
    Requires    = @('policy/policyAssignments')
    Run         = {
        $assignments = @(Get-McsbAssignments)
        $evidence = [ordered]@{ assignments = @($assignments | ForEach-Object { "$($mcsbInitiatives[(($_.properties.policyDefinitionId -split '/')[-1]).ToLowerInvariant()]) @ $($_.properties.scope)" } | Sort-Object) }
        if (-not $assignments) { return New-SubscriptionFinding (New-Fail 'The Microsoft cloud security benchmark initiative is not assigned' $evidence) }
        New-SubscriptionFinding (New-Pass "Assigned: $($evidence.assignments -join '; ')" $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-002'
    Title       = 'Microsoft cloud security benchmark policies are not disabled'
    Category    = 'Posture and vulnerability management'
    Service     = 'Azure Policy'
    Severity    = 'Medium'
    Description = "Lists effect parameters set to 'Disabled' in the Microsoft cloud security benchmark assignments."
    Rationale   = 'Disabling benchmark policies removes the corresponding recommendations from Defender for Cloud and the secure score, hiding misconfigurations instead of handling them.'
    Remediation = "Set the effect parameters back to their default (Audit/AuditIfNotExists). Handle justified deviations with policy exemptions that have an owner, reason and expiry date."
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/tutorial-security-policy')
    Frameworks  = @{ MCSB = 'PV-2'; CIS = '8.1.11' }
    Requires    = @('policy/policyAssignments')
    Run         = {
        $assignments = @(Get-McsbAssignments)
        if (-not $assignments) { return New-SubscriptionFinding (New-NotApplicable 'The benchmark initiative is not assigned (see AZ-GOV-001)') }
        foreach ($assignment in $assignments) {
            $disabled = @($assignment.properties.parameters.PSObject.Properties | Where-Object { $_.Value.value -eq 'Disabled' } | ForEach-Object Name | Sort-Object)
            $evidence = [ordered]@{ scope = $assignment.properties.scope; enforcementMode = $assignment.properties.enforcementMode; disabledParameters = $disabled }
            $result = if ($disabled) { New-Fail "$($disabled.Count) benchmark policy effect(s) set to Disabled" $evidence } else { New-Pass 'No benchmark policies disabled' $evidence }
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName $assignment.properties.displayName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-003'
    Title       = 'Policy waivers have an expiry date'
    Category    = 'Posture and vulnerability management'
    Service     = 'Azure Policy'
    Severity    = 'Low'
    Description = "Checks policy exemptions of category 'Waiver' for an expiry date."
    Rationale   = 'A waiver accepts a risk. Without an expiry date the accepted risk is never re-evaluated and exemptions accumulate silently.'
    Remediation = 'Set expiresOn on every waiver and review it before it expires; use the Mitigated category for exemptions that are covered by another control.'
    References  = @('https://learn.microsoft.com/azure/governance/policy/concepts/exemption-structure')
    Frameworks  = @{ MCSB = 'PV-2'; WAF = 'SE:01' }
    Requires    = @('policy/policyExemptions')
    Run         = {
        $waivers = @(Get-IngestData 'policy/policyExemptions' | Where-Object { $_ -and $_.properties.exemptionCategory -eq 'Waiver' })
        if (-not $waivers) { return New-SubscriptionFinding (New-Pass 'No policy waivers') }
        foreach ($waiver in $waivers) {
            $evidence = [ordered]@{ displayName = $waiver.properties.displayName; policyAssignmentId = $waiver.properties.policyAssignmentId; expiresOn = Format-UtcDate $waiver.properties.expiresOn }
            $result = if ($waiver.properties.expiresOn) { New-Pass "Waiver expires $($evidence.expiresOn)" $evidence } else { New-Fail 'Waiver without expiry date' $evidence }
            New-Finding -ResourceId $waiver.id -ResourceType $waiver.type -ResourceName $waiver.properties.displayName -Result $result
        }
    }
}

#CIS 9.3.9 and 9.3.10 are storage specific, so storage accounts have their own lock tests (AZ-STG-025, AZ-STG-026)
#and this one covers the remaining recovery critical types under the generic CIS 6.2
Add-AzTest @{
    Id            = 'AZ-GOV-004'
    Version       = 2
    Title         = 'Critical data and recovery resources have a delete lock'
    Category      = 'Backup and recovery'
    Service       = 'Azure Resource Manager'
    Severity      = 'Medium'
    Description   = 'Checks key vaults, Recovery Services vaults and Backup vaults for a CanNotDelete or ReadOnly lock on the resource, its resource group or the subscription. Storage accounts are covered by AZ-STG-025.'
    Rationale     = 'Locks prevent accidental or malicious deletion of resources whose loss destroys data, keys or backups. Deleting a lock needs Microsoft.Authorization/locks/delete, which most operators do not hold.'
    Remediation   = 'Add a CanNotDelete lock (az lock create --lock-type CanNotDelete --name DoNotDelete --resource <id>) and restrict lock administration to a dedicated role.'
    References    = @('https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources')
    Frameworks    = @{ MCSB = @('BR-2', 'AM-3'); CIS = '6.2' }
    Requires      = @('subscription/locks')
    ResourceTypes = @('Microsoft.KeyVault/vaults', 'Microsoft.RecoveryServices/vaults', 'Microsoft.DataProtection/backupVaults')
    Evaluate      = {
        param($Record)
        $locks = @(Get-EffectiveLocks $Record.id)
        $evidence = [ordered]@{ locks = @($locks | ForEach-Object { "$($_.properties.level) @ $($_.id -replace '(?i)/providers/Microsoft\.Authorization/locks/.*$', '')" } | Sort-Object) }
        if ($locks) { return New-Pass "Locked ($($locks[0].properties.level))" $evidence }
        New-Fail 'No delete lock on the resource, resource group or subscription' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-005'
    Title       = 'A custom role for administering resource locks exists'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Low'
    Description = 'Checks for a custom role that grants Microsoft.Authorization/locks permissions, so lock administration can be delegated without Owner or User Access Administrator.'
    Rationale   = 'Only Owner and User Access Administrator can manage locks by default. A dedicated role lets a small group manage locks while keeping them out of reach of everyone else.'
    Remediation = "Create a custom role with Microsoft.Authorization/locks/* and assign it (PIM eligible) to the team responsible for locks."
    References  = @('https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources')
    Frameworks  = @{ MCSB = 'PA-7'; CIS = '5.5' }
    Requires    = @('rbac/roleDefinitions')
    Run         = {
        $roles = @(Get-IngestData 'rbac/roleDefinitions' | Where-Object { $_ -and $_.properties.type -eq 'CustomRole' -and (@($_.properties.permissions | ForEach-Object { $_.actions }) | Where-Object { $_ -like 'Microsoft.Authorization/locks/*' }) })
        $evidence = [ordered]@{ lockRoles = @($roles | ForEach-Object { $_.properties.roleName } | Sort-Object) }
        if ($roles) { return New-SubscriptionFinding (New-Pass "Lock administrator role(s): $($evidence.lockRoles -join ', ')" $evidence) }
        New-SubscriptionFinding (New-Fail 'No custom role for administering resource locks' $evidence)
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-006'
    Title         = 'No unattached managed disks'
    Category      = 'Asset management'
    Service       = 'Compute'
    Severity      = 'Low'
    Description   = 'Finds managed disks that are not attached to any virtual machine.'
    Rationale     = 'Orphaned disks keep copies of data (often including credentials and system state) outside of any lifecycle, monitoring or backup process.'
    Remediation   = 'Delete disks that are no longer needed, after checking whether they must be retained; snapshot them to a governed location if retention is required.'
    Frameworks    = @{ MCSB = 'AM-3'; ALZ = 'Audit-UnusedResources' }
    ResourceTypes = @('Microsoft.Compute/disks')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ diskState = $Record.resource.properties.diskState; managedBy = $Record.resource.managedBy }
        if ($Record.resource.properties.diskState -eq 'Unattached') { return New-Fail 'Disk is not attached to a virtual machine' $evidence }
        New-Pass "Disk state $($Record.resource.properties.diskState)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-007'
    Title         = 'No unassociated public IP addresses'
    Category      = 'Asset management'
    Service       = 'Networking'
    Severity      = 'Low'
    Description   = 'Finds public IP addresses that are not associated with a network interface, load balancer, gateway or NAT gateway.'
    Rationale     = 'Unused public IP addresses are forgotten attack surface: they are easily re-associated with a resource, and DNS records pointing to them can be abused.'
    Remediation   = 'Delete public IP addresses that are not in use and remove DNS records that point to them.'
    Frameworks    = @{ MCSB = @('AM-3', 'NS-1'); CIS = '7.7'; ALZ = 'Audit-UnusedResources' }
    ResourceTypes = @('Microsoft.Network/publicIPAddresses')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ ipAddress = $p.ipAddress; associatedWith = if ($p.ipConfiguration) { $p.ipConfiguration.id } elseif ($p.natGateway) { $p.natGateway.id } else { $null } }
        if ($evidence.associatedWith) { return New-Pass 'Associated' $evidence }
        New-Fail 'Public IP address is not associated with any resource' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-008'
    Version     = 2
    Title       = 'No retired or classic services are in use'
    Category    = 'Asset management'
    Service     = 'Azure Resource Manager'
    Severity    = 'Medium'
    Description = 'Finds classic (ASM) resources and resource types whose service is retired or has a published retirement date: Azure Database for PostgreSQL single server, Azure Database for MySQL single server, Azure Database for MariaDB and Azure Blueprints (retires 31 January 2027).'
    Rationale   = 'Retired services no longer receive security updates or support, and classic resources lack Azure Resource Manager RBAC, policy and logging controls. A service with a published retirement date needs a migration plan before the deadline, not after.'
    Remediation = 'Migrate to the supported successor (Azure Resource Manager resources, PostgreSQL or MySQL flexible server, deployment stacks and template specs for blueprints) and delete the retired resources.'
    References  = @('https://learn.microsoft.com/azure/postgresql/migrate/whats-happening-to-postgresql-single-server', 'https://learn.microsoft.com/azure/governance/blueprints/blueprint-retirement')
    Frameworks  = @{ MCSB = @('AM-2', 'PV-6'); ALZ = 'Deny-Classic-Resources' }
    Requires    = @('subscription/resources')
    Run         = {
        #resource type -> why it is on the list, so the finding says what is actually wrong
        $retiredTypes = [ordered]@{
            'Microsoft.DBforPostgreSQL/servers'   = 'Azure Database for PostgreSQL single server is retired'
            'Microsoft.DBforMySQL/servers'        = 'Azure Database for MySQL single server is retired'
            'Microsoft.DBforMariaDB/servers'      = 'Azure Database for MariaDB is retired'
            'Microsoft.Blueprint/blueprintAssignments' = 'Azure Blueprints is deprecated and retires on 31 January 2027'
        }
        $resources = @(Get-IngestData 'subscription/resources' | Where-Object { $_ })
        $retired = @($resources | Where-Object { $_.type -match '^Microsoft\.Classic' -or $retiredTypes.Contains([string]$_.type) })
        foreach ($resource in $retired) {
            $reason = if ($retiredTypes.Contains([string]$resource.type)) { $retiredTypes[[string]$resource.type] } else { "$($resource.type) is a classic (ASM) resource type" }
            New-Finding -ResourceId $resource.id -ResourceType $resource.type -Result (New-Fail $reason ([ordered]@{ type = $resource.type; location = $resource.location }))
        }
        #blueprint assignments are not in the resource list; the call 404s when the provider is not registered,
        #which is a legitimate "none" rather than a collection failure, so it is reported separately
        $blueprintScope = "$(Get-SubscriptionScope)/providers/Microsoft.Blueprint/blueprintAssignments"
        if (-not (Test-IngestSection 'subscription/blueprintAssignments')) {
            New-Finding -ResourceId $blueprintScope -ResourceType 'Microsoft.Blueprint/blueprintAssignments' -ResourceName 'blueprintAssignments' -Result (New-Unknown 'Blueprint assignments could not be read, so their retirement could not be checked')
        } else {
            foreach ($blueprint in @(Get-IngestData 'subscription/blueprintAssignments' | Where-Object { $_ })) {
                New-Finding -ResourceId ([string]$blueprint.id) -ResourceType 'Microsoft.Blueprint/blueprintAssignments' -Result (New-Fail $retiredTypes['Microsoft.Blueprint/blueprintAssignments'] ([ordered]@{ blueprintId = $blueprint.properties.blueprintId }))
            }
        }
        if (-not $retired) { New-SubscriptionFinding (New-Pass 'No retired or classic resource types') }
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-009'
    Title       = 'Resources comply with the Azure Policy definitions assigned to them'
    Category    = 'Posture and vulnerability management'
    Service     = 'Azure Policy'
    Severity    = 'Medium'
    Description = 'Reads the per resource policy compliance states from Azure Resource Graph and reports one finding per policy definition that has non-compliant resources. This measures the outcome of the assigned policies, where AZ-GOV-001 and AZ-GOV-002 only check that the benchmark initiative is assigned and not disabled.'
    Rationale   = 'An assigned policy only improves security once resources actually comply with it. Non-compliant resources are the concrete deviations from the baseline the organization committed to.'
    Remediation = 'Work through the non-compliant resources per definition in Policy > Compliance, remediate them (deployIfNotExists policies can be remediated in bulk with a remediation task), and record accepted deviations as policy exemptions with an owner and expiry date.'
    References  = @('https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data')
    Frameworks  = @{ MCSB = @('PV-2', 'PV-1'); WAF = 'SE:01' }
    Requires    = @('resourceGraph/policyresources')
    Run         = {
        $states = @(Get-IngestData 'resourceGraph/policyresources' | Where-Object { $_ -and $_.type -eq 'microsoft.policyinsights/policystates' })
        if (-not $states) { return New-SubscriptionFinding (New-NotApplicable 'Azure Resource Graph returned no policy compliance states') }
        #policy states carry the definition id only, so resolve the display name to keep findings readable
        $definitionNames = @{}
        foreach ($definition in @(Get-IngestData 'policy/policyDefinitions' | Where-Object { $_ })) {
            if ($definition.id -and $definition.properties.displayName) { $definitionNames[([string]$definition.id).ToLowerInvariant()] = [string]$definition.properties.displayName }
        }
        $byDefinition = @{}
        foreach ($state in $states) {
            $key = [string]$state.properties.policyDefinitionId
            if (-not $key) { continue }
            if (-not $byDefinition.ContainsKey($key)) { $byDefinition[$key] = [pscustomobject]@{ Compliant = 0; NonCompliant = 0; Assignment = $state.properties.policyAssignmentName; Resources = [System.Collections.Generic.List[string]]::new() } }
            if ($state.properties.complianceState -eq 'NonCompliant') {
                $byDefinition[$key].NonCompliant++
                if ($byDefinition[$key].Resources.Count -lt 20) { $byDefinition[$key].Resources.Add([string]$state.properties.resourceId) }
            } elseif ($state.properties.complianceState -eq 'Compliant') { $byDefinition[$key].Compliant++ }
        }
        foreach ($key in ($byDefinition.Keys | Sort-Object)) {
            $item = $byDefinition[$key]
            if ($item.NonCompliant -eq 0 -and $item.Compliant -eq 0) { continue }
            $name = $definitionNames[$key.ToLowerInvariant()]
            if (-not $name) { $name = Get-ResourceName $key }
            $evidence = [ordered]@{ policyDefinitionId = $key; policyAssignment = $item.Assignment; nonCompliantResources = $item.NonCompliant; compliantResources = $item.Compliant; examples = @($item.Resources | Sort-Object) }
            $result = if ($item.NonCompliant) { New-Fail "$($item.NonCompliant) of $($item.NonCompliant + $item.Compliant) resources do not comply with '$name'" $evidence } else { New-Pass "All $($item.Compliant) evaluated resources comply with '$name'" $evidence }
            New-Finding -ResourceId $key -ResourceType 'Microsoft.Authorization/policyDefinitions' -ResourceName $name -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-010'
    Title       = 'Azure Advisor security recommendations are resolved'
    Category    = 'Posture and vulnerability management'
    Service     = 'Azure Advisor'
    Severity    = 'Medium'
    Description = 'Reads the Azure Advisor recommendations of category Security from Azure Resource Graph and reports one finding per open recommendation. Advisor surfaces Defender for Cloud recommendations plus platform advice that the other tests here do not cover.'
    Rationale   = 'Advisor security recommendations are the platform telling you about concrete, already detected weaknesses in this subscription. Leaving them open means known issues stay unfixed.'
    Remediation = 'Work through the recommendations in Advisor > Security, remediate or dismiss each one with a reason, and treat high impact recommendations first.'
    References  = @('https://learn.microsoft.com/azure/advisor/advisor-security-recommendations')
    Frameworks  = @{ MCSB = @('PV-2', 'PV-5'); WAF = 'SE:01' }
    Requires    = @('resourceGraph/advisorresources')
    Run         = {
        $recommendations = @(Get-IngestData 'resourceGraph/advisorresources' | Where-Object { $_ -and $_.type -eq 'microsoft.advisor/recommendations' -and $_.properties.category -eq 'Security' })
        if (-not $recommendations) { return New-SubscriptionFinding (New-Pass 'Azure Advisor reports no open security recommendations') }
        foreach ($recommendation in $recommendations) {
            $p = $recommendation.properties
            $evidence = [ordered]@{ impact = $p.impact; impactedField = $p.impactedField; impactedValue = $p.impactedValue; problem = $p.shortDescription.problem; solution = $p.shortDescription.solution }
            New-Finding -ResourceId ([string]$recommendation.id) -ResourceType 'Microsoft.Advisor/recommendations' -ResourceName ([string]$p.shortDescription.problem) -Result (New-Fail "$($p.impact) impact: $($p.shortDescription.problem) ($($p.impactedValue))" $evidence)
        }
    }
}
