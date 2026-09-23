#Identity and privileged access: Azure RBAC, PIM and the Entra ID context of principals with access

$ownerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
$graphAppId = '00000003-0000-0000-c000-000000000000'

#Entra roles Microsoft labels privileged (can manage identities, credentials or tenant configuration)
$privilegedEntraRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator', 'Security Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'User Administrator', 'Authentication Administrator',
    'Conditional Access Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator',
    'Hybrid Identity Administrator', 'Domain Name Administrator', 'External Identity Provider Administrator',
    'Partner Tier2 Support', 'Authentication Policy Administrator', 'Groups Administrator'
)

#Microsoft Graph application permissions that allow taking over the tenant (Tier 0)
$tierZeroGraphRoles = @(
    'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All', 'Domain.ReadWrite.All',
    'EntitlementManagement.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Organization.ReadWrite.All',
    'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.PermissionGrant',
    'PrivilegedAccess.ReadWrite.AzureADGroup', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'RoleAssignmentSchedule.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagement.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.AzureADGroup',
    'RoleManagementPolicy.ReadWrite.Directory', 'User.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All'
)

function Get-AssignmentEvidence {
    param($Assignment)
    return [ordered]@{
        principal     = Get-PrincipalLabel $Assignment.properties.principalId
        principalType = $Assignment.properties.principalType
        role          = Get-RoleName $Assignment.properties.roleDefinitionId
        scope         = $Assignment.properties.scope
    }
}

function Get-EntraRoleName {
    param([string]$RoleDefinitionId)
    $definition = @(Get-IngestData 'identity/directoryRoleDefinitions') | Where-Object { $_ -and ($_.id -eq $RoleDefinitionId -or $_.templateId -eq $RoleDefinitionId) } | Select-Object -First 1
    if ($definition) { return $definition.displayName }
    return $RoleDefinitionId
}

Add-AzTest @{
    Id          = 'AZ-IAM-001'
    Title       = 'The subscription has between 2 and 3 owners'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'High'
    Description = 'Counts the principals assigned the Owner role directly on the subscription.'
    Rationale   = 'A single owner is a single point of failure for administration; more than three owners widens the group that can take full control of the subscription, including granting access to others.'
    Remediation = 'Keep two or three Owner assignments on the subscription, preferably PIM eligible groups. Remove extra owners (az role assignment delete --role Owner --assignee <principal> --scope /subscriptions/<id>) or add a second one.'
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = 'PA-1'; CIS = '5.7'; WAF = 'SE:05' }
    Defender    = @{ '6f90a6d6-d4d6-0794-0ec1-98fa77878c2e' = 'A maximum of 3 owners should be designated for subscriptions'; '2c79b4af-f830-b61e-92b9-63dfa30f16e4' = 'There should be more than one owner assigned to subscriptions' }
    Policy      = @{ '4f11b553-d42e-4e3a-89be-32ca364cad4c' = 'A maximum of 3 owners should be designated for your subscription'; '09024ccc-0c5f-475e-9457-b7c0d9ed487b' = 'There should be more than one owner assigned to your subscription' }
    Requires    = @('rbac/roleAssignments')
    Run         = {
        $scope = Get-SubscriptionScope
        $owners = @(Get-ActiveRoleAssignments | Where-Object { (Get-RoleDefinitionGuid $_.properties.roleDefinitionId) -eq $ownerRoleId })
        $direct = @($owners | Where-Object { $_.properties.scope -eq $scope } | ForEach-Object { $_.properties.principalId } | Sort-Object -Unique)
        $inherited = @($owners | Where-Object { (Get-ScopeLevel $_.properties.scope) -in 'root', 'managementGroup' } | ForEach-Object { $_.properties.principalId } | Sort-Object -Unique)
        $evidence = [ordered]@{ ownerCount = $direct.Count; owners = @($direct | ForEach-Object { Get-PrincipalLabel $_ } | Sort-Object); inheritedOwners = @($inherited | ForEach-Object { Get-PrincipalLabel $_ } | Sort-Object) }
        if ($direct.Count -lt 2) { return New-SubscriptionFinding (New-Fail "$($direct.Count) owner(s) assigned on the subscription, at least 2 are needed" $evidence) }
        if ($direct.Count -gt 3) { return New-SubscriptionFinding (New-Fail "$($direct.Count) owners assigned on the subscription, at most 3 are recommended" $evidence) }
        New-SubscriptionFinding (New-Pass "$($direct.Count) owners assigned on the subscription" $evidence)
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-002'
    Title       = 'Users and groups do not hold standing privileged role assignments'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'High'
    Description = 'Checks active assignments of Owner, Contributor, User Access Administrator, Role Based Access Control Administrator and custom roles that can assign roles, held by users or groups, for permanent (non PIM activated, non expiring) assignments.'
    Rationale   = 'Standing privileged access is available to an attacker the moment an account is compromised. Just-in-time activation through Privileged Identity Management limits the exposure window and adds MFA, justification and approval.'
    Remediation = 'Convert permanent privileged assignments for users and groups to PIM eligible assignments (Privileged Identity Management > Azure resources > Assignments > Update to eligible), and remove the permanent active assignment.'
    References  = @('https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles')
    Frameworks  = @{ MCSB = 'PA-2'; WAF = 'SE:05' }
    Requires    = @('rbac/roleAssignmentScheduleInstances')
    Run         = {
        $instances = @(Get-IngestData 'rbac/roleAssignmentScheduleInstances' | Where-Object { $_ -and $_.properties.principalType -in 'User', 'Group' -and (Test-RolePrivileged $_.properties.roleDefinitionId) })
        $seen = @{}
        $findings = foreach ($instance in $instances) {
            $p = $instance.properties
            $id = if ($p.originRoleAssignmentId) { $p.originRoleAssignmentId } else { $instance.id }
            if ($seen.ContainsKey($id.ToLowerInvariant())) { continue }
            $seen[$id.ToLowerInvariant()] = $true
            $evidence = [ordered]@{ principal = Get-PrincipalLabel $p.principalId; principalType = $p.principalType; role = Get-RoleName $p.roleDefinitionId; scope = $p.scope; assignmentType = $p.assignmentType; endDateTime = Format-UtcDate $p.endDateTime }
            $result = if ($p.assignmentType -eq 'Assigned' -and -not $p.endDateTime) { New-Fail "Permanent $($evidence.role) assignment for $($evidence.principal)" $evidence }
            elseif ($p.assignmentType -eq 'Activated') { New-Pass "Just-in-time activated $($evidence.role) assignment" $evidence }
            else { New-Pass "Time bound $($evidence.role) assignment ending $($evidence.endDateTime)" $evidence }
            New-Finding -ResourceId $id -ResourceType 'Microsoft.Authorization/roleAssignments' -ResourceName "$($evidence.role): $($evidence.principal)" -Result $result
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No active privileged role assignments for users or groups') }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-003'
    Title       = 'Workload identities do not hold privileged roles at subscription scope or above'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'High'
    Description = 'Finds service principals and managed identities with Owner, Contributor, User Access Administrator, Role Based Access Control Administrator or equivalent custom roles at tenant root, management group or subscription scope.'
    Rationale   = 'Workload identities cannot use MFA or PIM. A leaked credential, a compromised pipeline or a compromised resource with such an identity gives an attacker control over every resource in the subscription.'
    Remediation = 'Scope workload identity assignments to the resource groups or resources they manage and use the least privileged built-in role. Replace Owner/User Access Administrator with Role Based Access Control Administrator with conditions where the identity must assign roles.'
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = @('PA-7', 'IM-3'); WAF = 'SE:05' }
    Requires    = @('rbac/roleAssignments')
    Run         = {
        $assignments = @(Get-ActiveRoleAssignments | Where-Object { $_.properties.principalType -eq 'ServicePrincipal' -and (Test-RolePrivileged $_.properties.roleDefinitionId) })
        if (-not $assignments) { return New-SubscriptionFinding (New-Pass 'No privileged role assignments for workload identities') }
        foreach ($assignment in $assignments) {
            $evidence = Get-AssignmentEvidence $assignment
            $evidence.scopeLevel = Get-ScopeLevel $assignment.properties.scope
            $result = if ($evidence.scopeLevel -in 'root', 'managementGroup', 'subscription') { New-Fail "$($evidence.principal) has $($evidence.role) at $($evidence.scopeLevel) scope" $evidence } else { New-Pass "$($evidence.role) limited to $($evidence.scopeLevel) scope" $evidence }
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result $result
        }
    }
}

$guestTest = {
    param([bool]$WriteRoles)
    $findings = foreach ($assignment in (Get-ActiveRoleAssignments | Where-Object { $_.properties.principalType -in 'User', 'Group' })) {
        if ((Test-RoleCanWrite $assignment.properties.roleDefinitionId) -ne $WriteRoles) { continue }
        $evidence = Get-AssignmentEvidence $assignment
        #without the principals behind the assignment, "no guests" cannot be distinguished from "unknown"
        if (-not (Test-AssignmentUsersResolved $assignment)) {
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Unknown "The $($assignment.properties.principalType.ToLowerInvariant()) behind this assignment could not be resolved in the directory" $evidence)
            continue
        }
        $guests = @(Get-AssignmentUsers $assignment | Where-Object { Test-GuestUser $_ })
        if (-not $guests) { continue }
        $evidence.guests = @($guests | ForEach-Object { "$($_.displayName) ($($_.userPrincipalName))" } | Sort-Object -Unique)
        New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Fail "Guest account(s) $($evidence.guests -join ', ') hold $($evidence.role) on $($evidence.scope)" $evidence)
    }
    if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No guest accounts with such role assignments') }
    $findings
}

Add-AzTest @{
    Id          = 'AZ-IAM-004'
    Version     = 2
    Title       = 'Guest accounts do not have owner or write permissions'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'High'
    Description = 'Finds external (guest) users that hold a role with write, delete or action permissions, directly or through group membership.'
    Rationale   = 'Guest accounts are governed by another organization: their credential hygiene, MFA and offboarding are outside your control, and they are a common path for unmonitored access.'
    Remediation = 'Remove the role assignment or the guest from the group. Where external administration is required, use PIM eligible assignments with approval and access reviews, or Azure Lighthouse for managed service providers.'
    References  = @('https://learn.microsoft.com/entra/id-governance/manage-guest-access-with-access-reviews')
    Frameworks  = @{ MCSB = @('PA-4', 'PA-1'); CIS = '5.3.2'; WAF = 'SE:05' }
    Defender    = @{ '20606e75-05c4-48c0-9d97-add6daa2109a' = 'Guest accounts with owner permissions on Azure resources should be removed'; '0354476c-a12a-4fcc-a79d-f0ab7ffffdbb' = 'Guest accounts with write permissions on Azure resources should be removed' }
    Policy      = @{ '339353f6-2387-4a45-abe4-7f529d121046' = 'Guest accounts with owner permissions on Azure resources should be removed'; '94e1c2ac-cbbe-4cac-a2b5-389c812dee87' = 'Guest accounts with write permissions on Azure resources should be removed' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/directoryObjects', 'identity/users', 'identity/groups')
    Run         = { & $guestTest $true }
}

Add-AzTest @{
    Id          = 'AZ-IAM-005'
    Version     = 2
    Title       = 'Guest accounts do not have read permissions'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Medium'
    Description = 'Finds external (guest) users that hold read-only roles, directly or through group membership.'
    Rationale   = 'Read access exposes configuration, network layout and sometimes data to accounts managed by another organization, which helps attackers plan further steps.'
    Remediation = 'Remove guest read access that is no longer needed and review remaining guest access periodically with access reviews.'
    References  = @('https://learn.microsoft.com/entra/id-governance/manage-guest-access-with-access-reviews')
    Frameworks  = @{ MCSB = 'PA-4'; CIS = '5.3.2' }
    Defender    = @{ '422107c6-5b9a-46a6-bb1d-26ef1cc52d65' = 'Guest accounts with read permissions on Azure resources should be removed' }
    Policy      = @{ 'e9ac8f8e-ce22-4355-8f04-99b911d6be52' = 'Guest accounts with read permissions on Azure resources should be removed' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/directoryObjects', 'identity/users', 'identity/groups')
    Run         = { & $guestTest $false }
}

Add-AzTest @{
    Id          = 'AZ-IAM-006'
    Version     = 2
    Title       = 'Disabled accounts do not hold role assignments'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'High'
    Description = 'Finds disabled user accounts that still have Azure role assignments, directly or through group membership.'
    Rationale   = 'Access of disabled (often departed) users lingers until someone re-enables the account, which attackers and insiders abuse. Role assignments should follow the account lifecycle.'
    Remediation = 'Remove role assignments and group memberships of disabled accounts as part of the leaver process.'
    Frameworks  = @{ MCSB = @('PA-4', 'PA-3'); CIS = '5.3.5' }
    Defender    = @{ '050ac097-3dda-4d24-ab6d-82568e7a50cf' = 'Disabled accounts with owner permissions on Azure resources should be removed' }
    Policy      = @{ '0cfea604-3201-4e14-88fc-fae4c427a6c5' = 'Blocked accounts with owner permissions on Azure resources should be removed'; '8d7e1fde-fe26-4b5f-8108-f8e432cbc2be' = 'Blocked accounts with read and write permissions on Azure resources should be removed' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/users', 'identity/groups')
    Run         = {
        $findings = foreach ($assignment in (Get-ActiveRoleAssignments | Where-Object { $_.properties.principalType -in 'User', 'Group' })) {
            $evidence = Get-AssignmentEvidence $assignment
            if (-not (Test-AssignmentUsersResolved $assignment)) {
                New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Unknown "The $($assignment.properties.principalType.ToLowerInvariant()) behind this assignment could not be resolved in the directory" $evidence)
                continue
            }
            $disabled = @(Get-AssignmentUsers $assignment | Where-Object { $_.accountEnabled -eq $false })
            if (-not $disabled) { continue }
            $evidence.disabledUsers = @($disabled | ForEach-Object { "$($_.displayName) ($($_.userPrincipalName))" } | Sort-Object -Unique)
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Fail "Disabled account(s) $($evidence.disabledUsers -join ', ') hold $($evidence.role)" $evidence)
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No disabled accounts with role assignments') }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-007'
    Title       = 'No role assignments for deleted principals'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Low'
    Description = 'Finds active and eligible role assignments whose principal no longer exists in the directory ("Identity not found"). Soft deleted principals are named from the Entra recycle bin.'
    Rationale   = 'Orphaned assignments hide the real access picture, and a restored principal (within 30 days) silently regains its access.'
    Remediation = 'Delete the orphaned role assignments (Access control (IAM) > Role assignments, filter on Identity not found). Assignments inherited from the tenant root or a management group must be removed at that scope.'
    Frameworks  = @{ MCSB = @('PA-4', 'PA-3') }
    Requires    = @('rbac/roleAssignments', 'identity/directoryObjects', 'identity/unresolvedPrincipalIds')
    Run         = {
        $unresolved = @{}
        foreach ($id in @(Get-IngestData 'identity/unresolvedPrincipalIds')) { if ($id) { $unresolved[$id.ToLowerInvariant()] = $true } }
        $deleted = @{}
        foreach ($object in @(Get-IngestData 'identity/deletedPrincipals')) { if ($object) { $deleted[$object.id.ToLowerInvariant()] = $object } }
        $candidates = @(Get-ActiveRoleAssignments) + @(Get-IngestData 'rbac/roleEligibilitySchedules' | Where-Object { $_ })
        $findings = foreach ($assignment in $candidates) {
            $principalId = ([string]$assignment.properties.principalId).ToLowerInvariant()
            if (-not $unresolved.ContainsKey($principalId) -or $assignment.properties.principalType -eq 'ForeignGroup') { continue }
            $evidence = Get-AssignmentEvidence $assignment
            $evidence.kind = if ($assignment.type -match 'Eligibility') { 'eligible' } else { 'active' }
            $object = $deleted[$principalId]
            if ($object) {
                $evidence.deletedPrincipal = $object.displayName
                $evidence.deletedDateTime = Format-UtcDate $object.deletedDateTime
                $detail = "$($evidence.role) assignment for deleted principal $($object.displayName) (deleted $($evidence.deletedDateTime))"
            } else {
                $detail = "$($evidence.role) assignment for principal $principalId that no longer exists"
            }
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $principalId" -Result (New-Fail $detail $evidence)
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No role assignments for deleted principals') }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-008'
    Title       = 'No custom roles grant subscription administrator permissions'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Medium'
    Description = 'Checks custom role definitions for the wildcard action (*), which equals Owner.'
    Rationale   = 'Custom roles with all actions hide Owner level access behind an unfamiliar name, bypass reviews that focus on built-in privileged roles and violate least privilege.'
    Remediation = 'Replace wildcard custom roles with built-in roles or custom roles that list only the required actions, then delete the wildcard role.'
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/custom-roles')
    Frameworks  = @{ MCSB = 'PA-7'; CIS = '5.4' }
    Policy      = @{ 'a451c1ef-c6ca-483d-87ed-f49761e3ffb5' = 'Audit usage of custom RBAC roles' }
    Requires    = @('rbac/roleDefinitions')
    Run         = {
        $custom = @(Get-IngestData 'rbac/roleDefinitions' | Where-Object { $_ -and $_.properties.type -eq 'CustomRole' })
        if (-not $custom) { return New-SubscriptionFinding (New-Pass 'No custom role definitions') }
        foreach ($role in $custom) {
            $actions = @($role.properties.permissions | ForEach-Object { $_.actions } | Where-Object { $_ })
            $evidence = [ordered]@{ roleName = $role.properties.roleName; assignableScopes = @($role.properties.assignableScopes); wildcardActions = @($actions | Where-Object { $_ -eq '*' }) }
            $result = if ($actions -contains '*') { New-Fail "Custom role '$($role.properties.roleName)' allows all actions (*)" $evidence } else { New-Pass "Custom role '$($role.properties.roleName)' lists specific actions" $evidence }
            New-Finding -ResourceId $role.id -ResourceType $role.type -ResourceName $role.properties.roleName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-009'
    Title       = 'No privileged role assignments at tenant root scope'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Critical'
    Description = "Finds privileged role assignments (for example User Access Administrator created by 'Elevate access') at the tenant root scope '/', which apply to every subscription and management group."
    Rationale   = 'Root scope privileged access controls all Azure resources in the tenant. Elevated access is meant for break-glass situations and must be removed right after use.'
    Remediation = "Remove the assignment at '/' (a Global Administrator can remove elevated access under Entra ID > Properties > Access management for Azure resources). Assign roles at management group or subscription scope instead."
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin')
    Frameworks  = @{ MCSB = @('PA-1', 'PA-7'); CIS = '5.3.3'; WAF = 'SE:05' }
    Requires    = @('rbac/roleAssignments')
    Run         = {
        $root = @(Get-ActiveRoleAssignments | Where-Object { $_.properties.scope -eq '/' })
        $findings = foreach ($assignment in $root) {
            if (-not (Test-RolePrivileged $assignment.properties.roleDefinitionId)) { continue }
            $evidence = Get-AssignmentEvidence $assignment
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Fail "$($evidence.principal) has $($evidence.role) at tenant root scope" $evidence)
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass "No privileged role assignments at '/' ($($root.Count) non privileged)") }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-010'
    Title       = 'Subscription roles are assigned to groups rather than individual users'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Low'
    Description = 'Finds role assignments made directly to user accounts at subscription scope.'
    Rationale   = 'Direct user assignments are hard to review and are often forgotten when people change roles. Group based (and PIM for Groups) assignments make access reviews and lifecycle management manageable.'
    Remediation = 'Create role based groups, assign the role to the group and replace the direct user assignment by group membership.'
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = 'PA-7'; WAF = 'SE:05' }
    Requires    = @('rbac/roleAssignments')
    Run         = {
        $scope = Get-SubscriptionScope
        $direct = @(Get-ActiveRoleAssignments | Where-Object { $_.properties.scope -eq $scope -and $_.properties.principalType -eq 'User' })
        if (-not $direct) { return New-SubscriptionFinding (New-Pass 'No direct user assignments at subscription scope') }
        foreach ($assignment in $direct) {
            $evidence = Get-AssignmentEvidence $assignment
            New-Finding -ResourceId $assignment.id -ResourceType $assignment.type -ResourceName "$($evidence.role): $($evidence.principal)" -Result (New-Fail "$($evidence.role) assigned directly to $($evidence.principal)" $evidence)
        }
    }
}

function Get-RolePolicies {
    #effective PIM policy per role definition at subscription scope
    $roleIds = @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'b24988ac-6180-42a0-ab88-20f7382dd24c', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')
    $scope = Get-SubscriptionScope
    foreach ($assignment in @(Get-IngestData 'rbac/roleManagementPolicyAssignments' | Where-Object { $_ -and $_.properties.scope -eq $scope })) {
        $roleGuid = Get-RoleDefinitionGuid $assignment.properties.roleDefinitionId
        if ($roleGuid -notin $roleIds) { continue }
        [pscustomobject]@{ RoleId = $roleGuid; RoleName = Get-RoleName $assignment.properties.roleDefinitionId; Id = $assignment.id; Rules = @($assignment.properties.effectiveRules) }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-011'
    Title       = 'PIM activation of privileged roles requires MFA, justification and a short duration'
    Category    = 'Privileged access'
    Service     = 'Privileged Identity Management'
    Severity    = 'Medium'
    Description = 'Checks the Privileged Identity Management settings of Owner, Contributor, User Access Administrator and Role Based Access Control Administrator on the subscription: MFA (or an authentication context) and justification on activation, a maximum activation of 8 hours, and approval for Owner, User Access Administrator and Role Based Access Control Administrator.'
    Rationale   = 'Eligible assignments only reduce risk when activation is protected. Without MFA and approval, a stolen session can activate the role; long activations recreate standing access.'
    Remediation = 'In Privileged Identity Management > Azure resources > <subscription> > Settings, edit each role: require Azure MFA or a Conditional Access authentication context, require justification, set the maximum activation duration to 8 hours or less, and require approval for roles that can grant access.'
    References  = @('https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings')
    Frameworks  = @{ MCSB = @('PA-2', 'PA-6'); WAF = 'SE:05' }
    Requires    = @('rbac/roleManagementPolicyAssignments')
    Run         = {
        foreach ($policy in @(Get-RolePolicies)) {
            $rules = @{}
            foreach ($rule in $policy.Rules) { $rules[$rule.id] = $rule }
            $enablement = @($rules['Enablement_EndUser_Assignment'].enabledRules)
            $authContext = [bool]$rules['AuthenticationContext_EndUser_Assignment'].isEnabled
            $duration = ConvertFrom-IsoDuration $rules['Expiration_EndUser_Assignment'].maximumDuration
            $approval = [bool]$rules['Approval_EndUser_Assignment'].setting.isApprovalRequired
            $needsApproval = $policy.RoleId -ne 'b24988ac-6180-42a0-ab88-20f7382dd24c'
            $problems = @()
            if (-not ($enablement -contains 'MultiFactorAuthentication' -or $authContext)) { $problems += 'no MFA or authentication context' }
            if ($enablement -notcontains 'Justification') { $problems += 'no justification' }
            if (-not $duration -or $duration.TotalHours -gt 8) { $problems += "maximum activation $($rules['Expiration_EndUser_Assignment'].maximumDuration)" }
            if ($needsApproval -and -not $approval) { $problems += 'no approval' }
            $evidence = [ordered]@{ role = $policy.RoleName; activationRequirements = $enablement; authenticationContext = $authContext; maximumDuration = $rules['Expiration_EndUser_Assignment'].maximumDuration; approvalRequired = $approval }
            $result = if ($problems) { New-Fail "$($policy.RoleName) activation: $($problems -join ', ')" $evidence } else { New-Pass "$($policy.RoleName) activation is protected" $evidence }
            New-Finding -ResourceId $policy.Id -ResourceType 'Microsoft.Authorization/roleManagementPolicyAssignments' -ResourceName $policy.RoleName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-012'
    Title       = 'PIM does not allow permanent active assignment of privileged roles'
    Category    = 'Privileged access'
    Service     = 'Privileged Identity Management'
    Severity    = 'Medium'
    Description = "Checks that the PIM settings of Owner, Contributor, User Access Administrator and Role Based Access Control Administrator on the subscription require active assignments to expire."
    Rationale   = 'When permanent active assignment is allowed, administrators can bypass just-in-time activation and create standing privileged access.'
    Remediation = "In the PIM role settings, under Assignment, clear 'Allow permanent active assignment' and set an expiry (for example 15 days) for active assignments."
    References  = @('https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings')
    Frameworks  = @{ MCSB = 'PA-2' }
    Requires    = @('rbac/roleManagementPolicyAssignments')
    Run         = {
        foreach ($policy in @(Get-RolePolicies)) {
            $rule = $policy.Rules | Where-Object { $_.id -eq 'Expiration_Admin_Assignment' } | Select-Object -First 1
            $evidence = [ordered]@{ role = $policy.RoleName; isExpirationRequired = [bool]$rule.isExpirationRequired; maximumDuration = $rule.maximumDuration }
            $result = if ($rule.isExpirationRequired) { New-Pass "Active $($policy.RoleName) assignments expire after $($rule.maximumDuration)" $evidence } else { New-Fail "Permanent active $($policy.RoleName) assignments are allowed" $evidence }
            New-Finding -ResourceId $policy.Id -ResourceType 'Microsoft.Authorization/roleManagementPolicyAssignments' -ResourceName $policy.RoleName -Result $result
        }
    }
}

function Get-AzureWorkloadIdentities {
    #service principal records (servicePrincipals.json) of non managed identities that have Azure role assignments here
    $access = Get-PrincipalAccessMap
    foreach ($record in @(Get-IngestData 'identity/servicePrincipals' | Where-Object { $_ })) {
        $principal = Get-Principal $record.id
        if (-not $principal -or $principal.servicePrincipalType -eq 'ManagedIdentity') { continue }
        $assignments = $access[$record.id.ToLowerInvariant()]
        if (-not $assignments) { continue }
        [pscustomobject]@{ Record = $record; Principal = $principal; Assignments = @($assignments) }
    }
}

function Get-WorkloadCredentials {
    #active credentials of a service principal and its application
    param($Identity, [ValidateSet('password', 'key', 'all')][string]$Kind = 'all')
    $sources = @(@{ owner = 'servicePrincipal'; object = $Identity.Principal }, @{ owner = 'application'; object = $Identity.Record.application })
    foreach ($source in $sources) {
        if (-not $source.object) { continue }
        $types = switch ($Kind) { 'password' { @('passwordCredentials') } 'key' { @('keyCredentials') } default { @('passwordCredentials', 'keyCredentials') } }
        foreach ($type in $types) {
            foreach ($credential in @($source.object.$type | Where-Object { $_ })) {
                $end = ConvertTo-UtcDate $credential.endDateTime
                if ($end -and $end -le $script:Ingest.ReferenceTime) { continue }
                [pscustomobject]@{ Owner = $source.owner; Type = $type; Name = $credential.displayName; KeyId = $credential.keyId; Start = ConvertTo-UtcDate $credential.startDateTime; End = $end }
            }
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-013'
    Title       = 'Workload identities with Azure access do not use client secrets'
    Category    = 'Identity management'
    Service     = 'Microsoft Entra ID'
    Severity    = 'Medium'
    Description = 'Finds applications and service principals with Azure role assignments in this subscription that have active client secrets (password credentials).'
    Rationale   = 'Client secrets are bearer credentials that end up in configuration files, pipelines and scripts. Managed identities, workload identity federation or certificates remove or reduce that exposure.'
    Remediation = 'Replace the workload with a managed identity or workload identity federation where possible, otherwise use a certificate stored in Key Vault. Then remove the client secrets from the application and service principal.'
    References  = @('https://learn.microsoft.com/entra/workload-id/workload-identity-federation')
    Frameworks  = @{ MCSB = @('IM-3', 'IM-8'); WAF = 'SE:09' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/servicePrincipals', 'identity/directoryObjects', 'identity/groups')
    Run         = {
        $identities = @(Get-AzureWorkloadIdentities)
        if (-not $identities) { return New-SubscriptionFinding (New-Pass 'No application identities with Azure access') }
        foreach ($identity in $identities) {
            $secrets = @(Get-WorkloadCredentials -Identity $identity -Kind password)
            $evidence = [ordered]@{ appId = $identity.Principal.appId; roles = @($identity.Assignments | ForEach-Object { "$(Get-RoleName $_.properties.roleDefinitionId) @ $($_.properties.scope)" } | Sort-Object -Unique); activeSecrets = @($secrets | ForEach-Object { "$($_.Owner): $($_.Name) ($($_.KeyId)) expires $(Format-UtcDate $_.End)" } | Sort-Object) }
            $result = if ($secrets) { New-Fail "$($identity.Principal.displayName) has $($secrets.Count) active client secret(s)" $evidence } else { New-Pass "$($identity.Principal.displayName) has no client secrets" $evidence }
            New-Finding -ResourceId "/servicePrincipals/$($identity.Record.id)" -ResourceType 'Microsoft.Entra/servicePrincipals' -ResourceName $identity.Principal.displayName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-014'
    Title       = 'Workload identity certificates are valid for at most one year'
    Category    = 'Identity management'
    Service     = 'Microsoft Entra ID'
    Severity    = 'Medium'
    Description = 'Checks the lifetime of active certificate credentials of applications and service principals with Azure role assignments in this subscription (client secrets are covered by AZ-IAM-013).'
    Rationale   = 'Long lived certificates stay valid long after the private key leaks and discourage rotation. Short lifetimes force a working rotation process.'
    Remediation = 'Issue new certificates valid for 12 months or less, automate rotation (for example with Key Vault), remove the long lived certificates and consider an application management policy that limits credential lifetime.'
    References  = @('https://learn.microsoft.com/graph/api/resources/applicationauthenticationmethodpolicy')
    Frameworks  = @{ MCSB = @('IM-8', 'IM-3'); WAF = 'SE:09' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/servicePrincipals', 'identity/directoryObjects', 'identity/groups')
    Run         = {
        $identities = @(Get-AzureWorkloadIdentities)
        if (-not $identities) { return New-SubscriptionFinding (New-Pass 'No application identities with Azure access') }
        foreach ($identity in $identities) {
            $credentials = @(Get-WorkloadCredentials -Identity $identity -Kind key)
            $long = @($credentials | Where-Object { $_.Start -and $_.End -and ($_.End - $_.Start).TotalDays -gt 366 })
            $evidence = [ordered]@{ appId = $identity.Principal.appId; longLivedCertificates = @($long | ForEach-Object { "$($_.Owner): $($_.Name) ($($_.KeyId)) $([int]($_.End - $_.Start).TotalDays) days" } | Sort-Object) }
            $result = if ($long) { New-Fail "$($identity.Principal.displayName) has $($long.Count) certificate(s) valid for more than a year" $evidence } elseif ($credentials) { New-Pass 'All active certificates are valid for a year or less' $evidence } else { New-Pass 'No active certificates' $evidence }
            New-Finding -ResourceId "/servicePrincipals/$($identity.Record.id)" -ResourceType 'Microsoft.Entra/servicePrincipals' -ResourceName $identity.Principal.displayName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-015'
    Title       = 'Applications with privileged Azure roles have no owners'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'High'
    Description = 'Finds applications and service principals with privileged Azure roles that have owners.'
    Rationale   = 'Owners of an application or service principal can add credentials to it and sign in as it. Every owner therefore effectively holds the privileged Azure role of the application, usually without MFA, PIM or review.'
    Remediation = 'Remove owners from applications and service principals that hold privileged Azure access, and manage them through Entra roles (Application Administrator with PIM) or a restricted administrative unit instead.'
    References  = @('https://learn.microsoft.com/entra/identity/enterprise-apps/assign-app-owners')
    Frameworks  = @{ MCSB = @('PA-1', 'PA-7'); WAF = 'SE:05' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/servicePrincipals', 'identity/directoryObjects', 'identity/groups')
    Run         = {
        $identities = @(Get-AzureWorkloadIdentities | Where-Object { $_.Assignments | Where-Object { Test-RolePrivileged $_.properties.roleDefinitionId } })
        if (-not $identities) { return New-SubscriptionFinding (New-Pass 'No applications with privileged Azure roles') }
        foreach ($identity in $identities) {
            $owners = @($identity.Record.owners) + @($identity.Record.applicationOwners) | Where-Object { $_ }
            $evidence = [ordered]@{ appId = $identity.Principal.appId; privilegedRoles = @($identity.Assignments | Where-Object { Test-RolePrivileged $_.properties.roleDefinitionId } | ForEach-Object { "$(Get-RoleName $_.properties.roleDefinitionId) @ $($_.properties.scope)" } | Sort-Object -Unique); owners = @($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } } | Sort-Object -Unique) }
            $result = if ($owners) { New-Fail "$($identity.Principal.displayName) has $(@($evidence.owners).Count) owner(s) who can act as it" $evidence } else { New-Pass 'No owners' $evidence }
            New-Finding -ResourceId "/servicePrincipals/$($identity.Record.id)" -ResourceType 'Microsoft.Entra/servicePrincipals' -ResourceName $identity.Principal.displayName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-016'
    Version     = 2
    Title       = 'Identities used in this subscription do not hold tenant takeover (Tier 0) Graph permissions'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'Critical'
    Description = "Finds managed identities and service principals referenced by this subscription's resources or role assignments that hold Microsoft Graph permissions which allow taking over the Entra tenant, such as RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All or Application.ReadWrite.All. Both application permissions (app role assignments) and tenant wide delegated permissions (admin consented OAuth2 grants) are checked."
    Rationale   = 'Anyone who controls the Azure resource (code deployment, Run Command, Automation, a Contributor) can obtain tokens for its identity. Tier 0 Graph permissions on that identity turn an Azure compromise into a full tenant compromise. A delegated grant consented for all users is equally dangerous whenever the application can act in the context of an administrator.'
    Remediation = 'Remove the Tier 0 permissions or replace them with scoped alternatives (for example Sites.Selected, RBAC for applications, administrative units). Revoke tenant wide admin consent for delegated scopes that are not needed. Where they are unavoidable, run the workload in an isolated subscription with minimal administrators.'
    References  = @('https://learn.microsoft.com/graph/permissions-reference')
    Frameworks  = @{ MCSB = @('PA-7', 'PA-1'); WAF = 'SE:05' }
    Requires    = @('identity/servicePrincipals', 'identity/apiServicePrincipals')
    Run         = {
        $roleValues = @{}
        $graphServicePrincipalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($api in @(Get-IngestData 'identity/apiServicePrincipals' | Where-Object { $_ -and $_.appId -eq $graphAppId })) {
            $null = $graphServicePrincipalIds.Add([string]$api.id)
            foreach ($role in @($api.appRoles)) { $roleValues["$($api.id)|$($role.id)".ToLowerInvariant()] = $role.value }
        }
        foreach ($record in @(Get-IngestData 'identity/servicePrincipals' | Where-Object { $_ })) {
            $principal = Get-Principal $record.id
            $granted = @($record.appRoleAssignments | Where-Object { $_ } | ForEach-Object { $roleValues["$($_.resourceId)|$($_.appRoleId)".ToLowerInvariant()] } | Where-Object { $_ })
            #delegated scopes consented for the whole tenant (consentType AllPrincipals) apply to every signed-in user
            $delegated = @($record.oauth2PermissionGrants | Where-Object { $_ -and $_.consentType -eq 'AllPrincipals' -and $graphServicePrincipalIds.Contains([string]$_.resourceId) } |
                    ForEach-Object { ([string]$_.scope) -split '\s+' } | Where-Object { $_ })
            $tierZero = @($granted | Where-Object { $_ -in $tierZeroGraphRoles } | Sort-Object -Unique)
            $tierZeroDelegated = @($delegated | Where-Object { $_ -in $tierZeroGraphRoles } | Sort-Object -Unique)
            $name = if ($principal) { $principal.displayName } else { $record.id }
            $evidence = [ordered]@{ appId = $principal.appId; servicePrincipalType = $principal.servicePrincipalType; tierZeroPermissions = $tierZero; tierZeroDelegatedPermissions = $tierZeroDelegated; graphPermissions = @($granted | Sort-Object -Unique); delegatedGraphPermissions = @($delegated | Sort-Object -Unique) }
            $problems = @()
            if ($tierZero) { $problems += "application permission(s) $($tierZero -join ', ')" }
            if ($tierZeroDelegated) { $problems += "tenant wide delegated permission(s) $($tierZeroDelegated -join ', ')" }
            $result = if ($problems) { New-Fail "$name holds Tier 0 Graph $($problems -join ' and ')" $evidence } else { New-Pass "$name holds no Tier 0 Graph permissions" $evidence }
            New-Finding -ResourceId "/servicePrincipals/$($record.id)" -ResourceType 'Microsoft.Entra/servicePrincipals' -ResourceName $name -Result $result
        }
    }
}

function Get-EntraRoleAssignments {
    #active and eligible directory role assignments with their expanded principal
    foreach ($assignment in @(Get-IngestData 'identity/directoryRoleAssignments' | Where-Object { $_ })) { [pscustomobject]@{ Kind = 'active'; Assignment = $assignment } }
    foreach ($assignment in @(Get-IngestData 'identity/directoryRoleEligibilitySchedules' | Where-Object { $_ })) { [pscustomobject]@{ Kind = 'eligible'; Assignment = $assignment } }
}

Add-AzTest @{
    Id          = 'AZ-IAM-017'
    Title       = 'The tenant has between 2 and 4 Global Administrators'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'Medium'
    Description = 'Counts principals with an active or eligible Global Administrator assignment. Global Administrators can elevate themselves to User Access Administrator on every Azure subscription.'
    Rationale   = 'Microsoft recommends fewer than five Global Administrators, and at least two (including break-glass accounts) so the tenant cannot be locked out.'
    Remediation = 'Reduce Global Administrators to at most four by moving people to least privileged roles, and keep at least two cloud-only emergency access accounts.'
    References  = @('https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = 'PA-1' }
    Requires    = @('identity/directoryRoleAssignments')
    Run         = {
        $gaTemplate = '62e90394-69f5-4237-9190-012177145e10'
        $assignments = @(Get-EntraRoleAssignments | Where-Object { $_.Assignment.roleDefinitionId -eq $gaTemplate })
        $principals = @($assignments | ForEach-Object { "$($_.Assignment.principal.displayName) [$($_.Kind)]" } | Sort-Object -Unique)
        $count = @($assignments | ForEach-Object { $_.Assignment.principalId } | Sort-Object -Unique).Count
        $evidence = [ordered]@{ globalAdministratorCount = $count; globalAdministrators = $principals; eligibleDataCollected = (Test-IngestSection 'identity/directoryRoleEligibilitySchedules') }
        $result = if ($count -lt 2) { New-Fail "$count Global Administrator(s), at least 2 are needed" $evidence } elseif ($count -gt 4) { New-Fail "$count Global Administrators, fewer than 5 are recommended" $evidence } else { New-Pass "$count Global Administrators" $evidence }
        New-TenantFinding -Result $result -Suffix '/roles/GlobalAdministrator'
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-018'
    Title       = 'Privileged Entra roles are held by cloud-only member accounts'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'High'
    Description = 'Finds users with active or eligible privileged Entra roles that are synchronized from on-premises Active Directory or are guests.'
    Rationale   = 'A synchronized administrator can be taken over from on-premises (a compromised domain means a compromised cloud), and a guest administrator is governed by another organization. Privileged accounts should be cloud-only members.'
    Remediation = 'Create dedicated cloud-only administrator accounts, move the privileged roles to them (PIM eligible) and remove the roles from synchronized and guest accounts.'
    References  = @('https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = @('PA-1', 'IM-1') }
    Requires    = @('identity/directoryRoleAssignments', 'identity/directoryRoleDefinitions')
    Run         = {
        $findings = foreach ($item in @(Get-EntraRoleAssignments)) {
            $assignment = $item.Assignment
            $principal = $assignment.principal
            if ($principal.'@odata.type' -ne '#microsoft.graph.user') { continue }
            $role = Get-EntraRoleName $assignment.roleDefinitionId
            if ($role -notin $privilegedEntraRoles) { continue }
            $issues = @()
            if ($principal.onPremisesSyncEnabled) { $issues += 'synchronized from on-premises' }
            if (Test-GuestUser $principal) { $issues += 'guest' }
            $evidence = [ordered]@{ user = "$($principal.displayName) ($($principal.userPrincipalName))"; role = $role; kind = $item.Kind; onPremisesSyncEnabled = [bool]$principal.onPremisesSyncEnabled; userType = $principal.userType }
            $result = if ($issues) { New-Fail "$($evidence.user) holds $role ($($item.Kind)) but is $($issues -join ' and ')" $evidence } else { New-Pass "$($evidence.user) is a cloud-only member" $evidence }
            New-TenantFinding -Result $result -Suffix "/roleAssignments/$($item.Kind)/$($assignment.id)"
        }
        if (-not $findings) { return New-TenantFinding -Result (New-Pass 'No users with privileged Entra roles found') -Suffix '/roles/privileged' }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-019'
    Title       = 'Service principals do not hold privileged Entra roles'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'High'
    Description = 'Finds service principals and managed identities with active or eligible privileged Entra roles such as Global Administrator or Privileged Role Administrator.'
    Rationale   = 'Workload identities cannot be protected with MFA or Conditional Access for users. Anyone who obtains their credential, or controls the Azure resource of a managed identity, holds the directory role.'
    Remediation = 'Replace directory roles on workload identities with the specific Graph permissions or scoped (administrative unit) roles they need, and restrict who can manage those identities.'
    References  = @('https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices')
    Frameworks  = @{ MCSB = @('PA-1', 'PA-7') }
    Requires    = @('identity/directoryRoleAssignments', 'identity/directoryRoleDefinitions')
    Run         = {
        $findings = foreach ($item in @(Get-EntraRoleAssignments)) {
            $assignment = $item.Assignment
            if ($assignment.principal.'@odata.type' -ne '#microsoft.graph.servicePrincipal') { continue }
            $role = Get-EntraRoleName $assignment.roleDefinitionId
            if ($role -notin $privilegedEntraRoles) { continue }
            $evidence = [ordered]@{ servicePrincipal = $assignment.principal.displayName; appId = $assignment.principal.appId; servicePrincipalType = $assignment.principal.servicePrincipalType; role = $role; kind = $item.Kind }
            New-TenantFinding -Result (New-Fail "$($assignment.principal.displayName) holds $role ($($item.Kind))" $evidence) -Suffix "/roleAssignments/$($item.Kind)/$($assignment.id)"
        }
        if (-not $findings) { return New-TenantFinding -Result (New-Pass 'No service principals with privileged Entra roles') -Suffix '/roles/servicePrincipals' }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-020'
    Title       = 'Users with write access have signed in within 90 days'
    Category    = 'Privileged access'
    Service     = 'Microsoft Entra ID'
    Severity    = 'Medium'
    Description = 'Finds users that hold write capable Azure roles (directly or through groups) without a sign-in in the 90 days before ingestion.'
    Rationale   = 'Unused privileged access is pure risk: it is not needed by the business, is unlikely to be monitored and gives attackers dormant accounts to abuse.'
    Remediation = 'Remove the role assignments (or the group memberships) of inactive users, and schedule access reviews for privileged roles.'
    References  = @('https://learn.microsoft.com/entra/id-governance/access-reviews-overview')
    Frameworks  = @{ MCSB = @('PA-4', 'PA-3') }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/users', 'identity/groups')
    Run         = {
        if (-not $script:Ingest.Manifest.sections.'identity/users'.signInActivity) { return New-SubscriptionFinding (New-Unknown 'Sign-in activity was not collected (requires AuditLog.Read.All and Entra ID P1)') }
        $access = Get-PrincipalAccessMap
        foreach ($user in @(Get-IngestData 'identity/users' | Where-Object { $_ })) {
            $assignments = @($access[$user.id.ToLowerInvariant()] | Where-Object { $_ -and (Test-RoleCanWrite $_.properties.roleDefinitionId) })
            if (-not $assignments) { continue }
            $activity = $user.signInActivity
            $dates = @($activity.lastSignInDateTime, $activity.lastNonInteractiveSignInDateTime, $activity.lastSuccessfulSignInDateTime) | Where-Object { $_ } | ForEach-Object { ConvertTo-UtcDate $_ }
            $last = $dates | Sort-Object -Descending | Select-Object -First 1
            $evidence = [ordered]@{ user = $user.userPrincipalName; lastSignIn = Format-UtcDate $last; roles = @($assignments | ForEach-Object { "$(Get-RoleName $_.properties.roleDefinitionId) @ $($_.properties.scope)" } | Sort-Object -Unique) }
            $age = if ($last) { Get-AgeInDays $last } else { $null }
            $result = if (-not $last) { New-Fail "$($user.userPrincipalName) has write access but no recorded sign-in" $evidence } elseif ($age -gt 90) { New-Fail "$($user.userPrincipalName) last signed in $age days before ingestion" $evidence } else { New-Pass "$($user.userPrincipalName) signed in within 90 days" $evidence }
            New-Finding -ResourceId "/users/$($user.id)" -ResourceType 'Microsoft.Entra/users' -ResourceName $user.userPrincipalName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-021'
    Title       = 'Azure Lighthouse delegations do not grant standing write access'
    Category    = 'Privileged access'
    Service     = 'Azure Lighthouse'
    Severity    = 'Medium'
    Description = 'Checks Azure Lighthouse delegations of the subscription and its resource groups for permanent (non eligible) authorizations with write capable roles for the managing tenant.'
    Rationale   = 'Lighthouse gives principals in another tenant access that does not appear as regular role assignments. Standing write access by a provider extends the attack surface to that provider.'
    Remediation = 'Use eligible authorizations (just-in-time with MFA and approval) in the registration definition, limit roles to what the provider needs and remove delegations that are no longer used.'
    References  = @('https://learn.microsoft.com/azure/lighthouse/how-to/create-eligible-authorizations')
    Frameworks  = @{ MCSB = @('PA-7', 'PA-8') }
    Requires    = @('subscription/lighthouseRegistrationAssignments', 'rbac/roleDefinitions')
    Run         = {
        $assignments = @(Get-IngestData 'subscription/lighthouseRegistrationAssignments' | Where-Object { $_ })
        foreach ($group in (Get-ResourceGroupRecords)) { $assignments += @($group.lighthouseRegistrationAssignments | Where-Object { $_ }) }
        if (-not $assignments) { return New-SubscriptionFinding (New-Pass 'No Azure Lighthouse delegations') }
        foreach ($assignment in $assignments) {
            $definition = $assignment.properties.registrationDefinition.properties
            $writers = @($definition.authorizations | Where-Object { $_ -and (Test-RoleCanWrite $_.roleDefinitionId) })
            $evidence = [ordered]@{ managedByTenant = "$($definition.managedByTenantName) ($($definition.managedByTenantId))"; offer = $definition.registrationDefinitionName; standingWrite = @($writers | ForEach-Object { "$($_.principalIdDisplayName): $(Get-RoleName $_.roleDefinitionId)" } | Sort-Object); eligible = @($definition.eligibleAuthorizations | Where-Object { $_ } | ForEach-Object { "$($_.principalIdDisplayName): $(Get-RoleName $_.roleDefinitionId)" } | Sort-Object) }
            $result = if ($writers) { New-Fail "$($definition.managedByTenantName) has standing write access through $($writers.Count) authorization(s)" $evidence } else { New-Pass "$($definition.managedByTenantName) has no standing write access" $evidence }
            New-Finding -ResourceId $assignment.id -ResourceType 'Microsoft.ManagedServices/registrationAssignments' -ResourceName $definition.registrationDefinitionName -Result $result
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-022'
    Title       = 'Workload identity federation trusts only expected issuers'
    Category    = 'Identity management'
    Service     = 'Microsoft Entra ID'
    Severity    = 'High'
    Description = 'Checks the federated identity credentials of applications and user assigned managed identities with Azure access for wildcard subjects, and lists the external issuers and subjects that can obtain a token for them.'
    Rationale   = 'A federated credential lets anyone who can make the external identity provider issue a token with the configured subject sign in as the workload, without any secret. A wildcard or overly broad subject (for example any branch or any pull request of a repository) lets a fork or an untrusted contributor obtain that token.'
    Remediation = 'Pin each federated credential to one issuer and one exact subject (for example repo:org/repo:ref:refs/heads/main or repo:org/repo:environment:production), remove credentials for issuers you do not control, and prefer protected environments with required reviewers for deployment credentials.'
    References  = @('https://learn.microsoft.com/entra/workload-id/workload-identity-federation-considerations')
    Frameworks  = @{ MCSB = @('IM-3', 'IM-8'); WAF = 'SE:09' }
    Requires    = @('rbac/roleAssignments', 'rbac/roleDefinitions', 'identity/servicePrincipals', 'identity/directoryObjects', 'identity/groups')
    Run         = {
        $findings = @(foreach ($identity in (Get-AzureWorkloadIdentities)) {
            $credentials = @($identity.Record.applicationFederatedIdentityCredentials | Where-Object { $_ })
            if (-not $credentials) { continue }
            #'*' anywhere in the subject means the issuer decides who may sign in as this workload
            $broad = @($credentials | Where-Object { ([string]$_.subject) -match '\*' -or -not $_.subject } | ForEach-Object { "$($_.name): $($_.issuer) / $(if ($_.subject) { $_.subject } else { '(no subject)' })" } | Sort-Object)
            $evidence = [ordered]@{
                appId               = $identity.Principal.appId
                federatedCredentials = @($credentials | ForEach-Object { "$($_.name): $($_.issuer) / $($_.subject)" } | Sort-Object)
                broadSubjects       = $broad
                roles               = @($identity.Assignments | ForEach-Object { "$(Get-RoleName $_.properties.roleDefinitionId) @ $($_.properties.scope)" } | Sort-Object -Unique)
            }
            $result = if ($broad) { New-Fail "$($identity.Principal.displayName) has $($broad.Count) federated credential(s) with a wildcard or missing subject" $evidence } else { New-Pass "$($credentials.Count) federated credential(s), all pinned to an exact subject" $evidence }
            New-Finding -ResourceId "/servicePrincipals/$($identity.Record.id)" -ResourceType 'Microsoft.Entra/servicePrincipals' -ResourceName $identity.Principal.displayName -Result $result
        })
        #user assigned managed identities keep their federated credentials as an Azure child resource, not in the directory
        $findings += @(foreach ($record in (Get-AzResourceRecords -Type 'Microsoft.ManagedIdentity/userAssignedIdentities')) {
            if (-not (Test-ChildCollected $record 'federatedIdentityCredentials')) { New-Finding -Record $record -Result (New-Unknown 'Federated identity credentials could not be read'); continue }
            $credentials = @(Get-Child $record 'federatedIdentityCredentials' | Where-Object { $_ })
            if (-not $credentials) { continue }
            $broad = @($credentials | Where-Object { ([string]$_.properties.subject) -match '\*' -or -not $_.properties.subject } | ForEach-Object { "$($_.name): $($_.properties.issuer) / $(if ($_.properties.subject) { $_.properties.subject } else { '(no subject)' })" } | Sort-Object)
            $evidence = [ordered]@{
                clientId             = $record.resource.properties.clientId
                federatedCredentials = @($credentials | ForEach-Object { "$($_.name): $($_.properties.issuer) / $($_.properties.subject)" } | Sort-Object)
                broadSubjects        = $broad
            }
            $result = if ($broad) { New-Fail "$($record.resource.name) has $($broad.Count) federated credential(s) with a wildcard or missing subject" $evidence } else { New-Pass "$($credentials.Count) federated credential(s), all pinned to an exact subject" $evidence }
            New-Finding -Record $record -Result $result
        })
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'No workload identity federation configured for identities with Azure access') }
        $findings
    }
}

Add-AzTest @{
    Id          = 'AZ-IAM-023'
    Title       = 'Deny assignment exclusions are limited'
    Category    = 'Privileged access'
    Service     = 'Azure RBAC'
    Severity    = 'Medium'
    Description = 'Checks the deny assignments that apply to this subscription for excluded principals. Deny assignments are created by Azure managed applications, Blueprints and deployment stacks; principals on their exclude list keep the access that the deny assignment takes away from everyone else.'
    Rationale   = 'A deny assignment overrides role assignments, so access cannot be judged from role assignments alone. Every excluded principal is a standing exemption that no access review covers and that does not show up as a role assignment.'
    Remediation = 'Confirm that each excluded principal is the intended operator of the managed application, blueprint or deployment stack that owns the deny assignment, and remove the owning resource when it is no longer used.'
    References  = @('https://learn.microsoft.com/azure/role-based-access-control/deny-assignments')
    Frameworks  = @{ MCSB = @('PA-7', 'PA-4') }
    Requires    = @('rbac/denyAssignments')
    Run         = {
        $assignments = @(Get-IngestData 'rbac/denyAssignments' | Where-Object { $_ })
        if (-not $assignments) { return New-SubscriptionFinding (New-Pass 'No deny assignments apply to this subscription') }
        foreach ($assignment in $assignments) {
            $p = $assignment.properties
            $excluded = @($p.excludePrincipals | Where-Object { $_ } | ForEach-Object { Get-PrincipalLabel $_.id } | Sort-Object)
            $evidence = [ordered]@{
                displayName             = $p.denyAssignmentName
                scope                   = $p.scope
                isSystemProtected       = [bool]$p.isSystemProtected
                doNotApplyToChildScopes = [bool]$p.doNotApplyToChildScopes
                excludedPrincipals      = $excluded
                deniedActions           = @($p.permissions | ForEach-Object { $_.actions } | Where-Object { $_ } | Sort-Object -Unique)
            }
            $result = if ($excluded) {
                New-Fail "Deny assignment '$($p.denyAssignmentName)' excludes $($excluded.Count) principal(s): $($excluded -join ', ')" $evidence
            } else {
                New-Pass "Deny assignment '$($p.denyAssignmentName)' applies to everyone in scope" $evidence
            }
            New-Finding -ResourceId $assignment.id -ResourceType 'Microsoft.Authorization/denyAssignments' -ResourceName $p.denyAssignmentName -Result $result
        }
    }
}
