# Azure subscription ingest

`Invoke-AzureIngest.ps1` collects everything security relevant about one Azure subscription into a folder of JSON files. It uses REST only (PowerShell 7.2+, no modules) and read operations only.

## Usage

```powershell
# service principal with secret
.\Invoke-AzureIngest.ps1 -SubscriptionId <sub> -TenantId <tenant> -ClientId <appId> -ClientSecret (Read-Host -AsSecureString)

# certificate from the CurrentUser/LocalMachine My store, or a .pfx/.pem file
.\Invoke-AzureIngest.ps1 -SubscriptionId <sub> -TenantId <tenant> -ClientId <appId> -CertificateThumbprint <thumbprint>
.\Invoke-AzureIngest.ps1 -SubscriptionId <sub> -TenantId <tenant> -ClientId <appId> -CertificatePath .\app.pfx -CertificatePassword $pw

# managed identity (VM, App Service, Functions, Automation, Container Apps, Arc); add -ClientId for a user assigned identity
.\Invoke-AzureIngest.ps1 -SubscriptionId <sub> -ManagedIdentity
```

| Output parameter | Default | |
|---|---|---|
| `-OutputPath` | `.\AzureIngest` | Folder in which the run folder is created |
| `-FolderName` | `<subscriptionId>_<yyyyMMdd-HHmmss>` | Run folder name; must not exist or be empty |
| `-Compress` | off | Replace the run folder by `<run folder>.zip` |
| `-CompactJson` | off | No indentation |

Other: `-ActivityLogDays` (0-90, default 90), `-SkipGraph`, `-SkipResourceGraph`, `-ThrottleLimit` (default 8), `-Environment` (AzureCloud, AzureUSGovernment, AzureChinaCloud).

The script returns `{ Path, Resources, FailedRequests }`.

## Permissions

- Azure: **Reader** on the subscription.
- Graph application permissions: **Directory.Read.All**. Optional: **RoleManagement.Read.Directory** (eligible directory roles), **AuditLog.Read.All** (user sign-in activity), **Policy.Read.All** (Conditional Access policies and security defaults).

Missing permissions do not stop the run. Each failed call is listed in `failures.json` and the affected section is marked in `manifest.json`.

## Output

```
manifest.json          run metadata, caller identity, counts, status per section, failure totals
failures.json          every failed request: category, statusCode, errorCode, message, uri, context
index.json             one entry per resource group and resource: id, type, file, apiVersion, status
subscription/          subscription, subscriptionPolicies (tenant transfer policy), providers, resourceGroups, resources (list), locks, deployments,
                       deploymentStacks, Lighthouse, blueprints, activity log diagnostic settings, budgets, serialConsole, ...
rbac/                  roleAssignments, roleDefinitions, denyAssignments, PIM schedules/instances/requests,
                       roleManagementPolicies (+Assignments)
policy/                policyAssignments, policyDefinitions, policySetDefinitions, policyExemptions, policyStatesSummary, attestations, remediations
defender/              pricings, securityContacts, settings, assessments, secureScores, alerts, JIT policies, securityConnectors,
                       governanceRules, alertsSuppressionRules, apiCollections, regulatoryComplianceStandards, securityStandards, ...
resourceGroups/        per resource group: deployments, deploymentStacks, lighthouseRegistrationAssignments
resources/<Namespace>/<type>/<name>_<hash>.json
resourceGraph/<table>.json   Azure Resource Graph rows scoped to the subscription
activityLog/activityLog.json
identity/              directoryObjects, users, groups, servicePrincipals, apiServicePrincipals,
                       directoryRole*, conditionalAccessPolicies, conditionalAccessExcludedGroups, securityDefaults,
                       unresolvedPrincipalIds, organization
```

Collections are JSON arrays of the raw API objects. Values are written exactly as returned (no date conversion).

A resource file:

```jsonc
{
  "id": "...", "type": "...", "apiVersion": "2025-01-01", "collectedAt": "...",
  "resource": { },                 // full GET at the latest stable API version (VMs and scale sets add $expand=userData)
  "diagnosticSettings": [ ],       // null when the type does not support them
  "children": { "firewallRules": [ ], "config/web": { } },   // see $childResourceMap
  "textContent": { "content": "..." },                        // e.g. runbook source
  "failures": [ { "path": "...", "statusCode": 404, "errorCode": "..." } ]
}
```

A child that is `null` failed or is not configured (e.g. Sentinel not enabled); its reason is in `failures`. An empty array means the call succeeded and nothing exists.

Graph files: `groups.json` holds per group `transitiveMembers`, `owners` and `properties` (role-assignable, dynamic membership, on-premises sync). `servicePrincipals.json` holds per service principal its `appRoleAssignments` (API permissions), `oauth2PermissionGrants`, `owners`, backing `application` with credentials, `applicationOwners` and `applicationFederatedIdentityCredentials`. `apiServicePrincipals.json` resolves app role ids to names. `conditionalAccessExcludedGroups.json` holds the user members of every group a Conditional Access policy excludes (`members`, or `membersError` with the status code). `unresolvedPrincipalIds.json` lists referenced ids that no longer exist (orphaned assignments) or belong to other tenants.

## Notes

- The output can contain sensitive values: deployment parameters and outputs, unencrypted automation variables, runbook source, container environment variables, logic app definitions.
- Not collected: anything needing more than Reader (list keys, app settings, connection strings, effective NSG rules) and data plane content.
- A `subscriptionEndpoints` path that starts with `/` is read from the root (tenant level, e.g. the subscription transfer policy) instead of below the subscription.
- To collect more, add paths to `$childResourceMap` (`'path'`, `'path@apiVersion'` or `'collection/*/child'`) or rows to `$subscriptionEndpoints`.
