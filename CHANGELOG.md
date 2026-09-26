# Changelog

## 1.0.3

### Added
- Seven App Service and Azure Functions tests (308 in total): a supported language runtime, failing from 90 days before
  its end of life, looked up in the App Service runtime catalog (AZ-APP-012), access restrictions that trust shared
  service tags (AZ-APP-013), App Service authentication that accepts identities of other tenants or social accounts
  (AZ-APP-014), principals that can take a function app over through the storage it runs from (AZ-FUNC-001), Flex
  Consumption apps that read their deployment package with a storage key (AZ-FUNC-002), functions that anyone can call
  while the app has write access in Azure (AZ-FUNC-003) and HTTP functions protected by a function key alone
  (AZ-FUNC-004).
- AzCmply Custom 2026.09.3: AZC-13, only those who can change a function app can change the storage it runs from.
  AZC-11 now covers workloads (functions next to workflows) and AZC-01 access restrictions of App Service.
- Ingestion: the App Service runtime catalogs (`web/functionAppStacks.json`, `web/webAppStacks.json`).
- Contributing on GitHub: issue forms (bug report, wrong test result, new test or framework mapping, feature request), a
  pull request template, `CONTRIBUTING.md`, `SECURITY.md`, the self-test as a workflow on every push and pull request,
  and Dependabot updates for the workflow actions.

### Fixed
- AZ-APP-009 (version 3) counted App Service authentication as enforced when it requires sign-in with the action
  AllowAnonymous, which passes unauthenticated requests to the function.

## 1.0.2

### Added
- Ten Logic App tests (301 in total), for Consumption workflows and API connections: request triggers callable from any
  address with their signed URL (AZ-LOGIC-001), such workflows with write access in Azure (AZ-LOGIC-002), HTTP steps
  that sign in with passwords, certificates, keys or credential headers instead of a managed identity or service
  principal (AZ-LOGIC-003), Key Vault secrets, tokens and credentials visible in run history (AZ-LOGIC-004), API
  connections that sign in as a user (AZ-LOGIC-005) or store a shared secret (AZ-LOGIC-006), connections in error
  (AZ-LOGIC-007) or not used by any workflow (AZ-LOGIC-008), runs and triggers that keep failing (AZ-LOGIC-009) and
  workflows without runs for 75 days (AZ-LOGIC-010).
- AzCmply Custom 2026.09.2: AZC-11, workflows that anyone can call have no write access in Azure, and AZC-12, workflows
  do not keep failing unnoticed.
- Ingestion: daily run metrics of Logic App workflows over the 75 days before the run (child `metrics`), and the
  connector metadata of API connections (`web/managedApis.json`).

### Changed
- AZ-SEC-003 (version 3) also finds passwords, certificates, credential headers and URL keys written as plain values in
  the HTTP steps of Logic App definitions, and plain secret defaults of their parameters.

### Fixed
- The SAS signature pattern of the secret scans missed most Logic App callback URLs (base64url signatures); a function
  key in a URL is now found as well. AZ-SEC-001, AZ-SEC-002 and AZ-SEC-004 have a new version for this.

## 1.0.1

### Added
- Domain controllers on virtual machines without Tier 0 protection: AZ-VM-015 (High) for likely, AZ-VM-016
  (Informational) for possible domain controllers. Detection is best effort from Azure configuration: DNS server of a
  virtual network, network interface, Azure Firewall or DNS forwarding rule, network security group rules for Kerberos,
  global catalog or AD Web Services, AD DS promotion in userData, custom data or extension settings, and the machine
  name. Tier 0 protection: no role that can take the machine over is delegated on a subscription or resource group
  shared with other workloads, held by a workload identity, or held permanently instead of through PIM.
- AzCmply Custom 2026.09.1: control AZC-10, only Tier 0 administrators can take over domain controllers on virtual
  machines through Azure.
- Ingestion: added forwarding rules of DNS forwarding rulesets.

### Fixed
- Test counts per area and severity in the analyzer README.

## 1.0.0

### Added
- 21 tests: security defaults (AZ-IAM-026), MFA for all users on all resources (AZ-IAM-027), an
  emergency access account outside Conditional Access (AZ-IAM-028), subscription transfer policy (AZ-GOV-011),
  autoscale (AZ-GOV-012), resource and resource group region (AZ-GOV-013), masking of classified SQL columns
  (AZ-SQL-010), Change Tracking and Inventory (AZ-VM-013), Azure Virtual Desktop public access (AZ-AVD-001), Bot
  Service isolation, local authentication and HTTPS endpoint (AZ-BOT-001 to 003), Data Explorer public access, disk
  and double encryption (AZ-ADX-001 to 003), Azure Firewall rule logs (AZ-NET-024), DNS query logging (AZ-NET-025), an alert on deleted diagnostic settings (AZ-LOG-025),
  a delete lock on Log Analytics workspaces (AZ-LOG-026), Azure management sessions limited to 12 hours (AZ-IAM-029)
  and a managed device for Azure management (AZ-IAM-030).
- Full control catalogs: ISO 27001:2022 (93 Annex A controls), NIST CSF 2.0 (106 subcategories), CIS Controls v8.1
  (153 safeguards), SOC 2 (61 criteria), NIST SP 800-53 Rev. 5 (1014 controls and enhancements of release 5.2.0) and
  PCI DSS v4.0.1 (249 requirements).
- CMMC 2.0 as a framework: the 149 practices of Levels 1 to 3 in 32 CFR 170 (FAR 52.204-21, NIST SP 800-171 Rev. 2 and
  the selected NIST SP 800-172 requirements), mapped to the tests by JSolve.
- AzCmply Custom: JSolve's own controls for Azure attack paths that no other framework covers, with 14 tests: network security group rules that trust shared Azure service tags (AZ-NET-026), Front Door access
  restrictions without the X-Azure-FDID check (AZ-APP-010), App Service deployment sites more open than the app
  (AZ-APP-011), Bastion shareable links (AZ-NET-027), the serial console (AZ-VM-014), managed identities with write
  access outside their resource group (AZ-IAM-031), privileged groups that others can change (AZ-IAM-032), data roles
  at subscription scope or above (AZ-IAM-033), storage resource instance rules for other tenants (AZ-STG-027), APIs
  without a subscription key or token validation (AZ-APIM-008), a cost budget with notifications (AZ-GOV-014) and
  alerts on role assignments, deleted locks and run command (AZ-LOG-027 to 029).
- Ingestion: the tenant subscription transfer policy, the members of groups that Conditional Access excludes, SQL
  data classification and masking rules, data collection rule associations of machines and the virtual network links
  of DNS security policies, group properties (role-assignable, dynamic, synchronized), the serial console setting and
  cost budgets.

### Changed
- Frameworks logic revamped

## 0.9.4

### Added
- DORA as a framework: a JSolve crosswalk from the MCSB v2 controls to the 26 articles of DORA (Regulation (EU)
  2022/2554) and its ICT risk management standard (Delegated Regulation (EU) 2024/1774) that have a technical Azure
  side. 
- Nine tests (254 in total): geo-redundant database backups (AZ-BCK-007), SQL long-term retention (AZ-BCK-008), cross
  region restore on geo-redundant vaults (AZ-BCK-009), tested restores and failovers (AZ-BCK-010), Site Recovery for
  virtual machines (AZ-BCK-011), zone redundancy (AZ-BCK-012), a year of activity log (AZ-LOG-024), Conditional Access
  MFA for Azure management (AZ-IAM-024) and applications of other organizations with Azure roles (AZ-IAM-025).
- Ingestion: Conditional Access policies and security defaults (needs Graph `Policy.Read.All`;

## 0.9.3

### Changed
- AzCmply web: while an assessment runs, the page asks to keep the tab open, asks before the tab is closed or
  reloaded, and holds a Web Lock so Chrome and Edge do not freeze or discard it in the background. A run the tab lost
  is reported after the reload.
- AzCmply web and the HTML report follow the look of M365Permissions: slate neutrals, white cards, cyan accent.
- AzCmply web: "AzCmply PowerShell module" links to the PowerShell Gallery.
- The JSolve B.V. mark in the footer of the page and the report, and a link preview image for the page.

### Fixed
- Ingestion: a server error that denies access is no longer retried (Microsoft.Security/apiCollections answers 502
  with AccessDenied details, which stalled the collection for over a minute).

## 0.9.2

### Changed
- Analysis: "Required data was not collected" now says why per section: the HTTP status and error code, skipped
  collection, or a resource provider that is not registered
- AzCmply web: sections that could not be collected are listed on the page with their status and a likely cause

### Fixed
- AzCmply web: Google Analytics was blocked by the Content Security Policy. The converter now adds the hash of each
  inline script to the policy; 
- The parity pipeline failed because `.gitignore` excluded all HTML, including the page itself :D

## 0.9.1

### Added
- AzCmply web (`Web/site`): the full assessment in the browser. Sign in with the multi-tenant JSolve app or your own
  app registration, pick a subscription, and collection, analysis and report run in the page. The report opens full
  screen on request; the history shows the posture score trend per subscription; the ingestion, results, CSVs, report
  and history can be exported for the PowerShell module.

### Changed
- Ingestion: fixed api versions, Graph property selections and directory role exports moved into the collection maps, so the web ingestion reads them from the same place.

### Fixed
- Analysis: controls whose ids sort equal once padded (for example NIST CSF `DE.AE-2` and `DE.AE-02`) no longer come
  out in a different order per run.
- Self-test fixture: database server configurations are written in a fixed order.
- AzCmply web: after an upload, browsers kept running the previous scripts for up to a week, because the host lets them
  cache scripts that long. The page now loads each upload fresh (a build id in `index.html`), and the site includes an
  `.htaccess` for Apache and LiteSpeed hosts with the security headers and revalidation on every visit.
- AzCmply web: Google Analytics was blocked by the Content Security Policy. The converter now adds the hash of each
  inline script to the policy; Analytics gets only the page address without query string, and does not run on the
  return from sign-in.
- The parity pipeline failed because `.gitignore` excluded all HTML, including the page itself.
