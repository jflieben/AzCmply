# Changelog

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
