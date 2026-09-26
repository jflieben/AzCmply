# AzCmply

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/AzCmply?label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/AzCmply) [![Self-test](https://github.com/jflieben/AzCmply/actions/workflows/selftest.yml/badge.svg)](https://github.com/jflieben/AzCmply/actions/workflows/selftest.yml) [![Web parity](https://github.com/jflieben/AzCmply/actions/workflows/web.yml/badge.svg)](https://github.com/jflieben/AzCmply/actions/workflows/web.yml)

Free (non commercially) fully automated test suite for Azure subscriptions against multiple up to date industry security baselines.

AzCmply reads an Azure subscription and its Entra ID context, runs 308 tests against it and writes a report: a posture score, the failures to address, results per security domain and per framework, and every test with its remediation and evidence per resource. Frameworks: the Microsoft cloud security benchmark v2, CIS Microsoft Azure Foundations Benchmark 6.0.0, the Well-Architected Framework security pillar, Azure landing zone policies, ISO 27001:2022, NIST CSF 2.0, CIS Controls v8.1, SOC 2, NIST SP 800-53 Rev. 5, PCI DSS v4.0.1, DORA with its ICT risk management standard (RTS 2024/1774) and CMMC 2.0 Levels 1 to 3, to which JSolve maps the tests. AzCmply Custom adds JSolve's own controls for Azure attack paths that none of these frameworks covers.

Everything is read only and can be run it again later to make the report show the trend and what changed.

AzCmply is an automated technical assessment of Azure configuration, not an audit or a certification. It does not establish compliance with any framework or regulation and does not replace an assessment by an accredited auditor, certification body or supervisory authority. Framework names and control identifiers show where results relate to their requirements; the frameworks belong to their publishers.

| | AzCmply web | PowerShell module |
|---|---|---|
| Runs | in your browser | on any machine with PowerShell 7.2+ |
| Signs in as | the user (delegated) | a service principal or managed identity |
| Suited for | an assessment by hand, no install | scheduled and automated runs |
| Data | stays in the browser; results history kept locally | written to a folder |

If you want, the web page can export what it collects and analyses just like the PS module, and the format is interchangeable.

## AzCmply web

Open [the page](https://azcmply.jsolve.nl/), sign in, pick a subscription and run. Collection, analysis and the report all run in the browser; the data goes from the Microsoft APIs to the page and nowhere else. The page keeps the results of every run (not the collected data) in the browser, which gives each report its trend until you clear your browser cache; the history list shows the posture score trend per subscription. **Try it with demo data**, next to the sign-in button, shows a report without signing in. Keep the tab open while an assessment runs: the collected data exists only in that tab. Other tabs are fine meanwhile.

### Who can sign in

| Needed | For |
|---|---|
| Azure RBAC **Reader** on the subscription | everything in the subscription |
| Entra ID role **Global Reader** | the Entra ID checks: principals behind role assignments, privileged and eligible roles, app credentials, sign-in activity, Conditional Access, security defaults, emergency access accounts, the subscription transfer policy |

Without the Entra role the assessment still runs; the Entra ID checks then report Unknown. Clear **Entra ID enrichment** on the page to skip them.

### The app registration

The page signs in through an Entra ID app registration of the single-page application type. It has no secret and only delegated, read-only permissions, so it can never do more than the signed in user:

| API | Delegated permission | Why |
|---|---|---|
| Azure Service Management | `user_impersonation` | read the subscription with the user's own Azure RBAC |
| Microsoft Graph | `User.Read` | sign-in |
| Microsoft Graph | `Directory.Read.All` | principals, groups, service principals and their credentials |
| Microsoft Graph | `RoleManagement.Read.Directory` | directory role assignments and eligible (PIM) assignments |
| Microsoft Graph | `AuditLog.Read.All` | last sign-in of accounts with access |
| Microsoft Graph | `Policy.Read.All` | Conditional Access policies and security defaults (MFA, emergency access accounts) |

Use one of these:

1. **The JSolve app** (multi-tenant, on the page hosted by JSolve B.V.). An administrator of your tenant (Global Administrator, Privileged Role Administrator or Cloud Application Administrator) grants consent once, with **Admin consent for this app** on the page. After that anyone in the tenant with the access above can sign in but actually running a scan requires the user to have permissions on each target subscription.
2. **Your own app registration**, for a page you host yourself or run on your own computer, or if your policies do not allow third party apps. Create it with one command, which signs in with a device code and needs a role that can create app registrations:

   ```powershell
   cd Web
   .\New-AzCmplyAppRegistration.ps1 -GrantAdminConsent                                   # for http://localhost:8400/
   .\New-AzCmplyAppRegistration.ps1 -RedirectUri 'https://azcmply.contoso.com/' -GrantAdminConsent
   ```

   On the page, open **App registration and tenant**, enter the application (client) id it prints and, for a single tenant app, your tenant id. Running the script again updates the same app. To create the registration by hand instead: platform **Single-page application** with the page address as redirect URI, the permissions above, and admin consent.

### Hosting the page yourself

The page is static: serve the folder `Web/site` from any web server.

- On your own computer: `.\Web\Start-AzCmplyWeb.ps1` serves it at `http://localhost:8400/` and opens it.
- Amywhere else: upload the folder including the hidden `.htaccess`, which sets the security headers

Run `.\Web\Convert-AzCmplyToWeb.ps1` before every upload.

Set the redirect URI of your app registration to the address of the page, and put the client id of your multi-tenant app in `Web/site/js/config.js` if you want it to be the default for your users.

`index.html` contains the Google Analytics tag of azcmply.jsolve.nl. Remove that snippet when you host the page yourself, then run the converter, which updates the script hashes.

## PowerShell module

```powershell
Install-Module AzCmply -Scope CurrentUser

# collect, analyse and report in one call; run it again against the same -Path for a trend
Invoke-AzCmplyAssessment -SubscriptionId <id> -TenantId <id> -ClientId <appId> -ClientSecret (Read-Host -AsSecureString) -Organization 'Contoso'
Invoke-AzCmplyAssessment -SubscriptionId <id> -ManagedIdentity -Path D:\Assessments
```

The service principal or managed identity needs **Reader** on the subscription and the Microsoft Graph application permission **Directory.Read.All**; **RoleManagement.Read.Directory**, **AuditLog.Read.All** and **Policy.Read.All** add eligible directory roles, sign-in activity and Conditional Access. Certificate authentication is supported too (`-CertificateThumbprint`, `-CertificatePath`). See [PSModule](PSModule/README.md) for the separate steps (`Invoke-AzCmplyIngest`, `Invoke-AzCmplyAnalysis`, `New-AzCmplyReport`, `Compare-AzCmplyAnalysis`).

## How the web variant is built

The browser runs the analyzer, the comparison and the report generated from the PowerShell source. `Web/Convert-AzCmplyToWeb.ps1` converts the scripts to JavaScript, and a small runtime in `Web/site/js/runtime` reproduces PowerShell's behaviour (comparison, sorting, formatting, null handling). The same run extracts what the ingestion collects from `Ingest/Invoke-AzureIngest.ps1`.

```powershell
.\Web\Convert-AzCmplyToWeb.ps1            # regenerate Web/site/generated
.\Web\generator\Test-WebParity.ps1        # PowerShell and web give the same results, the same comparison and the same report
```

`Test-WebParity.ps1 -Thorough` adds the degraded ingestions of the self-test; `Test-WebIngestParity.ps1` compares the web ingestion with the PowerShell ingestion on a live subscription. Both need node 20 or later.

## Contributing

Bug reports, wrong results, new tests and framework mappings are welcome: open an [issue](https://github.com/jflieben/AzCmply/issues/new/choose) with one of the forms, or read [CONTRIBUTING.md](CONTRIBUTING.md) to build it yourself. Report vulnerabilities in AzCmply privately, see [SECURITY.md](SECURITY.md).

## License

<a href="https://www.jsolve.nl"><img src="Web/site/img/jsolve-mark.png" alt="JSolve B.V." height="28" align="left"></a> AzCmply is made by [JSolve B.V.](https://www.jsolve.nl)
<br clear="left">

See https://jsolve.nl/commercial-use.html for provisions on commercial use of this tool.

Tl;dr: commercial (re)use is NOT allowed without prior written consent by the author, otherwise free to use and modify as long as proper attribution is given to the author.
