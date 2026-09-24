# Azure security analysis

`Invoke-AzureAnalyze.ps1` runs 254 security tests against an ingestion made by `..\Ingest\Invoke-AzureIngest.ps1` and writes one result per test, with a finding per evaluated resource. PowerShell 7.2+, no modules, no network access.

```powershell
.\Invoke-AzureAnalyze.ps1 -IngestPath ..\Ingest\AzureIngest\<subscriptionId>_<timestamp>          # folder or .zip
.\Invoke-AzureAnalyze.ps1 -IngestPath <ingest> -TestId 'AZ-STG-*','AZ-KV-*' -OutputPath D:\Analysis
.\Compare-AzureAnalysis.ps1 -Baseline <old result folder> -Current <new result folder> -OutputPath comparison.json
.\selftest\Invoke-SelfTest.ps1                                                                     # verify the suite
```

## Frameworks

Every test carries the controls it implements:

| Tag | Source | Version | Per-control source |
|---|---|---|---|
| `MCSB` | [Microsoft cloud security benchmark](https://learn.microsoft.com/security/benchmark/azure/overview) | v2 (preview) | Learn page and anchor per control |
| `CIS` | [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure) | 6.0.0 | none public (PDF after registration) |
| `WAF` | [Well-Architected Framework security checklist](https://learn.microsoft.com/azure/well-architected/security/checklist) | SE:01 to SE:12 | Learn guide per recommendation |
| `ALZ` | [Azure landing zone policy assignments](https://azure.github.io/Azure-Landing-Zones/policy/policyassignments/) | ALZ library platform/alz/2026.08.1 | assignment file in the pinned library release |
| `derived` | NIST SP 800-53 Rev.5, PCI DSS v4, CIS Controls v8.1, NIST CSF 2.0, ISO 27001:2022, SOC 2, via Microsoft's MCSB v2 control mappings | per framework in the catalog | the MCSB controls it comes from (`via`) |
| `DORA` | [Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng) and its RTS on the ICT risk management framework, [Delegated Regulation (EU) 2024/1774](https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj/eng), through a JSolve crosswalk of the MCSB v2 controls (`mappings.DORA` in the catalog), or tagged directly on resilience tests that MCSB does not cover | 26 articles with a technical Azure side | the MCSB controls it comes from (`via`), none when tagged directly |

`catalog\frameworks.json` holds each framework's name, short name, version, publisher, source URL, access terms and the date the catalog was checked against the source. MCSB v2 publishes some NIST CSF identifiers in CSF 1.1 form (for example `PR.AC-05`, unpadded as `PR.AA-1` on some pages); they are reproduced exactly as published.

Tests also list the matching Defender for Cloud recommendation ids and built-in Azure Policy definition ids where they exist (158 tests), so results can be cross-checked against Defender and Policy. Every id is verified against the published Azure Policy definitions and the Defender assessment metadata catalogue.

A test is one requirement, and a control is only tagged on tests that cover exactly what it asks for. Where a benchmark numbers variants separately (CIS 8.3.1/8.3.2 for keys in RBAC and access policy vaults, 8.3.3/8.3.4 for secrets, 7.5/7.8 and 6.1.1.5/6.1.1.6 for NSG and virtual network flow logs, 9.3.9/9.3.10 for storage account locks, 2.1.2 for Databricks subnets), each variant has its own test, so a control is never reported as failing because of resources it does not cover. Where frameworks genuinely overlap, the test is tagged with all of them instead of being duplicated. Generic tests (`AZ-PAAS-*`, `AZ-LOG-015`) exclude resource types that have a dedicated test, so no resource is evaluated twice for the same setting. The catalog of controls is `catalog\frameworks.json`; tags are validated against it when tests load.

## Tests

| Area | Tests | Area | Tests |
|---|---|---|---|
| Identity and privileged access (`IAM`) | 25 | Storage (`STG`) | 26 |
| Defender for Cloud plans and settings (`DEF`) | 25 | Key Vault (`KV`) | 11 |
| Defender findings (`DFA`) | 4 | SQL, PostgreSQL, MySQL, Cosmos DB, Redis (`SQL` `PG` `MY` `COS` `RED` `DB`) | 23 |
| Logging and monitoring (`LOG`) | 24 | App Service (`APP`) | 9 |
| Governance (`GOV`) | 10 | Compute (`VM`) | 12 |
| Network (`NET`) | 23 | Containers (`AKS` `ACR` `CAPP` `ACI`) | 17 |
| Integration (`MSG` `APIM` `AUTO`) | 10 | AI (`AI`) | 7 |
| Backup and resilience (`BCK`) | 12 | Data and analytics (`DBX` `SYN` `ADF`) | 9 |
| Exposed secrets (`SEC`) | 4 | Generic PaaS (`PAAS`) | 3 |

Severity: Critical 4, High 57, Medium 121, Low 64, Informational 8.

## Output

`<OutputPath>\<ingest folder name>\`:

- `results.json`: everything, input for [New-AzureSecurityReport.ps1](../Report/README.md)
- `tests.csv`: one row per test
- `findings.csv`: one row per finding

`results.json`:

```jsonc
{
  "schemaVersion": 2,
  "analyzer": { "version": "0.9", "tests": 254 },
  "ingest": { "folder", "subscriptionId", "subscriptionName", "tenantId", "startedAt", "ingestVersion", "status" },
  "analyzedAt": "...",                                   // the only value that changes between identical runs
  "summary": { "postureScore", "scoreMethod", "tests": {status: n}, "findings": {status: n}, "bySeverity": {...} },
  "frameworks": {                                        // rollup per framework control, worst status of its tests
    "MCSB": { "name", "shortName", "version", "publisher", "kind", "url", "access", "retrieved", "note",
              "coverage": { "controls", "assessed", "notAssessed" },
              "controls": { "NS-2": { "title", "status", "tests": ["AZ-STG-007"], "url" } } },
    "CIS": { ..., "download", "controls": { "9.3.4": { "title", "status", "tests", "assessment": "Manual" } } },
    "PCI DSS v4": { ..., "kind": "derived", "derivedFrom": "MCSB", "controls": { "1.4.2": { "status", "tests", "via": ["NS-2"] } } }
  },
  "tests": [ {
    "id": "AZ-STG-001", "version": 1, "title", "category", "service", "severity",
    "description", "rationale", "remediation", "references": [],
    "frameworks": { "MCSB": [{ "id", "title", "version", "criticality", "url" }], "CIS": [{ "id", "title", "version", "level" }], "WAF": [], "ALZ": [],
                    "derived": { "NIST SP 800-53 Rev.5": [{ "id": "AC-2", "version": "Revision 5", "via": ["PA-7"] }] } },
    "defenderRecommendations": [{ "id", "name" }], "azurePolicies": [{ "id", "name" }],
    "status": "Fail", "statusReason": null, "counts": { "Pass", "Fail", "Unknown", "NotApplicable" },
    "findings": [ { "resourceId", "resourceName", "resourceType", "resourceGroup", "status", "detail", "evidence": {} } ]
  } ]
}
```

Test status: `Fail` if any finding fails, else `Unknown`, else `Pass`, else `NotApplicable`; `Error` when the test threw (reason in `statusReason`). `Unknown` means the data needed was not collected (missing permission or failed call). Framework controls without a test are `NotAssessed`.

Comparable runs: tests and findings are sorted, evidence contains observed values only, and ages are computed against the ingestion start time, so analysing the same ingestion twice gives identical files apart from `analyzedAt`. A finding is identified by test id + resource id. A test's `version` changes when its logic changes, and `Compare-AzureAnalysis.ps1` flags those tests so a status change is not mistaken for a real improvement.

`postureScore` is the severity weighted (Critical 8, High 4, Medium 2, Low 1) average of each test's pass rate.

Evidence never contains secret values; secret tests report the location and pattern name only. Results still describe weaknesses in detail, so treat them as confidential.

## Coverage gaps

Every framework card reports its own coverage (`assessed of controls`), counting all controls in the catalog, not only the ones a test happens to cover. What is left is:

- CIS: the four Automated recommendations 5.1.1, 5.1.3 and 5.6 need tenant level Entra and subscription policy data that the ingestion does not collect; the remaining unassessed CIS recommendations are the ones CIS itself marks Manual, and the report labels them "(manual in CIS)".
- MCSB process controls (incident response plans, threat modeling, DevOps pipeline security, red teaming, emergency access) cannot be derived from configuration.
- DORA: only the articles with a technical Azure side are in the catalog. Governance, incident classification and reporting, resilience testing (including TLPT), contracts, the register of information and exit plans are processes, not configuration. The crosswalk is JSolve's, not published by the EU or Microsoft; a mapping means the configuration contributes to an article, not that the article is met.
- ALZ: 56 of the 80 policy assignments in the pinned library release are covered. The rest are not security controls (resource location, zone resiliency, change tracking) or apply to management group scopes this tool does not read.
- Types not present in a subscription report `NotApplicable`. The self-test checks every test on synthetic data shaped after the Azure Resource Manager API.

## What the analysis will not claim

A test only reports `Pass` when the data it needs was actually read. When a required ingestion section or a child resource call failed, the test reports `Unknown` with the reason, never `Pass` and never `Fail`. The self-test enforces this: it re-analyses the non-compliant fixture with each ingestion file removed in turn, and with every child call marked as failed, and no test may turn a `Fail` into a `Pass`.

`Unknown` is a coverage gap, not a result. `Compare-AzureAnalysis.ps1` therefore reports a finding that went from `Fail` to `Unknown` as `lostVisibility`, never as `resolved`, and the report says so in the executive summary.

## Adding tests

Add an `Add-AzTest @{ ... }` block to the matching `tests\NN-*.ps1` file:

- `Id` (`AZ-<AREA>-<NNN>`, never reused), `Title`, `Category`, `Service`, `Severity`, `Description`, `Rationale`, `Remediation`, `References`
- Read data only through `Requires` (ingestion sections) and `Test-ChildCollected` (child resources). Anything read without one of those can make a test pass on missing data, which the self-test rejects.
- `Frameworks` (`MCSB` required; `CIS`, `WAF`, `ALZ` optional), `Defender`, `Policy`, `Requires` (ingestion sections)
- `ResourceTypes` + `Evaluate { param($Record) ... }` for per resource tests, or `Run { ... }` returning findings. Return `New-Pass`, `New-Fail`, `New-Unknown` or `New-NotApplicable` with a detail and an evidence dictionary.
- Increase `Version` when the logic changes.

Then add the resource to both modes of `selftest\New-FixtureIngest.ps1` and run `selftest\Invoke-SelfTest.ps1`.
