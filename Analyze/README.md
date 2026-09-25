# Azure security analysis

`Invoke-AzureAnalyze.ps1` runs 289 security tests against an ingestion made by `..\Ingest\Invoke-AzureIngest.ps1` and writes one result per test, with a finding per evaluated resource. PowerShell 7.2+, no modules, no network access.

```powershell
.\Invoke-AzureAnalyze.ps1 -IngestPath ..\Ingest\AzureIngest\<subscriptionId>_<timestamp>          # folder or .zip
.\Invoke-AzureAnalyze.ps1 -IngestPath <ingest> -TestId 'AZ-STG-*','AZ-KV-*' -OutputPath D:\Analysis
.\Compare-AzureAnalysis.ps1 -Baseline <old result folder> -Current <new result folder> -OutputPath comparison.json
.\selftest\Invoke-SelfTest.ps1                                                                     # verify the suite
```

## Frameworks

Each framework has its own catalog in `catalog\frameworks\`: every control of the framework, and per control either the tests that evidence it (`tests`, with `coverage` `full` or `partial`) or why it has none (`applicability`: `manual` when the control concerns the Azure environment but needs evidence outside configuration, `notApplicable` when it does not concern Azure). Frameworks are peers: a test can evidence controls in any number of frameworks, and a control can have any number of tests.

| Framework | Version | Mapping | Controls |
|---|---|---|---|
| [MCSB](https://learn.microsoft.com/security/benchmark/azure/overview) | v2 (preview) | the framework's own Azure checks | 81 |
| [CIS Azure](https://www.cisecurity.org/benchmark/azure) | 6.0.0 | the framework's own Azure checks | 127 |
| [WAF](https://learn.microsoft.com/azure/well-architected/security/checklist) | security checklist SE:01 to SE:12 | the framework's own Azure checks | 12 |
| [ALZ](https://azure.github.io/Azure-Landing-Zones/policy/policyassignments/) | ALZ library platform/alz/2026.08.1 | the framework's own Azure checks | 80 |
| [ISO 27001](https://www.iso.org/standard/27001) | 2022, Annex A | JSolve | 93 |
| [NIST CSF](https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final) | 2.0 | JSolve | 106 |
| [CIS Controls](https://www.cisecurity.org/controls/v8-1) | v8.1 | JSolve | 153 |
| [SOC 2](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) | 2017 criteria, 2022 points of focus | JSolve | 61 |
| [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Revision 5, release 5.2.0 | JSolve | 1014 |
| [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) | v4.0.1, requirements 1 to 12 | JSolve | 249 |
| [DORA](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng) | (EU) 2022/2554 and RTS 2024/1774, technical articles | JSolve | 26 |
| [CMMC](https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-G/part-170) | 2.0, Levels 1 to 3 (32 CFR 170) | JSolve | 149 |
| AzCmply Custom | 2026.09 | JSolve's own controls | 9 |

- The framework's own Azure checks: MCSB, CIS Azure, WAF and ALZ describe Azure configuration, and each test implements the check it is mapped to. CIS Azure recommendations and ALZ assignments of a single policy are fully covered by their tests. MCSB controls, WAF items and ALZ initiatives also ask for things AzCmply does not check, so they are partial; the Bot Service, Data Explorer and Virtual Desktop guardrail initiatives are full because every policy in them has a test.
- JSolve: the other frameworks are not written for Azure. Which tests evidence which control is JSolve's assessment, not the publisher's, and the report says so. A control is full only where its tests check everything about it that Azure configuration can show (CIS Controls 8.6, 10.1 and 13.6; NIST SP 800-53 IA-2(1), IA-2(2) and SI-7(9)); every other mapped control is partial.
- CMMC: Level 1 is the 15 basic safeguarding requirements of FAR 52.204-21(b)(1), Level 2 the 110 requirements of NIST SP 800-171 Rev. 2 and Level 3 the 24 NIST SP 800-172 requirements that 32 CFR 170.14 selects, with the DoD parameters. Ids follow 32 CFR 170.14(c)(1) (for example `AC.L1-b.1.i`, `AC.L2-3.1.1`, `AC.L3-3.1.2e`), each practice has its `level`, and a Level 1 practice has the tests of the Level 2 requirement it corresponds to.
- AzCmply Custom: JSolve's controls for Azure attack paths that none of the other frameworks covers, based on published attack research and breaches (for example the shared service tag bypass of Tenable TRA-2024-19). Its 14 tests (AZ-IAM-031 to 033, AZ-NET-026, AZ-NET-027, AZ-APP-010, AZ-APP-011, AZ-VM-014, AZ-STG-027, AZ-GOV-014, AZ-LOG-027 to 029, AZ-APIM-008) evidence no control of another framework.
- Catalog text: ISO 27001 control titles are the Annex A headings, NIST CSF and NIST SP 800-53 texts are NIST's, CMMC texts are those of the FAR, NIST SP 800-171 and 32 CFR 170 (all public domain). CIS Controls, SOC 2 and PCI DSS are listed by id with the name of their control, series or principal requirement; their text is licensed by CIS, the AICPA and the PCI SSC. The PCI DSS requirement numbers are those of Microsoft's PCI DSS v4 regulatory compliance initiative, which lists every requirement; appendices A1 to A3 are left out.
- Each catalog records name, short name, version, publisher, source URL and the date it was checked against the source. A new framework, or a new version of one, is one file; the analyzer checks when it loads that every test a catalog names exists and that every test evidences at least one control.

Tests also list the matching Defender for Cloud recommendation ids and built-in Azure Policy definition ids where they exist (158 tests), so results can be cross-checked against Defender and Policy. Every id is verified against the published Azure Policy definitions and the Defender assessment metadata catalogue.

A test is one requirement, and a control only lists tests that address what it asks for. Where a benchmark numbers variants separately (CIS 8.3.1/8.3.2 for keys in RBAC and access policy vaults, 8.3.3/8.3.4 for secrets, 7.5/7.8 and 6.1.1.5/6.1.1.6 for NSG and virtual network flow logs, 9.3.9/9.3.10 for storage account locks, 2.1.2 for Databricks subnets), each variant has its own test, so a control is never reported as failing because of resources it does not cover. Where frameworks overlap, one test evidences controls in all of them instead of being duplicated. Generic tests (`AZ-PAAS-*`, `AZ-LOG-015`) exclude resource types that have a dedicated test, so no resource is evaluated twice for the same setting.

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
  "schemaVersion": 3,
  "analyzer": { "version": "0.9.4", "tests": 289 },
  "ingest": { "folder", "subscriptionId", "subscriptionName", "tenantId", "startedAt", "ingestVersion", "status" },
  "analyzedAt": "...",                                   // the only value that changes between identical runs
  "summary": { "postureScore", "scoreMethod", "tests": {status: n}, "findings": {status: n}, "bySeverity": {...} },
  "frameworks": {                                        // every control of every framework, in catalog order
    "ISO 27001": { "key", "name", "shortName", "version", "publisher", "type", "url", "access", "retrieved", "mapping": "jsolve", "note",
                   "coverage": { "controls", "automated", "full", "partial", "manual", "notApplicable",
                                 "results": { "Pass", "Fail", "Unknown", "NotApplicable", "Error", "NotAssessed" }, "score" },
                   "controls": { "A.8.20": { "title", "applicability": "automated", "coverage": "partial", "status": "Fail", "tests": ["AZ-NET-001"] },
                                 "A.5.23": { "title", "applicability": "manual", "status": "NotAssessed", "tests": [] },
                                 "A.7.1": { "title", "applicability": "notApplicable", "status": "NotAssessed", "tests": [] } } },
    "CIS Azure": { ..., "mapping": "native", "controls": { "9.3.4": { "title", "applicability", "coverage", "status", "tests", "level", "assessment": "Automated" } } }
  },
  "tests": [ {
    "id": "AZ-STG-001", "version": 1, "title", "category", "service", "severity",
    "description", "rationale", "remediation", "references": [],
    "frameworks": { "MCSB": [{ "id", "title", "coverage", "criticality", "url" }], "CIS Azure": [{ "id", "title", "coverage", "level" }], "ISO 27001": [{ "id", "title", "coverage" }] },
    "defenderRecommendations": [{ "id", "name" }], "azurePolicies": [{ "id", "name" }],
    "status": "Fail", "statusReason": null, "counts": { "Pass", "Fail", "Unknown", "NotApplicable" },
    "findings": [ { "resourceId", "resourceName", "resourceType", "resourceGroup", "status", "detail", "evidence": {} } ]
  } ]
}
```

Test status: `Fail` if any finding fails, else `Unknown`, else `Pass`, else `NotApplicable`; `Error` when the test threw (reason in `statusReason`). `Unknown` means the data needed was not collected (missing permission or failed call). A framework control takes the worst status of its tests (Fail, Error, Unknown, Pass, NotApplicable); a control without a test that ran is `NotAssessed`, and its `applicability` says whether it needs manual evidence or does not concern Azure. `score` per framework is the share of passing controls among those that pass or fail.

Comparable runs: tests and findings are sorted, evidence contains observed values only, and ages are computed against the ingestion start time, so analysing the same ingestion twice gives identical files apart from `analyzedAt`. A finding is identified by test id + resource id. A test's `version` changes when its logic changes, and `Compare-AzureAnalysis.ps1` flags those tests so a status change is not mistaken for a real improvement.

`postureScore` is the severity weighted (Critical 8, High 4, Medium 2, Low 1) average of each test's pass rate.

Evidence never contains secret values; secret tests report the location and pattern name only. Results still describe weaknesses in detail, so treat them as confidential.

## Coverage gaps

Every framework card reports its coverage against the whole catalog: how many controls that concern Azure have tests (full or partial), how many need manual evidence, and how many are outside Azure scope. What is left is:

- CIS Azure: every Automated recommendation has a test. The rest are the ones CIS itself marks Manual; the report labels them "(manual in CIS)".
- MCSB and WAF: process controls (incident response plans, threat modeling, DevOps pipeline security, red teaming) cannot be read from configuration.
- ALZ: 72 of the 80 policy assignments in the pinned library release have tests. Not covered: Enforce-ALDO-Services, Enforce-ALZ-Decomm and Enforce-ALZ-Sandbox (management group archetypes), Audit-PeDnsZones and Deny-HybridNetworking (depend on whether the subscription is a landing zone or the connectivity platform), DenyAction-DeleteUAMIAMA (blocks an action, not a setting), Enforce-AKS-HTTPS (ingress settings inside the cluster) and Deploy-MDFC-DefSQL-AMA (the Azure Monitor Agent setup of Defender for SQL on machines).
- ISO 27001, NIST CSF, CIS Controls, SOC 2, NIST SP 800-53, PCI DSS, DORA and CMMC: controls about people, physical security, organization-wide governance, end-user devices and software development are outside Azure scope and only counted. Controls that concern Azure but have no test need manual evidence; they include processes (access reviews, incident response, change approval, penetration tests) and technical measures that need data from inside machines or network devices (time synchronization, software allowlisting, host command-line logging, FIPS validated cryptography).
- DORA: only the articles with a technical Azure side are in the catalog. Governance, incident classification and reporting, resilience testing (including TLPT), contracts, the register of information and exit plans are processes, not configuration.
- Types not present in a subscription report `NotApplicable`. The self-test checks every test on synthetic data shaped after the Azure Resource Manager API.

## What the analysis will not claim

A test only reports `Pass` when the data it needs was actually read. When a required ingestion section or a child resource call failed, the test reports `Unknown` with the reason, never `Pass` and never `Fail`. The self-test enforces this: it re-analyses the non-compliant fixture with each ingestion file removed in turn, and with every child call marked as failed, and no test may turn a `Fail` into a `Pass`.

`Unknown` is a coverage gap, not a result. `Compare-AzureAnalysis.ps1` therefore reports a finding that went from `Fail` to `Unknown` as `lostVisibility`, never as `resolved`, and the report says so in the executive summary.

## Adding tests

Add an `Add-AzTest @{ ... }` block to the matching `tests\NN-*.ps1` file:

- `Id` (`AZ-<AREA>-<NNN>`, never reused), `Title`, `Category`, `Service`, `Severity`, `Description`, `Rationale`, `Remediation`, `References`
- Read data only through `Requires` (ingestion sections) and `Test-ChildCollected` (child resources). Anything read without one of those can make a test pass on missing data, which the self-test rejects.
- `Defender`, `Policy`, `Requires` (ingestion sections)
- `ResourceTypes` + `Evaluate { param($Record) ... }` for per resource tests, or `Run { ... }` returning findings. Return `New-Pass`, `New-Fail`, `New-Unknown` or `New-NotApplicable` with a detail and an evidence dictionary.
- Increase `Version` when the logic changes.

Add the test id to the controls it evidences in `catalog\frameworks\*.json` (`tests`, and `coverage` when the control had none), and to the AzCmply Custom catalog when no framework asks for it. Then add the resource to both modes of `selftest\New-FixtureIngest.ps1` and run `selftest\Invoke-SelfTest.ps1`.
