# Azure security report

`New-AzureSecurityReport.ps1` turns the `results.json` of [Invoke-AzureAnalyze.ps1](../Analyze/README.md) into one self-contained HTML file. The file has no external dependencies, works offline, follows the light or dark system theme (with a toggle) and prints with the visible tests expanded.

Pipeline: [Ingest](../Ingest/README.md) > [Analyze](../Analyze/README.md) > Report.

## Usage

```powershell
# report.html next to results.json
.\New-AzureSecurityReport.ps1 -AnalysisPath ..\Analyze\AzureAnalysis\<subscriptionId>_<timestamp>

# with changes since an earlier analysis
.\New-AzureSecurityReport.ps1 -AnalysisPath <new analysis> -BaselinePath <old analysis> -Organization 'Contoso' -OutputPath .\contoso.html
```

| Parameter | Description |
|---|---|
| `-AnalysisPath` | `results.json` or the folder that contains it (required) |
| `-OutputPath` | HTML file to write, or a folder to write `<subscriptionId>_<timestamp>.html` in. Default: `report.html` next to `results.json` |
| `-BaselinePath` | Earlier `results.json` or folder. Adds a changes section, computed with `Analyze\Compare-AzureAnalysis.ps1`. With `-HistoryPath` it defaults to the most recent earlier run found there |
| `-HistoryPath` | Folder holding earlier analyses of the same subscription, searched recursively for `results.json`. From two runs on, the report gains a trend section |
| `-HistoryLimit` | Most recent runs to read from `-HistoryPath`. Default 24 |
| `-Title` | Report title. Default `Azure security assessment` |
| `-Organization` | Organization name shown in the header |

The script returns an object with `Path`, `Tests`, `Failing` and `PostureScore`.

## Contents

1. Cover and executive summary: posture score meter with rating, generated key findings, key figures and results by severity.
2. Trend and changes. With `-HistoryPath` and two or more runs of the same subscription: the posture score over time as a line chart, the result mix per run as bars, and a table with the score change per run. The score axis is a padded window around the values rather than a fixed 0 to 100, so a real move is visible instead of flattened; the window is labelled and the caption names it. With `-BaselinePath` (or the run the history picked): new failures, lost visibility, resolved and still failing findings, grouped by test. A finding that went from failing to unknown is reported as lost visibility, never as resolved: the weakness was not fixed, the data needed to judge it was no longer collected, and the score is not comparable until that is resolved.
3. Priorities: failing Critical and High tests with the affected resources.
4. Security domains: failing, unknown and passing tests per MCSB domain.
5. Framework results: a card per framework (MCSB v2, CIS Azure 6.0.0, WAF, ALZ, ISO 27001, NIST CSF, CIS Controls, SOC 2, NIST SP 800-53, PCI DSS, DORA, CMMC and AzCmply Custom) with version, publisher, source, who mapped the tests (the framework's own Azure checks or JSolve), the result of the controls that have tests, and the coverage: controls with tests (full or partial), controls that need manual evidence and controls outside Azure scope. Per framework a control table lists every control with tests, its result, coverage and tests; the controls that need manual evidence follow behind a toggle, and the ones outside Azure scope are only counted. Controls link to their source documentation where one exists. The section opens with the statement that AzCmply is a technical assessment, not an audit or a certification.
6. Test results: filter by result, severity, domain, framework or text. Each test shows what is checked, why, the remediation, its framework mappings with version and source, Defender for Cloud recommendations, Azure Policy definitions, references, and the result and evidence per resource.
7. Scope and sources: assessment scope, result definitions and every framework's version, publisher, mapping and source.

Resource names are links to the Azure portal wherever the portal has a page for the resource: any resource, resource
group or subscription by its resource id, Azure Policy definitions by definition id, and Entra users, groups and
enterprise applications by object id. Role, deny and policy assignments have no page of their own, so they link to the
scope they apply to and say so on hover. Anything that cannot be resolved to a real page stays plain text rather than
pointing somewhere wrong, and the full resource id is always shown as selectable text next to the name.

Every chart has a table view. Status is always shown with an icon and a label, never by color alone.
The report contains details about weaknesses in the environment. Treat it as confidential. Generated reports in this folder are git-ignored.
