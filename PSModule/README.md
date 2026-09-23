# AzCmply PowerShell module

Generated output. Build it with `..\Build-AzCmplyModule.ps1`; do not edit anything in here, the next build overwrites it.

The build copies `Ingest`, `Analyze` and `Report` in unchanged and keeps their relative layout, because the scripts
resolve the test suite, the control catalog and each other through `$PSScriptRoot`. Only `AzCmply.psm1` and
`AzCmply.psd1` are generated: each function takes its parameter block and help straight from the script it calls,
so the module surface cannot drift from the components. Credentials (`*.local`), collected data and generated
reports are never packaged, and the build fails if one slips through.

```powershell
Import-Module .\AzCmply\AzCmply.psd1

# collect, analyse and report in one call. Run it again later against the same -Path and the report
# picks up the earlier runs by itself and adds a trend section.
Invoke-AzCmplyAssessment -SubscriptionId <id> -TenantId <id> -ClientId <appId> -ClientSecret (Read-Host -AsSecureString) -Organization 'Contoso'

# or a step at a time
$ingest   = Invoke-AzCmplyIngest   -SubscriptionId <id> -ManagedIdentity
$analysis = Invoke-AzCmplyAnalysis -IngestPath $ingest.Path
$report   = New-AzCmplyReport      -AnalysisPath $analysis.Path -Organization 'Contoso'
```

| Command | Alias | Component |
|---|---|---|
| `Invoke-AzCmplyAssessment` | | all three, in one run folder |
| `Invoke-AzCmplyIngest` | `Invoke-AzureIngest` | [Ingest](../Ingest/README.md) |
| `Invoke-AzCmplyAnalysis` | `Invoke-AzureAnalyze` | [Analyze](../Analyze/README.md) |
| `Compare-AzCmplyAnalysis` | `Compare-AzureAnalysis` | [Analyze](../Analyze/README.md) |
| `New-AzCmplyReport` | `New-AzureSecurityReport` | [Report](../Report/README.md) |
| `Invoke-AzCmplySelfTest` | | verifies the packaged test suite |

To install for the current user, copy the `AzCmply` folder into a `$env:PSModulePath` entry.
