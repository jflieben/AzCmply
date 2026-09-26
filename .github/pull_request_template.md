## What and why

<!-- What the pull request changes and why. Link the issue: "Fixes #123". -->

## Checklist

- [ ] `Analyze\selftest\Invoke-SelfTest.ps1` passes
- [ ] `Web\Convert-AzCmplyToWeb.ps1` was run and its output committed; `Web\generator\Test-WebParity.ps1 -Thorough` passes
- [ ] New or changed tests: the fixture makes them pass and fail, they are mapped in the framework catalogs, and changed logic has a higher `Version`
- [ ] Changes to how data is collected are also in `Web\site\js\ingest.js` (and `Test-WebIngestParity.ps1` passes, if you have a subscription)
- [ ] `CHANGELOG.md` (under `## Unreleased`) and the test counts in the READMEs are updated
- [ ] No ingestion output, results, reports, tenant data or secrets in the commits
- [ ] I agree to the [licensing of contributions](https://github.com/jflieben/AzCmply/blob/main/CONTRIBUTING.md#licensing-of-contributions)
