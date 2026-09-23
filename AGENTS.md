AzCmply is a tool with multiple subtools to help assess the security of an Azure environment.
It purposely separates the ingestion, analysis and reporting tasks so they can be done independently.

Ingestion logic is in \Ingest, it contains creds.local with credentials and target info for a test environment to validate the full chain against.
Analysis logic is in \Analyze
Reporting logic is in \Report
Build-AzCmplyModule.ps1 packages all three as the AzCmply PowerShell module in \PSModule. The module is generated output: the components stay the source of truth, and Invoke-AzCmplyAssessment runs the whole chain in one command.

The tool only uses read permissions, should have detailed error reporting during any tool call.
But most importantly, the tool should be comprehensive and super-accurately test the baselines/frameworks it uses to source tests, of which it should always use the latest version.

The tool should be 100% transparant in which tests it ran, why they failed or weren't run, which frameworks and controls they belong to (if any), and if none, AzCmply is the author/framework.

Never use typical AI speak, paragraphing or symbols (e.g. the em-dash). Keep it succinct, brief and Dutch professional style, don't explain, just state the facts.

Everywhere where versioning makes sense, this should be based on the VERSION file in the root, which I will update on an as-needed basis.

Every time you do any sort of significant work, update the CHANGELOG.md file and the README.md file, these are both public facing files that help users understand and use our tool.

## Rules that keep the output honest

These are not style preferences; breaking them makes the tool state something untrue.

- A test may only report `Pass` or `Fail` on data it actually read. Reach ingestion data through `Requires`
  (sections) and `Test-ChildCollected` (child resources); anything read without one of those can turn missing
  data into a clean bill of health. Report `New-Unknown` with the reason instead.
- A framework control may only be tagged on a test that covers exactly what that control asks for. Where a
  benchmark numbers variants separately, split the test rather than tagging both ids on one, otherwise a
  control is reported as failing because of resources it does not cover.
- Framework catalogs are reproductions of their source, not paraphrases. Control ids, titles and mappings are
  copied as published, including inconsistencies, and `retrieved` records when that was last checked.
- `Unknown` is a coverage gap, never progress. A finding that goes from `Fail` to `Unknown` between runs is
  `lostVisibility` in the comparison, never `resolved`.
- A portal link is only rendered for a resource id the Azure portal really has a page for. A link that lands on an
  error page, or on something other than what the row names, is the report pointing at the wrong thing; unmatched
  ids stay plain text. Where only the scope can be opened, the link says so on hover.
- `selftest\Invoke-SelfTest.ps1` enforces the first rule by re-analysing the non-compliant fixture with each
  ingestion file removed and with every child call failed. It takes several minutes; run it before committing.
