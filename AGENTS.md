AzCmply is a tool with multiple subtools to help assess the security of an Azure environment.
It purposely separates the ingestion, analysis and reporting tasks so they can be done independently.

Ingestion logic is in \Ingest, it contains creds.local with credentials and target info for a test environment to validate the full chain against.
Analysis logic is in \Analyze
Reporting logic is in \Report
Build-AzCmplyModule.ps1 packages all three as the AzCmply PowerShell module in \PSModule. The module is generated output: the components stay the source of truth, and Invoke-AzCmplyAssessment runs the whole chain in one command.
\Web is AzCmply web: a static site (\Web\site) that does the same in the browser. See "The web variant" below.

The tool only uses read permissions, should have detailed error reporting during any tool call.
But most importantly, the tool should be comprehensive and super-accurately test the baselines/frameworks it uses to source tests, of which it should always use the latest version.

The tool should be 100% transparant in which tests it ran, why they failed or weren't run, which frameworks and controls they belong to (if any), and if none, AzCmply is the author/framework.

Never use typical AI speak, paragraphing or symbols (e.g. the em-dash). Keep it succinct, brief and Dutch professional style, don't explain, just state the facts.

Everywhere where versioning makes sense, this should be based on the VERSION file in the root, which I will update on an as-needed basis.

Every time you do any sort of significant work, update the CHANGELOG.md file and the README.md file, these are both public facing files that help users understand and use our tool.

Portable NODE is available on this system.

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
- The one exception is a `crosswalk` framework (DORA): the article titles are copied as published, but the mapping
  is JSolve's own (`mappings.DORA` on the MCSB controls) and must say so wherever it is shown. Only articles with a
  technical Azure side belong in its catalog. A test tags DORA directly only when it is a resilience check with no
  fitting MCSB control; that is also the only case in which a test may go without an MCSB control.
- `Unknown` is a coverage gap, never progress. A finding that goes from `Fail` to `Unknown` between runs is
  `lostVisibility` in the comparison, never `resolved`.
- A portal link is only rendered for a resource id the Azure portal really has a page for. A link that lands on an
  error page, or on something other than what the row names, is the report pointing at the wrong thing; unmatched
  ids stay plain text. Where only the scope can be opened, the link says so on hover.
- `selftest\Invoke-SelfTest.ps1` enforces the first rule by re-analysing the non-compliant fixture with each
  ingestion file removed and with every child call failed. It takes several minutes; run it before committing.
- Analysis output must be deterministic: sorts need a tie breaker and nothing may depend on the enumeration order of
  an unordered hashtable (it differs per process). The web parity check fails on any such dependency.

## The web variant

The browser runs code generated from the PowerShell source, never a rewrite of it. PowerShell stays the only place
where tests, analysis, comparison and report are written.

- `Web\Convert-AzCmplyToWeb.ps1` converts `Analyze\lib`, `Analyze\tests`, `Invoke-AzureAnalyze.ps1`,
  `Compare-AzureAnalysis.ps1` and `Report\New-AzureSecurityReport.ps1` to JavaScript in `Web\site\generated`, copies the
  framework catalog, extracts the ingestion's collection maps (`ingest-plan.js`) and bundles the demo fixture. It is
  idempotent. Run it after every change to those files, the collection maps, the fixture or anything in `Web\site`, and
  commit its output: it also stamps the build id (version plus a hash of every file the page loads) into
  `Web\site\index.html`, which `js\boot.js` uses to fetch a new upload past the browser cache (the jsolve.nl host caches
  scripts for a week).
  Never edit `Web\site\generated` by hand. `-Check` fails when the output is stale (CI runs it).
- `Web\generator\Test-WebParity.ps1` must pass after regenerating: language conformance, analysis of both fixtures
  (results.json, tests.csv, findings.csv), comparison and report byte for byte. Add `-Thorough` after test changes.
- When the converter stops on a construct, extend `Web\generator\Transpiler.ps1` or the runtime
  (`Web\site\js\runtime`) and add a case to `Web\generator\conformance.ps1` that pins the PowerShell behaviour. Do not
  rewrite the PowerShell to dodge the converter unless the PowerShell itself improves.
- The runtime reproduces PowerShell semantics (comparison and conversion, member enumeration, AutomationNull, .NET
  sort order, number and date formatting). Known, deliberate gaps are listed at the top of `conformance.ps1`.
- `Web\site\js\runtime\overrides.js` holds native versions of generated functions for speed only, keyed on the hash of
  the PowerShell function; a changed function falls back to the generated code automatically.
- The collection maps region of `Ingest\Invoke-AzureIngest.ps1` must stay literal data (the generator refuses logic
  there). The collection logic itself is mirrored by hand in `Web\site\js\ingest.js`: a change to how the PowerShell
  ingestion collects needs the same change there, verified with `Web\generator\Test-WebIngestParity.ps1` against the
  test subscription in `Ingest\creds.local`.
- Security of the page: no third party scripts, styles or fonts except Google Analytics in `index.html`; the Content
  Security Policy in `index.html`, `.htaccess` and `staticwebapp.config.json` stays strict (the converter stamps the
  hash of each inline script into `script-src`; no `'unsafe-inline'`); Analytics never gets a query string or fragment
  and does not run on the sign-in return, whose URL holds the authorization code; reports render only in the
  sandboxed `report-frame.html`; tokens stay in the tab (memory and sessionStorage); set text with `textContent`,
  never `innerHTML` with data.
- Sections that could not be collected show on the page with their HTTP status and a hint (`js\ingest.js`), and in the
  Unknown reasons of the analysis (`Get-IngestSectionProblem` in `Analyze\lib\AnalyzeCore.ps1`).
- A running assessment is guarded in `js\app.js` (`guardRun`/`releaseRun`): keep-open note, beforeunload prompt, Web
  Lock, screen wake lock and a sessionStorage marker that reports a lost run. Every exit of a run calls `releaseRun`.
- `Web\generator\page-check.mjs` runs the demo in headless Chrome (serve the site with `Web\Start-AzCmplyWeb.ps1`),
  checks that the report opens full screen only on request and that the history renders its trend column, and reports
  console errors and CSP violations. Run it at 1280 and 390 pixels wide after page changes.
- The page exports (ingestion zip, results.json, CSVs, report, history) but does not open existing data.
- The page (`Web\site\css\app.css`) and the report (CSS in `Report\New-AzureSecurityReport.ps1`) share the look of
  M365Permissions (`C:\Git\M365PermissionsFrontEndDev\frontend\src\styles.css`): keep their color tokens in step.
  `#00acd7` is for fills and borders; text, lines and white-on-accent use `--accent-strong` (`#007ea3`) for contrast.
- The JSolve B.V. mark sits in the footers only, never on the report cover: `Web\site\img\jsolve-mark.png` for the page,
  `$jsolveMark` (a data URI) in the report, which must stay one self-contained file. Images under `Web\site` are
  binary in `.gitattributes`; the build id hashes them by their bytes.
