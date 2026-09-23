# Changelog

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
