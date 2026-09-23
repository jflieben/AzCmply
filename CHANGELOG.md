# Changelog

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
