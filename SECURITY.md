# Security policy

## Reporting a vulnerability

Report vulnerabilities in AzCmply privately, never in a public issue:

- on GitHub: **Security** tab, **Report a vulnerability**, or
- by email to [hello@jsolve.nl](mailto:hello@jsolve.nl?subject=AzCmply%20security), subject "AzCmply security".

Include the version, the component (ingestion, analysis, report, module, web page), how to reproduce it and what an attacker gains. You will hear when a fix is released, and whether you want to be credited in the changelog.

## Scope

In scope: AzCmply itself.

- the scripts and the PowerShell module, for example a call that writes to Azure or needs more than read access
- the web page at [azcmply.jsolve.nl](https://azcmply.jsolve.nl/): sign-in, handling of tokens, the Content Security Policy, collected data leaving the browser
- the report, for example script injection through collected data

## Supported versions

Fixes go into the next release of the module on the PowerShell Gallery and of the web page. Use the latest version.
