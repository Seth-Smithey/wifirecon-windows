# Security policy

Security fixes target the latest version on `main`. Older releases are not
maintained separately; update to the latest release before reporting a problem.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Seth-Smithey/wifirecon-win/security/advisories/new).
Do not open a public issue containing credentials, private network names,
BSSIDs, GPS coordinates, client details, packet captures, or unredacted logs.
Provide a minimal reproduction using invented network names and synthetic data.
If private reporting is unavailable, do not post sensitive details publicly.

## Data and deployment

Survey databases, settings, exports, and logs can contain sensitive network and
location information. They belong in your local data directory, never in Git.
Examples and test fixtures use invented network names and locally administered
MAC addresses. Ignore rules help prevent mistakes but do not encrypt your data.

The desktop application does not open a listening port. The optional web server
has no built-in TLS or multi-user access control. Use it only on a trusted
network, or behind an authenticated TLS proxy. Treat its API token as a secret.
Windows scans may transmit probe requests; surveying is not radio-silent capture.

## Repository checks

CI runs Ruff, regression tests, and offscreen checks on Windows and Linux.
Security workflows scan Git history with Gitleaks, audit resolved dependencies
with pip-audit, and run Bandit. Bandit records all findings and blocks high-severity
findings; lower-severity findings require review in the report. CodeQL analyzes
Python and JavaScript, and dependency review checks pull requests when GitHub's
public-repository security features are available.

Actions are pinned to full commit SHAs. Workflows use minimal permissions and
do not persist checkout credentials. Dependency updates are proposed as PRs.
These checks reduce risk; they do not establish that the application is free of
vulnerabilities. Hardware behavior still requires testing on Windows.
