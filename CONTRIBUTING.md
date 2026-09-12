# Development

Use `main` as the stable branch and make changes on a short-lived branch.
Open a pull request against `main`. Dependabot also targets `main`.

On Windows, run `Setup wifirecon.cmd` once, then activate `.venv` or use its
Python executable explicitly. Do not commit `.venv`, build output, credentials,
survey databases, or customer exports. `HANDOFF.md` is a local working note.

Before pushing:

```powershell
.venv\Scripts\python.exe -m pip install ruff==0.16.7
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe -m tools.verify
```

The self-checks use synthetic data and offscreen Qt. Hardware diagnostics are
separate: `python -m app --doctor` can fail when Wi-Fi is off or no adapter is
present, so it is not a CI gate.

CI checks Linux and Windows with Python 3.10 and 3.14, and builds a Windows
folder package. Download the `wifirecon-windows` artifact from a successful
Actions run. Extract the artifact, then extract the application ZIP inside it.
Keep `wifirecon.exe` alongside its `_internal` folder.

## Releases

Run `./build.ps1` on Windows. It smoke-tests with isolated synthetic data and
produces `dist/wifirecon-VERSION-win64.zip` plus `dist/SHA256SUMS.txt`.
Never distribute just the executable from a folder build.

For a release, update `VERSION`, commit and push the tested change, create and
push the matching `vVERSION` tag, then run `./build.ps1 -Release` with the GitHub
CLI authenticated. It requires the tag to already exist.

Folder packages currently require manual download and extraction to update.
The application has no GitHub authentication for private release downloads;
use your signed-in browser if access requires it. Source checkouts can use authenticated Git.

## Security and privacy checks

Run `python -m bandit -r app --severity-level high` and
`python -m pip_audit -r requirements.txt` before changes that affect dependencies
or network-facing code. CI also scans fetched Git history with Gitleaks.
CodeQL and dependency review activate when the repository is public.

Use generic `Example_` network names and locally administered MAC addresses in
fixtures. Never include actual SSIDs, BSSIDs, client names, GPS coordinates, or
real configuration files. See [SECURITY.md](SECURITY.md) before sharing logs.
