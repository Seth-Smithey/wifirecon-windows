# wifirecon-win

[![CI](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/ci.yml/badge.svg)](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/ci.yml)
[![Security](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/security.yml/badge.svg)](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/security.yml)
[![CodeQL](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/codeql.yml/badge.svg)](https://github.com/Seth-Smithey/wifirecon-windows/actions/workflows/codeql.yml)

Download the Windows ZIP and its SHA-256 checksum from
[Releases](https://github.com/Seth-Smithey/wifirecon-windows/releases/latest).
Extract the complete folder before running `wifirecon.exe`. Folder installations
update by extracting a new release package. Builds are currently unsigned.

Wireless survey and inventory for Windows, built on the Native
Wifi API. A native desktop application: no VM, no monitor mode, no driver
replacement, and no embedded browser.

## What this can and cannot do

Windows does not expose true monitor mode for the MT7921AU, and the MediaTek
Windows driver does not support frame injection. So this is deliberately not a
port of the Kali tooling.

What it **does** have is `WlanGetNetworkBssList`, which returns the raw
information-element blob from every beacon and probe response the radio hears.
That is considerably more than `netsh wlan show networks` gives you, and it is
enough to build a real survey platform.

**Works:**

- Per-BSSID inventory with RSSI, channel, width, band, PHY generation
- Full RSN/WPA parsing: AKM suites, pairwise and group ciphers, PMF capable
  and required, PMKID count, group management cipher
- WPS decoding including manufacturer, model, device name and config methods
- HT / VHT / HE / EHT capability and operation elements, so Wi-Fi 4 through 7
- BSS Load: connected station count and channel utilisation straight from the AP
- Country code, regulatory environment, beacon interval, 802.11k/r/v support
- Vendor identification from the OUI, with MA-L / MA-M / MA-S support
- 26 detection rules, time-series history, GPS tagging, six export formats

**Does not work, and cannot on Windows:**

- WPA handshake or PMKID capture
- Deauthentication, injection, or any active attack
- Client and probe-request tracking — those frames are not addressed to you
- Rogue AP or evil twin *operation*

For any of that, the Kali VM stays where it is. This is the passive half, running
natively.

## Documentation

- **[START-HERE.txt](START-HERE.txt)** - two steps to get it running
- **[docs/GUIDE.md](docs/GUIDE.md)** - the full guide: every view, the
  consulting workflow, tuning, building an executable, troubleshooting
- **[docs/DETECTIONS.md](docs/DETECTIONS.md)** - all 26 detection rules
- **[QUICKSTART.md](QUICKSTART.md)** - condensed setup
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - development, CI and release workflow

## Install

For source setup, clone this repository with your authenticated Git client:

```powershell
git clone https://github.com/Seth-Smithey/wifirecon-windows.git
cd wifirecon-win
cmd /c "Setup wifirecon.cmd"
```

Python 3.10 or newer is required. Setup installs dependencies into `.venv`.
Then double-click `wifirecon.vbs` (or use `Start wifirecon (console).cmd`).

For a packaged build, download the `wifirecon-windows` artifact from a successful
GitHub Actions run, or the application ZIP from Releases when one is published.
Extract it and keep `wifirecon.exe` with its `_internal` folder. Python is bundled.
Sign in to GitHub when a download requires it. See [SECURITY.md](SECURITY.md)
for reporting vulnerabilities and handling survey data safely.

**Just run it.** Double-click. It opens its own window — Qt widgets, drawn
natively, no Edge and no WebView2 — and the console hides itself. Everything
works this way, portably, off a USB stick if you like.

**Or install it properly**, which adds a Start Menu entry and makes it uninstall
like any other Windows program:

```powershell
.\wifirecon.exe --install
```

That copies it to `%LOCALAPPDATA%\Programs\wifirecon`, creates the shortcut, and
registers it under **Settings → Apps → Installed apps**. No administrator rights
needed; everything is per-user.

```powershell
.\wifirecon.exe --install --autostart          # also start when you sign in
.\wifirecon.exe --install --desktop-shortcut
.\wifirecon.exe --install --install-dir "D:\Tools\wifirecon"
```

## Run

```powershell
wifirecon.exe                  # open the application, hide the console
wifirecon.exe --console        # keep the console visible
wifirecon.exe --server         # run the web server for remote access instead
wifirecon.exe --port 9000      # with --server
wifirecon.exe --doctor         # diagnostics, exit code 1 on any failure
wifirecon.exe --scan-once      # one scan, print the result, exit
wifirecon.exe --mock           # synthetic data, useful for demos
wifirecon.exe --status         # install state as JSON
```

## Updating

For a Git checkout, close the app, run `git pull --ff-only`, and rerun setup if
dependencies changed. Commit or stash your own edits before pulling.

For a folder build, close the app and extract the new ZIP into a new folder.
Run the new executable with its supporting files. Survey data remains under
`%LOCALAPPDATA%\wifirecon-win` unless you configured a custom data directory.

The built-in release updater supports public releases. It can replace
single-file executables, but cannot install
folder ZIPs automatically. Download the complete folder ZIP instead.

### Shipping an update

```powershell
.\build.ps1
```

That builds and smoke-tests the app, then writes the complete ZIP and its
`SHA256SUMS.txt` to `dist`. See [CONTRIBUTING.md](CONTRIBUTING.md) for publishing
a tagged release with `-Release`.

## Uninstalling

Three ways, all equivalent:

- **Settings → Apps → Installed apps → wifirecon → Uninstall**
- **Settings tab → Installation → Uninstall wifirecon** in the app itself
- `wifirecon.exe --uninstall` (add `--keep-data` to leave the database alone)

Any of them removes the shortcuts, the autostart entry, the registry entry, the
data directory and the executable. The executable deletes itself a couple of
seconds after exiting, since a running program cannot delete its own file. If
the install folder contains anything you put there, the folder is left in place.

## Building from source

```powershell
git clone https://github.com/Seth-Smithey/wifirecon-windows.git
cd wifirecon-win
.\build.ps1
```

This produces `dist\wifirecon\` and a zip beside it you can hand to someone.
A folder build is the default because Qt is large: a single-file executable has
to unpack the whole runtime on every launch, which is slow and is the shape
antivirus heuristics dislike most.

Options: `-OneFile` (the single portable executable anyway), `-WithGps`
(bundles pyserial), `-Clean`, `-Version 1.2.0`, `-Release`, `-SkipTest`.

To run from source instead of building, double-click `Setup wifirecon.cmd` then
`wifirecon.vbs`. The `.cmd` launchers work regardless of PowerShell's
execution policy, which the `.ps1` scripts do not. `install.ps1` and `run.ps1`
still exist and do the same thing if you prefer them.

### A note on antivirus

PyInstaller single-file executables are unsigned and unpack themselves at
startup, which is a shape heuristic scanners dislike. A fresh build may get
flagged on first run. Options, in order of preference: sign it with a code
signing certificate, build with `-OneDir`, or add an exclusion. UPX compression
is deliberately disabled in the spec because it makes this considerably worse.

## Where things live

| Path | What |
|---|---|
| `%LOCALAPPDATA%\Programs\wifirecon\wifirecon.exe` | The program |
| `%LOCALAPPDATA%\wifirecon-win\wifirecon.db` | SQLite store |
| `%LOCALAPPDATA%\wifirecon-win\config.json` | Settings |
| `%LOCALAPPDATA%\wifirecon-win\wifirecon.log` | Rotating log |
| `%LOCALAPPDATA%\wifirecon-win\manuf` | Vendor database (optional) |
| `%LOCALAPPDATA%\wifirecon-win\updates\` | Update staging |

Data is deliberately separate from the program, so updating replaces only the
executable. Set `WIFIRECON_DATA_DIR` to move all of it.

## Interface

A native Qt application. Thirteen views in the left rail, keyboard shortcuts
`1`–`9` and `0`, `s` to start or stop scanning, `r` to refresh, `/` to jump to
Live and focus the filter.

**Live** — everything in range, sortable, with signal bars, security posture,
PHY generation and reported load. Right-click a row to copy it, mark it, or
open its detail. Export saves exactly the rows the filters are showing.

Surveying needs no network connection and does not request association.
It calls `WlanScan`, so Windows and the driver may send probe requests; this
is not guaranteed radio-silent capture. See Microsoft's
[WlanScan documentation](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanscan).

**Spectrum** — the frequency-accurate occupancy ribbon. Every AP is drawn at its
real centre frequency spanning its real channel width, so overlap on screen is
overlap in the air. Block height tracks signal strength. Band colours follow
wavelength: 2.4 GHz amber, 5 GHz cyan, 6 GHz violet.

**Findings** — detection output with evidence, acknowledgement and filtering.
Rules that describe a standing property of the neighbourhood report once with
a count rather than once per access point, and any rule can be muted from its
context menu. See [docs/DETECTIONS.md](docs/DETECTIONS.md).

**Networks** — grouped by SSID, which is where inconsistent security shows up.

**Marks** — watch, trusted and ignore lists. Add your own networks as trusted
first; the impersonation rules need a reference to compare against.

**Devices**, **My network**, **Survey**, **Report**, **Adapter**, **Scan log**,
**Diagnostics**, **Settings**.

Dark and light themes, switchable from View or the Settings screen.

## Notifications

Findings always land in the Findings tab. Optionally they also go to:

- Windows toast notifications
- An HTTP webhook (JSON POST, works with Slack and Teams incoming webhooks)
- Syslog over UDP or TCP, formatted as CEF, JSON or RFC 5424

CEF is the one to use for Splunk or Wazuh. Each channel has its own minimum
severity and a Test button.

## Exports

`networks.csv`, `alerts.csv`, `observations.csv`, `wigle.csv` (WiGLE 1.6),
`survey.kml` (Google Earth), `survey.json`, and `report.html` — a self-contained
survey report you can hand to someone else.

## GPS

With a serial NMEA receiver, every observation gets a coordinate and the WiGLE
and KML exports become useful. The default build does not bundle pyserial, so
use a build made with `.\build.ps1 -WithGps`. Then pick the COM port in Settings.

## Command line

Every flag above works on the executable. From source, substitute
`python -m app` for `wifirecon.exe`.

`--doctor` returns a non-zero exit code when a check fails, so it works as a
monitoring probe.

## Remote access

The desktop application opens no port at all. To reach a running survey from
another machine, turn on **Reachable from other machines** in Settings and
start the server with `wifirecon.exe --server`. That binds all interfaces and
requires an API token on every request, in an `X-Api-Token` header or a `token`
query parameter. There is no TLS and no user accounts — put it behind something
else if it needs to be exposed.

Both interfaces call the same service layer, so they agree on everything.

## Troubleshooting

Run diagnostics first: `.\run.ps1 -Doctor`. It checks the WLAN AutoConfig
service, the API, adapters, privileges, disk, database and dependencies, and
each failure comes with the specific fix.

**No networks appear.** Confirm `wlansvc` is running (`net start wlansvc`) and
that the adapter shows cleanly in Device Manager. A yellow triangle means the
driver never bound.

**"Access denied" from WlanScan.** Run as Administrator.

**Results only refresh every 20 seconds.** Windows rate-limits scan requests to
roughly four a minute per adapter. Shorter intervals just re-read the same
cached list, which is why the setting has a floor.

**Vendors show as unknown.** The built-in list covers common AP vendors. For
full coverage, save Wireshark's `manuf` file into
`%LOCALAPPDATA%\wifirecon-win\` and restart.

**Windows SmartScreen blocks it.** The executable is unsigned. Click *More info*
→ *Run anyway*, or sign it yourself. Handing the build to someone else means
they will see this too; a folder build trips it noticeably less than a
single-file one.

**No window appears.** The interface needs PySide6. Run `wifirecon --doctor`,
which names it if it is missing, or `pip install PySide6-Essentials` from the
project's `.venv`.

**The update said it restarted but nothing came back.** Start it from the Start
Menu. If the executable is missing, a `wifirecon.exe.old` sits next to where it
was — rename it back.
