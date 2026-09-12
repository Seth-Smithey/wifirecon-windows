# wifirecon — the full guide

Version 2.1.0. Passive wireless survey, inventory and diagnostics for Windows,
built on the Native Wifi API. A native Qt desktop application.

---

## Contents

1. [What this is, and what it cannot do](#1-what-this-is-and-what-it-cannot-do)
2. [Installing](#2-installing)
3. [The one thing to understand: passive and active](#3-the-one-thing-to-understand-passive-and-active)
4. [Your first ten minutes](#4-your-first-ten-minutes)
5. [The interface](#5-the-interface)
6. [The thirteen views](#6-the-thirteen-views)
7. [Detections: reading them and tuning them](#7-detections-reading-them-and-tuning-them)
8. [Using it for consulting work](#8-using-it-for-consulting-work)
9. [Exports](#9-exports)
10. [GPS and wardriving](#10-gps-and-wardriving)
11. [Notifications, SIEM and webhooks](#11-notifications-siem-and-webhooks)
12. [Reaching it from another machine](#12-reaching-it-from-another-machine)
13. [Building an executable](#13-building-an-executable)
14. [Updating](#14-updating)
15. [Uninstalling](#15-uninstalling)
16. [Command line reference](#16-command-line-reference)
17. [Troubleshooting](#17-troubleshooting)
18. [Where things live](#18-where-things-live)
19. [Verifying an install](#19-verifying-an-install)

---

## 1. What this is, and what it cannot do

Windows does not expose true monitor mode for the MT7921AU, and the MediaTek
Windows driver does not support frame injection. So this is deliberately not a
port of the Kali tooling.

What it does have is `WlanGetNetworkBssList`, which returns the raw
information-element blob from every beacon and probe response the radio hears.
That is considerably more than `netsh wlan show networks` gives you, and it is
enough to build a real survey platform.

**Works:**

- Per-BSSID inventory with RSSI, channel, width, band, PHY generation
- Full RSN/WPA parsing: AKM suites, pairwise and group ciphers, PMF capable and
  required, PMKID count, group management cipher
- WPS decoding including manufacturer, model, device name and config methods
- HT / VHT / HE / EHT capability and operation elements, so Wi-Fi 4 through 7
- BSS Load: connected station count and channel utilisation from the AP itself
- Country code, regulatory environment, beacon interval, 802.11k/r/v support
- Vendor identification from the OUI, with MA-L / MA-M / MA-S support
- 26 detection rules, time-series history, GPS tagging, six export formats

**Does not work, and cannot on Windows:**

- WPA handshake or PMKID capture
- Deauthentication, injection, or any active attack
- Client and probe-request tracking — those frames are not addressed to you
- Rogue AP or evil twin *operation*

For any of that, a Kali VM stays where it is. This is the passive half, running
natively.

### A note on survey traffic

Surveying does not require network credentials or request association. It uses
`WlanScan`, so Windows and the driver may transmit probe requests. Radio silence
and absence of logs are not guaranteed. See Microsoft's
[WlanScan documentation](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanscan).

---

## 2. Installing

### Running from source (what you have)

**Double-click `Setup wifirecon.cmd`.** It finds Python, builds a virtual
environment in `.venv\`, installs the dependencies — Qt is about 200 MB, so
this takes a minute or two — downloads Wireshark's vendor database, puts a
shortcut on your desktop and in the Start Menu, and finishes by running
diagnostics.

**Then double-click `wifirecon.vbs`**, or the new desktop shortcut. It opens its
own window.

Use **`Start wifirecon (console).cmd`** instead when you want the log visible
while it runs. Same application; the console stays open and prints everything.

The one prerequisite is **Python 3.10 or newer with "Add python.exe to PATH"
ticked** during installation. Setup tells you if it is missing and where to get
it. It is only needed to run from source — a built executable has Python inside
it.

### Installing an executable

If you have a built `wifirecon.exe`, just run it. To install it properly, which
adds a Start Menu entry and makes it uninstall like any other Windows program:

```powershell
.\wifirecon.exe --install
```

That copies it to `%LOCALAPPDATA%\Programs\wifirecon`, creates the shortcut, and
registers it under **Settings → Apps → Installed apps**. No administrator
rights needed; everything is per-user.

```powershell
.\wifirecon.exe --install --autostart          # also start when you sign in
.\wifirecon.exe --install --desktop-shortcut
.\wifirecon.exe --install --install-dir "D:\Tools\wifirecon"
```

A folder build installs the whole folder, not just the executable — the exe on
its own is a stub that cannot start.

---

## 3. The one thing to understand: passive and active

This trips people up, so it is worth being explicit.

**The wireless survey does not need to be joined to any network.** It reads
beacons and probe responses through Windows. Scan requests may cause the driver
to send probes; this is not guaranteed passive capture. The status bar states
that no network connection is needed.

**Two views are active, and both ask before doing anything:**

| View | What it does | Needs a connection |
|---|---|---|
| **Devices** | Sends mDNS, SSDP and NetBIOS queries across the network *this machine* is joined to, and records what answers | Yes |
| **My network** | Joins a network, and can port-scan the hosts on it | Yes |

Neither of them uses the survey adapter. **Devices** in particular is not part
of the wireless scan at all — it is looking at IP hosts, not radios. If you
press Discover and get a list of `192.168.x.x` addresses, that is working as
intended and has nothing to do with the Alfa.

The wireless survey is **Live** and **Spectrum**.

---

## 4. Your first ten minutes

**1. Pick the adapter.** On first launch you get a picker before anything else.
Every wireless radio Windows can see is listed with its chipset, MAC, driver
version, supported bands and whether its radio is actually on. The one it
thinks you want is marked **recommended** — an external adapter with 6 GHz
support and its radio on scores highest, so an Alfa wins whenever it is plugged
in. Pick one and press **Start scanning**. Only then does anything touch the
radio.

**2. Check Diagnostics.** Everything should be green or amber. A red row tells
you exactly what to fix, and each failure comes with the specific remedy.

**3. Add your own networks as Trusted.** This matters more than anything else
on this list.

> Marks → kind `Trusted`, match on `Network name`, value = your SSID.

The impersonation rules compare what they hear against this list. **With it
empty, `lookalike_ssid` has no reference and will never fire** — and that is
the rule you actually want working. Add your home SSID and any work network you
care about. The application nudges you about this on startup until you do.

**4. Let it run for a bit.** Detections that depend on history — signal
anomalies, channel changes, beacon fingerprint drift — need a handful of scans
before they have a baseline. Give it fifteen minutes.

**5. Use the Networks view, not just Live.** Live lists one row per radio. A
tri-band access point puts the same name on 2.4, 5 and 6 GHz with a different
BSSID each, so 94 rows in Live might really be 40 networks. Networks groups by
name and shows every radio underneath, which is the count that reflects what is
actually around you. Rows in Live carry a `+5/6` chip when the same name
appears on another band.

**6. Look at Spectrum.** Blocks are drawn at their real centre frequency
spanning their real channel width, so overlap on screen is overlap in the air.

---

## 5. The interface

**The rail**, down the left, holds the thirteen views and a count beside Live,
Findings and Devices. The site picker at the top scopes survey work to one
engagement.

**The top left always names the adapter in use**, its band coverage, and a
status dot: grey idle, green scanning, red faulted. Click it to change adapter.

**Beside it**, Start/Stop and Single scan, then a strip showing what the engine
is doing right now — listening, reading, analysing, or counting down to the next
scan — so it is never ambiguous whether something is happening.

**Top right**, three readouts: in range, known, open findings.

**The status bar** shows the scan state, when the last scan was, how many this
session, and — permanently — that surveying needs no network connection.

### Keyboard

| Key | Action |
|---|---|
| `1`–`9`, `0` | Jump to a view |
| `s` | Start or stop scanning |
| `r` | Refresh status |
| `/` | Go to Live and focus the filter |
| `Escape` | Close the detail drawer |
| `Ctrl+R` | Single scan |
| `Ctrl+S` | Start or stop scanning |

### Themes

Dark and light, from **View → Switch theme** or the Settings screen. Band
colours follow wavelength in both: 2.4 GHz amber, 5 GHz cyan, 6 GHz violet.
That is the organising logic everywhere — chips, rows, the ribbon, the reports.

### Window state

Size, position and maximised state are remembered between runs, in the settings
file rather than the registry, so a portable copy keeps its layout.

---

## 6. The thirteen views

### Live

One row per radio in range. Sortable on every column. Signal is a bar coloured
by band plus the level in dBm; security is a set of badges — `OPEN`, `WEP`,
`WPS`, `802.1X`, `no PMF`; load is the AP's own reported utilisation and client
count.

- A **red stripe** on the left of a row means an open critical or high finding
  against that radio. A **cyan stripe** means you are watching it.
- Rows older than five minutes dim, so you can tell current from recent.
- **Right-click** a row to copy the BSSID, name or whole row, mark it trusted,
  watch it, ignore it, or open its detail.
- **Double-click** opens the detail drawer.
- **Export…** saves exactly the rows the filters are showing, as CSV, with the
  columns as they appear on screen.

Filters: text search across name, BSSID and vendor; band; time window; and
**Flagged only**, which narrows to radios with an open critical or high
finding.

### Spectrum

Three frequency ribbons, one per band, plus a per-channel occupancy table.

Every access point is a block at its real centre frequency spanning its real
channel width. Nothing is rounded to a channel number, because doing so would
hide exactly the overlap the view exists to show. Block colour is the band;
signal drives the fill opacity and the length of the meter along the bottom
edge. A block outlined in red has an open critical or high finding.

Blocks stack onto rows only when they would otherwise collide, so the ribbon
grows as the air gets busier. Hover for the full detail, click to open the
drawer.

The 6 GHz header also counts how many APs are on a **preferred scanning
channel**, because a 6 GHz radio that is not on one is far less discoverable.

### Findings

Detection output. Grouped by rule once there are more than a dozen, with the
worst-severity groups opened automatically. Severity, title, network, rule and
age; hover any row for the full detail and evidence.

- **Right-click** to acknowledge, reopen, open the network's detail, or **mute
  the rule entirely**.
- **Acknowledge all** clears the open list without deleting anything.
- **Reopen** puts acknowledged findings back.
- **Clear…** deletes, and asks which scope: acknowledged only, everything, one
  rule, or anything older than thirty days.

See [DETECTIONS.md](DETECTIONS.md) for every rule.

### Networks

One entry per network *name*, with every radio serving it nested underneath.
This is where inconsistent security shows up: a name offered as both WPA2 and
open is the shape of a credential-capture AP, and a flat list hides it.

Group tags call out `tri-band`, `dual-band`, `mixed security`, `802.1X`, `WPS`
and `PMF optional`. **Multi-band only** narrows to names on more than one band.

### Marks

The watch, trusted and ignore lists.

| Kind | What it does |
|---|---|
| **Trusted** | Teaches the impersonation rules what the real thing looks like. Add your own network names here first, or those rules have nothing to compare against. |
| **Watch** | Raises the severity of changes on a network, and enables `watched_ap_missing`. |
| **Ignore** | Silences a specific BSSID, vendor prefix or name entirely. |

Match on a full MAC address, a vendor prefix (OUI), an exact network name, or a
name prefix.

### Scan log

The engine's activity feed, newest last; every recent scan with its counts,
duration and any error; and every scanning session with its adapter and length.
This is where you look when you want to know what the engine has actually been
doing.

### Devices

**Active. Not the wireless survey. Does not use the survey adapter.**

Discovers IP hosts on the network this machine is joined to, using mDNS, SSDP,
NetBIOS and optionally Bluetooth, then resolves names. It asks before running,
because it sends queries and is visible to anything listening.

Broadcast, multicast and network addresses are hidden by default — they answer
on a network without being hosts on it. **Show broadcast and multicast** brings
them back if you want them.

### My network

**Active.** Four things, each explicit:

- **Connection** — what this machine is joined to, its signal, security,
  channel, gateway and subnets. "Not joined to a network" is a normal state for
  a survey machine, not a fault.
- **Join a network** — creates a profile and associates. The one part of the
  application that transmits.
- **Audit this network** — discovers hosts on your subnet and checks the listed
  ports on each. This connects to other people's machines, so it requires a
  typed confirmation and should only be run on a network you are responsible
  for.
- **Mobile hotspot** — shares this machine's connection over Wi-Fi. Untested on
  real hardware; treat a failure as expected rather than broken.

### Survey

The consulting workflow. Sites, walk-survey points, the coverage matrix, the
channel plan, and before/after snapshots. See
[section 8](#8-using-it-for-consulting-work).

### Report

The client-ready document, the access-point inventory, and the raw exports. See
[section 8](#8-using-it-for-consulting-work) and [section 9](#9-exports).

### Adapter

Every radio in full detail: hardware, MAC, bands, driver, state and whether the
radio is on. The one you are using is outlined.

**Diagnose & repair** looks underneath the Wi-Fi API at the USB device tree, so
it can tell "nothing plugged in" apart from "plugged in but not working", which
look identical otherwise. It then works through the fixes in order, stopping as
soon as the adapter appears:

1. Ask Windows to re-scan for hardware changes
2. Start the WLAN AutoConfig service if it is stopped
3. Check whether VMware or VirtualBox has claimed the USB device
4. Enable adapters that were disabled (problem code 22)
5. Restart adapters whose driver loaded and then failed (codes 10, 43, 31)
6. Bind a driver from the driver store to adapters that have none (code 28)
7. Check whether the radio is switched off in software or hardware
8. Restart WLAN AutoConfig to force a re-enumeration

Most of those need administrator rights. Running unelevated it changes nothing,
tells you which steps are blocked, and offers to run just those in a
short-lived elevated helper — Windows prompts once, the application keeps
running, and your session survives.

**It never uninstalls, deletes or disables anything.** Every step reports what
it did and whether it worked.

If the adapter you chose is unplugged mid-session, scanning stops and says so
rather than quietly continuing on the laptop's built-in radio.

### Diagnostics

Health checks with the specific fix for each failure, where everything lives on
disk, upkeep actions (prune, compact, reload the vendor database), and the tail
of the log.

Run it first whenever something is wrong.

### Settings

Everything, grouped: scanning, detections, Windows notifications, webhook,
syslog, GPS, retention, remote access, interface, updates. Then the two
destructive operations, both gated:

- **Clear observed networks** — forgets every network and its history. Marks,
  sites and inventory are kept.
- **Wipe everything** — deletes all of it. Requires typing `WIPE EVERYTHING`.

---

## 7. Detections: reading them and tuning them

Every rule runs on every scan. Findings go to the database and then to whichever
notification channels are on. A finding is suppressed for `suppress_seconds`
(fifteen minutes by default) after it fires for the same rule and target, so a
persistent condition does not repeat every twenty seconds.

Severity ladder: `info` < `low` < `medium` < `high` < `critical`.

### Two kinds of rule

**Event rules** report one finding per radio, because the thing they describe
is specific to that radio: a lookalike name, an enterprise downgrade, a
security change, a beacon fingerprint change, a channel move.

**Inventory rules** describe a standing property of the neighbourhood — WPS
being on, PMF being absent, a channel being busy — and report **one summary
finding with a count**, not one per access point:

> WPS enabled on 17 of 286 nearby APs (9 PIN-capable)

The strongest three by signal are named in the detail, and the full per-radio
list is in the evidence. This is deliberate: in a dense area, one finding per
access point produced hundreds of rows a scan and buried the handful that
mattered.

### Tuning, in the order worth trying

**1. Add trusted marks.** Not really tuning, but it is what switches the most
valuable rules on. Nothing else here matters as much.

**2. Mute rules you do not care about.** Right-click any finding →
*Mute '<rule>'*. Existing findings stay; no new ones are raised. Stored in
`detections.muted_rules`.

**3. Raise the severity floor.** Settings → Detections → Severity floor. It
ships at `low`, which keeps inventory-style rules like `open_network` out of the
way. Raise it to `medium` or `high` in a dense area.

**4. Lengthen the cooldown.** `suppress_seconds`, per rule and target.

**5. Use Ignore marks** for a specific BSSID, vendor prefix or name that is
noisy and known-good.

### The beacon fingerprint

`ie_fingerprint_change` reports that an access point now advertises a different
set of information elements. Firmware updates do this; so does a different
device claiming the same MAC.

The fingerprint deliberately ignores ten volatile element IDs — TIM, BSS Load,
ERP, channel-switch announcements and so on — because a beacon always carries
TIM and a probe response never does, and Windows caches whichever frame it last
received. Including them made the fingerprint flip constantly.

When it does change, the finding says what changed — *"Added: 48. Removed:
nothing."* — and ranks `high` rather than `low` if the elements that carry the
security posture were among them.

---

## 8. Using it for consulting work

Everything below is under **Survey** and **Report**.

### Set up a site first

Report or Survey → add the client name and address. Survey points, AP inventory
and snapshots all belong to the selected site, so separate engagements stay
separate. Pick the active site from the dropdown at the top of the left rail.

### Walk survey

Stand somewhere, name it ("Reception", "Suite 204"), press **Capture point**.
It runs a fresh scan and records every network audible from that spot.

Do that at each location the client cares about and the coverage matrix fills
in: signal for every network at every point, colour-graded against the
thresholds survey reports are normally written to.

> Above &minus;67 dBm supports voice. Below &minus;72 dBm is unreliable.

It also tells you which locations have no usable signal at all and which
networks have gaps.

A location where nothing was audible is a real result, and it records as one.

### Channel plan

Scores every channel on how many access points occupy or overlap it, how strong
those are, and reported channel utilisation. Recommends where to put new radios
in each band, with the reasoning for each pick.

It knows 2.4 GHz has only three non-overlapping channels, flags DFS channels in
5 GHz as usable but liable to vacate on radar, and prefers the 6 GHz preferred
scanning channels so new APs are discoverable.

### Before and after

Take a snapshot, do the work, compare. It reports what appeared, what went
away, and what changed — channel moves, security changes, and signal shifts
over 10 dB. Useful for proving remediation actually landed.

### AP inventory

Label the access points you manage, with location and asset tag. Open any
network from Live and use **Add to inventory**. Reports then name them properly,
and anything unlabelled stands out as unmanaged.

### The client report

Report → title, your name, the window to cover, what to include, then **Open
the report** or **Save as…**.

You get a self-contained HTML document: executive summary, findings grouped and
explained in plain language for a non-technical reader, channel plan, coverage
results with recommendations, AP inventory, and the full network list. It prints
cleanly to PDF straight from the browser.

The report explains the Windows survey method and its limits. Record separate
network discovery, association or audit activity in your engagement notes.

---

## 9. Exports

From the Report view, or `/api/export/<name>` when the server is running.

| File | What |
|---|---|
| `networks.csv` | Every radio seen, one row each |
| `alerts.csv` | Every finding |
| `observations.csv` | The full time series |
| `wigle.csv` | WiGLE 1.6 upload format |
| `survey.kml` | Google Earth |
| `survey.json` | Everything, as JSON |
| `report.html` | The survey report on its own |

Live has its own **Export…**, which saves exactly the filtered rows with the
columns as shown — useful when you want a slice rather than everything.

---

## 10. GPS and wardriving

With a serial NMEA receiver, every observation gets a coordinate and the WiGLE
and KML exports become useful.

Settings → GPS → enable, then pick the COM port and baud rate. `pyserial` is
needed and is not installed by default:

```powershell
.venv\Scripts\python.exe -m pip install pyserial
```

For a built executable, use one made with `.\build.ps1 -WithGps`.

A fix older than `stale_seconds` is treated as no fix rather than a stale
coordinate.

---

## 11. Notifications, SIEM and webhooks

Findings always land in the Findings view. Optionally they also go to:

- **Windows toast notifications**
- **The Windows event log**
- **An HTTP webhook** — JSON POST, with a `text` field that Slack and Teams
  incoming webhooks render directly
- **Syslog over UDP or TCP**, formatted as CEF, JSON or RFC 5424

Each channel has its own minimum severity and a **Test** button that sends a
synthetic finding, so you can confirm the pipeline before waiting for a real
one.

**For Splunk or Wazuh:** Settings → Syslog → point it at your collector and
leave the format on CEF.

---

## 12. Reaching it from another machine

The desktop application opens no port at all. To reach a running survey from
elsewhere — a phone, a laptop across the room — there is an optional web
interface.

1. Settings → Remote access → **Reachable from other machines**. An API token
   is generated automatically.
2. Start the server: `python -m app --server`

That binds every interface and requires the token on every request, in an
`X-Api-Token` header or a `token` query parameter.

**There is no TLS and no user accounts.** Put it behind something else if it
needs to be exposed beyond a trusted LAN.

Both interfaces call the same service layer, so they agree on everything.

---

## 13. Building an executable

```powershell
.\build.ps1
```

Takes a few minutes. Produces `dist\wifirecon\` with the executable in it,
`SHA256SUMS.txt`, and a zip of the folder you can hand to someone. The build
smoke-tests the binary before it finishes, so if it completes, it works.

| Option | Effect |
|---|---|
| `-OneFile` | One portable exe instead of a folder |
| `-WithGps` | Bundles pyserial |
| `-Version 1.2.0` | Sets the version first |
| `-Release` | Publishes a GitHub release (needs `gh`) |
| `-Clean` | Rebuilds the build environment |
| `-SkipTest` | Skips the smoke test |

### Why a folder is the default

The interface is Qt, and a one-file build has to unpack the whole Qt runtime to
a temporary directory on every launch. That is slow, and a self-extracting
unsigned executable is the exact shape antivirus heuristics complain about. A
folder build starts immediately and gets flagged far less often.

### Giving it to someone else

Send them the zip from `dist\`. Two things will happen:

- **SmartScreen will warn them.** The executable is unsigned. *More info* →
  *Run anyway*.
- **CrowdStrike or Defender may flag it.** Add an exclusion for the path, or
  upload the hash to an allowlist.

The real fix is a code signing certificate. Worth it only if this starts going
to client machines rather than friends.

UPX compression is deliberately disabled in the spec, because it makes the
antivirus problem considerably worse.

---

## 14. Updating

### From a zip

Drop the new zip onto **`Update wifirecon.cmd`**, or run:

```powershell
python -m app --update-from "C:\path\to\wifirecon-win.zip"
python -m app --list-backups
python -m app --rollback 20260830-004816-v2.0.0-preupdate
```

Every update backs up the previous version first, and the last three are kept.
If a backup cannot be completed, the update refuses to start rather than
leaving you with no way back. Your database, settings, sites, survey data and
virtual environment are never touched.

### From a GitHub release

The updater looks for releases at the repository named in `app/updater.py`:

```python
REPO = "Seth-Smithey/wifirecon-win"
```

The release updater has no GitHub authentication for private releases;
use a signed-in browser when download access requires it. Folder builds
require manual extraction of the complete ZIP. Source checkouts can use
authenticated Git. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the release process.

---

## 15. Uninstalling

Three ways, all equivalent:

- **Settings → Apps → Installed apps → wifirecon → Uninstall**
- **Settings → Installation → Uninstall wifirecon** in the application
- `wifirecon.exe --uninstall` (add `--keep-data` to leave the database alone)

Any of them removes the shortcuts, the autostart entry, the registry entry, the
data directory and the executable. The executable deletes itself a couple of
seconds after exiting, since a running program cannot delete its own file. If
the install folder contains anything you put there, the folder is left in place.

Running from source, there is nothing to uninstall — delete the folder, and
`%LOCALAPPDATA%\wifirecon-win\` if you want the data gone too.

---

## 16. Command line reference

From source, `python -m app`. From a build, `wifirecon.exe`.

| Flag | Effect |
|---|---|
| *(none)* | Open the desktop application |
| `--console` | Keep the console visible and print to it |
| `--server` | Run the web interface instead, for remote access |
| `--port N` | With `--server`, bind a different port |
| `--host ADDR` | With `--server`, bind a different address |
| `--browser` | With `--server`, open a browser |
| `--no-browser` | With `--server`, do not |
| `--mock` | Synthetic data. Nothing touches the radio |
| `--scan-once` | One scan, print the result, exit |
| `--doctor` | Diagnostics. Exit code 1 on any failure |
| `--version` | Print the version and exit |
| `--status` | Install state as JSON |
| `--install` | Install per-user, with a Start Menu entry |
| `--autostart` | With `--install`, start on sign-in |
| `--desktop-shortcut` | With `--install` |
| `--install-dir PATH` | With `--install` |
| `--uninstall` | Remove it |
| `--keep-data` | With `--uninstall`, keep the database |
| `--update` | Check for and apply a release update |
| `--update-from ZIP` | Update from a local package |
| `--list-backups` | Versions available to roll back to |
| `--rollback NAME` | Roll back to one |
| `--check-adapter` | Report why an adapter is unavailable. Changes nothing |
| `--fix-adapter` | Apply the adapter repairs |

`--doctor` returns a non-zero exit code when a check fails, so it works as a
monitoring probe.

`python -m tools.verify` runs 75 self-checks over the service layer, the
spectrum geometry, the threading, the detection rules and every view. It is the
fastest way to tell a broken install from a broken adapter.

---

## 17. Troubleshooting

**Run diagnostics first**, either in the application or with
`python -m app --doctor`. It checks the WLAN AutoConfig service, the Native
Wifi API, adapters, privileges, disk, database and dependencies, and every
failure comes with the specific fix.

### No window appears

Use `Start wifirecon (console).cmd`, which keeps the console open and prints the
reason. Exit code 3 means the interface component is missing:

```powershell
.venv\Scripts\python.exe -m pip install PySide6-Essentials
```

Exit code 4 means the data directory is not writable. Set `WIFIRECON_DATA_DIR`
somewhere it can write.

For a built executable, `wifirecon.exe --console` keeps the console and prints
Qt's own startup errors.

### No networks appear

Confirm `wlansvc` is running (`net start wlansvc`) and that the adapter shows
cleanly in Device Manager. A yellow triangle means the driver never bound — use
**Diagnose & repair** on the Adapter view.

You do **not** need to be joined to a network. If that is what you were
waiting for, press Start scanning.

### "Access denied" from WlanScan

Run as Administrator.

### Results only refresh every 20 seconds

That is Windows, not the application. Scan requests are rate-limited to roughly
four a minute per adapter, which is why the interval setting has a floor.
Shorter intervals just re-read the same cached list.

### The adapter shows fewer bands than it has

The band list comes from the driver first, then from beacons actually received.
If a 6 GHz network has come back through this adapter, the band list says 6 GHz
whatever the driver claims, and the Adapter view says where the answer came
from.

If the hardware covers 6 GHz but the driver only reports 2.4 and 5, installing
Alfa's or MediaTek's own driver usually adds the band.

### The adapter disappears when a VM is running

VMware's USB arbitration service claims USB devices. **Diagnose & repair**
checks for this explicitly and names it. Detach the device from the VM, or stop
`VMUSBArbService`.

### Hundreds of findings

Expected on a first scan in a dense area, and it settles. If it does not, work
through [section 7](#7-detections-reading-them-and-tuning-them) — add trusted
marks, mute the rules you do not care about, raise the severity floor.

### Vendors show as unknown

The built-in list covers common AP vendors. For full coverage, save Wireshark's
`manuf` file into `%LOCALAPPDATA%\wifirecon-win\` and use **Reload vendor
database** on the Diagnostics view. Setup tries to fetch it automatically.

### Windows SmartScreen blocks the executable

It is unsigned. *More info* → *Run anyway*, or sign it yourself.

### The update said it restarted but nothing came back

Start it from the Start Menu. If the executable is missing, a
`wifirecon.exe.old` sits next to where it was — rename it back. Or
`--list-backups` and `--rollback`.

---

## 18. Where things live

| Path | What |
|---|---|
| `%LOCALAPPDATA%\Programs\wifirecon\` | The installed program |
| `%LOCALAPPDATA%\wifirecon-win\wifirecon.db` | SQLite store |
| `%LOCALAPPDATA%\wifirecon-win\config.json` | Settings, including window geometry |
| `%LOCALAPPDATA%\wifirecon-win\wifirecon.log` | Rotating log |
| `%LOCALAPPDATA%\wifirecon-win\manuf` | Vendor database (optional) |
| `%LOCALAPPDATA%\wifirecon-win\backups\` | Pre-update backups |
| `%LOCALAPPDATA%\wifirecon-win\reports\` | Reports opened from the application |

Data is deliberately separate from the program, so updating replaces only the
code. Set `WIFIRECON_DATA_DIR` to move all of it — onto a USB stick, for
instance, for a genuinely portable install.

Other environment variables: `WIFIRECON_DB`, `WIFIRECON_PORT`,
`WIFIRECON_TOKEN`, `WIFIRECON_LOG_LEVEL`, `WIFIRECON_MOCK`.

---

## 19. Verifying an install

```powershell
python -m tools.verify
```

75 checks over the service layer, the spectrum geometry, the threading bridge,
the theme, the detection rules, the destructive-operation gates and every view.
Runs against a temporary database seeded from synthetic data, so it never
touches your real data. Takes about forty seconds.

```powershell
python -m app --doctor
```

Health checks against the actual machine: the WLAN service, the API, adapters,
privileges, disk, database and dependencies. Exit code 1 on any failure.

```powershell
python -m app --scan-once --mock
```

Exercises the whole pipeline — parse, detect, store — against synthetic data
without touching the radio.

Between the three, a failure tells you whether the problem is the code, the
machine, or the radio.

---

*Surveying does not require association. Windows may send probe requests.
Devices and My network perform additional network activity after confirmation.*
