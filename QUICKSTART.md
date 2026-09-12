# Quick start

## Setting up

**Double-click `Setup wifirecon.cmd`.** That is the whole thing.

It finds Python, builds the environment, installs what it needs — including Qt,
which is about 200 MB and takes a minute — downloads the vendor database, puts a
shortcut on your desktop and in the Start Menu, and runs diagnostics. No
PowerShell, no execution policy, no commands to type.

Then **double-click `wifirecon.vbs`**, or the wifirecon shortcut on your desktop.
It opens its own window. Closing the window stops the application and closes the
session cleanly.

Use **`Start wifirecon (console).cmd`** instead when you want the log visible.

If you skip setup and launch straight away, the launcher notices and sets itself
up first.

**The one prerequisite** is Python 3.10 or newer with "Add python.exe to PATH"
ticked during installation. Setup tells you if it is missing and where to get it.
It is only needed to run from source — a built executable has it inside.

### Updating

You never need to delete and reinstall again. Three ways, all keeping your
database, settings, sites, survey data and virtual environment:

**Drag and drop.** Diagnostics tab → Update → drop the new zip on the box. It
checks the package is genuine, shows you which version it contains, backs up
what you have, swaps the files and restarts itself.

**Drag onto the launcher.** Drop the zip onto `Update wifirecon.cmd`. Same
thing, no browser needed. It also refreshes dependencies afterwards.

**From a prompt.**

```powershell
wifirecon --update-from "C:\path\to\wifirecon-win.zip"
wifirecon --list-backups
wifirecon --rollback 20260830-004816-v1.4.1-preupdate
```

Every update backs up the previous version first, and the last three are kept.
If a backup cannot be completed, the update refuses to start rather than leaving
you with no way back.

### If the adapter will not come online

Use **Diagnose & repair** in the app. When a fix needs administrator rights it
runs that part in a short-lived helper process — Windows prompts once, the app
keeps running, and your page stays open.

If you would rather do it from outside the app, double-click
`Repair adapter (admin).cmd`, which elevates itself and prints every step.

---


## 1. See it working in two minutes (no adapter needed)

This runs against synthetic data, so you can look at the whole interface before
plugging anything in.

```powershell
cd wifirecon-win
.\install.ps1
.\run.ps1 -Mock
```

The application opens with about 20 fake access points, a populated spectrum
ribbon, and real detection findings. Nothing touches your radio.

Close the window, or press Ctrl+C in the console, to stop it.

---

## 2. Run it for real, from source

```powershell
.\run.ps1
```

Same thing, live. Check the **Diagnostics** tab first — it will tell you
straight away if the WLAN service is stopped or the adapter has not bound.

---

## 3. Build the executable

This is what you want long term: one file, no Python needed on the machine
you run it on.

```powershell
.\build.ps1
```

Takes a few minutes. Output lands in `dist\wifirecon\` alongside
`SHA256SUMS.txt`, plus a zip of the folder you can send to someone. The build
smoke-tests the binary before it finishes, so if it completes, it works.

A folder build is the default because Qt is large. `.\build.ps1 -OneFile` gives
you the single portable executable instead.

Then either just run `dist\wifirecon\wifirecon.exe`, or install it properly:

```powershell
.\dist\wifirecon\wifirecon.exe --install --autostart
```

That puts it in `%LOCALAPPDATA%\Programs\wifirecon`, adds a Start Menu entry,
registers it under Settings → Apps so it uninstalls normally, and sets it to
start when you sign in.

---

## Prerequisite

Python 3.10 or newer, with **Add python.exe to PATH** ticked during install.
Only needed to build or run from source — the finished exe has it baked in.

```powershell
python --version
```

If that fails, get it from https://www.python.org/downloads/

---

## If the adapter does not show up

The picker has a **Diagnose & repair** button, and it runs automatically when no
adapter is available. It looks underneath the Wi-Fi API at the USB device tree,
so it can tell "nothing plugged in" apart from "plugged in but disabled", which
look identical otherwise.

It then works through the fixes in order, stopping as soon as the adapter
appears:

1. Ask Windows to re-scan for hardware changes
2. Start the WLAN AutoConfig service if it is stopped
3. Check whether VMware or VirtualBox has claimed the USB device
4. Enable adapters that were disabled (problem code 22)
5. Restart adapters whose driver loaded and then failed (codes 10, 43, 31)
6. Bind a driver from the driver store to adapters that have none (code 28)
7. Check whether the radio is switched off in software or hardware
8. Restart WLAN AutoConfig to force a re-enumeration

Most of those need administrator rights. Running unelevated it changes nothing,
tells you which steps are blocked, and offers a **Restart as administrator**
button that goes through the normal Windows prompt.

It never uninstalls, deletes or disables anything. Every step reports what it
did and whether it worked.

From a prompt:

```powershell
wifirecon.exe --check-adapter   # report only, changes nothing
wifirecon.exe --fix-adapter     # apply the repairs
```

Known adapters are identified by USB vendor and product ID, so a driverless
device with no friendly name still reads as "MediaTek MT7921AU (Alfa
AWUS036AXML)" rather than "Unnamed device".

## It does not scan until you say so

On first launch you get an adapter picker before anything else. Every wireless
radio Windows can see is listed with its chipset, MAC, driver version, supported
bands and whether its radio is actually on. The one it thinks you want is marked
**recommended** — an external adapter with 6 GHz support and its radio on scores
highest, so the Alfa wins whenever it is plugged in.

Pick one, press **Start scanning**, and only then does it touch the radio.

After that, the adapter you are on is shown permanently in the top left, with
the band coverage underneath and a status dot. Click it any time to switch. The
strip beside it shows what the engine is doing right now — listening, reading,
analysing, or counting down to the next scan — so it is never ambiguous whether
something is happening.

If the adapter you chose is unplugged mid-session, scanning stops and says so
rather than quietly continuing on the laptop's built-in radio.

To have it resume scanning automatically on launch instead, there is a setting
under Settings → Scanning. It is off by default.

## First ten minutes in the interface

**1. Check Diagnostics.** Everything should be green or amber. A red row tells
you exactly what to fix. The Wireless adapters row names the exact adapter in
use, its bands and its MAC.

**2. Confirm the adapter.** The Adapter tab shows every radio in full detail,
the live activity feed, and every previous scanning session.

**3. Add your own networks as trusted.** This matters more than anything else on
this list. Marks → kind `Trusted`, match on `Network name`, value = your SSID.

The impersonation rules compare against this list. With it empty,
`lookalike_ssid` has no reference and will never fire — which is the rule you
actually want working. Add your home SSID, and any RSOC or ASU network you care
about.

**4. Let it run for a bit.** Detections that depend on history — signal
anomalies, channel changes, beacon fingerprint drift — need a handful of scans
before they have a baseline. Give it fifteen minutes.

**5. Use the Networks view, not just Live.** Live lists one row per radio. A
tri-band access point puts the same name on 2.4, 5 and 6 GHz with a different
BSSID each, so 94 rows in Live might really be 40 networks. Networks groups by
name and shows every radio underneath, which is the count that reflects what is
actually around you. Rows in Live carry a `+5/6` chip when the same name appears
on another band.

**6. Look at Spectrum.** Blocks are drawn at real centre frequency spanning real
channel width, so overlap on screen is overlap in the air.

---

## Using it for consulting work

Everything below is under the **Survey** and **Report** tabs.

**Set up a site first.** Report tab → add the client name and address. Survey
points, AP inventory and snapshots all belong to the selected site, so separate
engagements stay separate. Pick the active site from the dropdown at the top of
the left rail.

**Walk survey.** Stand somewhere, name it ("Reception", "Suite 204"), press
capture. It runs a fresh scan and records every network audible from that spot.
Do that at each location the client cares about and the coverage matrix fills in:
signal for every network at every point, colour-graded against the thresholds
survey reports are normally written to. Above &minus;67 dBm supports voice, below
&minus;72 is unreliable. It also tells you which locations have no usable signal
at all and which networks have gaps.

**Channel plan.** Scores every channel on how many access points occupy or
overlap it, how strong those are, and reported channel utilisation. Recommends
where to put new radios in each band. It knows 2.4 GHz only has three
non-overlapping channels, flags DFS channels in 5 GHz as usable but liable to
vacate on radar, and prefers the 6 GHz scanning channels so new APs are
discoverable.

**Before and after.** Take a snapshot, do the work, compare. It reports what
appeared, what went away, and what changed — channel moves, security changes,
and signal shifts over 10 dB. Useful for proving remediation actually landed.

**AP inventory.** Label the access points you manage, with location and asset
tag. Open any network from Live and use "Add to inventory". Reports then name
them properly, and anything unlabelled stands out as unmanaged.

**Client report.** Report tab → title, your name, what to include, then Open.
You get a self-contained HTML document: executive summary, findings grouped and
explained in plain language for a non-technical reader, channel plan, coverage
results with recommendations, AP inventory, and the full network list. It prints
cleanly to PDF straight from the browser.

The report explains the Windows survey method and its limits. Windows may send
probe requests. Record separate discovery or audit activity in engagement notes.

## Wiring it into what you already run

**Splunk or Wazuh.** Settings → Notifications → Forward to syslog. Point it at
your collector, leave format on CEF. The Test button sends a synthetic finding
so you can confirm the pipeline before waiting for a real one.

**Slack or Teams.** Settings → Notifications → webhook, paste an incoming
webhook URL. The payload has a `text` field those both render directly.

**As a monitoring probe.** `wifirecon.exe --doctor` returns a non-zero exit code
when any check fails.

---

## Turning on self-updates

The updater looks for GitHub releases at the repo named in `app/updater.py`:

```python
REPO = "Seth-Smithey/wifirecon-win"
```

Change that to wherever you actually put it, then:

```powershell
git init
git add .
git commit -m "wifirecon 1.0.0"
git remote add origin https://github.com/<you>/wifirecon-win.git
git push -u origin main
```

To ship a version after that:

```powershell
.\build.ps1 -Version 1.1.0 -Release
```

That builds, smoke-tests, writes the checksum file, and publishes the GitHub
release with both attached. Every install picks it up on its next check and
offers it under Diagnostics. Needs the GitHub CLI (`gh`) installed and
authenticated; without it you get `dist\` and upload by hand.

Until you do that, update checks report "no releases published yet" and
everything else works normally.

---

## If CrowdStrike or SmartScreen objects

The binary is unsigned, so expect one or both on first run.

SmartScreen: *More info* → *Run anyway*.

CrowdStrike: add an exclusion for the executable path, or upload the hash to
your allowlist. Building with `.\build.ps1 -OneDir` produces a folder instead of
a single self-extracting file and gets flagged noticeably less often, if you would
rather avoid the exclusion.

---

## When something is wrong

`python -m tools.verify` runs 50 checks over the service layer, the spectrum
geometry, the threading and every view. It is the fastest way to tell a broken
install from a broken adapter.

`.\run.ps1 -Doctor` first for the hardware side. It checks the WLAN AutoConfig service, the Native
Wifi API, adapters, privileges, disk, database and dependencies, and every
failure comes with the specific fix.

**No networks at all.** Confirm `wlansvc` is running: `net start wlansvc`. Then
check Device Manager — a yellow triangle on the adapter means the driver never
bound.

**Access denied from WlanScan.** Run it as Administrator.

**Only updates every 20 seconds.** That is Windows, not the app. Scan requests
are rate limited to roughly four a minute per adapter, which is why the interval
setting has a floor.

**Vendors all show unknown.** Save Wireshark's `manuf` file into
`%LOCALAPPDATA%\wifirecon-win\` and restart. `install.ps1` tries to fetch it
automatically.

Logs are at `%LOCALAPPDATA%\wifirecon-win\wifirecon.log`, and the last 200 lines
show up at the bottom of the Diagnostics tab.
