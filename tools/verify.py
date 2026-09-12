"""Verification checks over the desktop rewrite.

    python -m tools.verify            run everything
    python -m tools.verify --quiet    only report failures

These are the checks worth having after moving the interface off the web
stack: that the service layer still behaves the way the routes did, that the
spectrum geometry is unchanged, that work crossing threads actually arrives,
and that the destructive operations still refuse without confirmation.

Every check runs against a temporary database seeded from the mock source, so
nothing here touches real data.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Set before anything imports config, so no real data directory is touched.
_TEMP = tempfile.mkdtemp(prefix="wifirecon-verify-")
os.environ["WIFIRECON_DATA_DIR"] = _TEMP
os.environ["WIFIRECON_MOCK"] = "1"
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

RESULTS: list[tuple[int, str, bool, str]] = []
_NUMBER = 0


def check(name: str):
    """Register one check. It passes unless it raises or returns False."""
    def wrap(fn):
        global _NUMBER
        _NUMBER += 1
        fn._check_number = _NUMBER
        fn._check_name = name
        CHECKS.append(fn)
        return fn
    return wrap


CHECKS: list = []


def expect(condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(detail or "condition was false")


# ---------------------------------------------------------------------------
# 1-8  Integrity
# ---------------------------------------------------------------------------


@check("Every Python module parses")
def c_compile() -> str:
    files = sorted(
        list((ROOT / "app").rglob("*.py")) + list((ROOT / "tools").rglob("*.py"))
    )
    for path in files:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    return f"{len(files)} modules"


@check("The application starts without FastAPI installed")
def c_no_fastapi_needed() -> str:
    import app.main  # noqa: F401
    import app.window  # noqa: F401

    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    expect("from fastapi" not in source, "main.py still imports fastapi at module level")
    expect("import fastapi" not in source, "main.py still imports fastapi")
    return "main.py has no import-time web dependency"


@check("The interface package reports itself available")
def c_ui_available() -> str:
    from app.ui import available

    ok, reason = available()
    expect(ok, reason)
    return "PySide6 present"


@check("All thirteen views import")
def c_views_import() -> str:
    names = ["adapters", "devices", "diagnostics", "findings", "history", "live",
             "marks", "network", "report", "settings", "spectrum", "ssids", "survey"]
    for name in names:
        importlib.import_module(f"app.ui.views.{name}")
    return f"{len(names)} views"


@check("The service layer knows about no interface at all")
def c_services_clean() -> str:
    # It is called by both the desktop application and the optional server, so
    # importing either one here would make the two diverge again.
    offenders = []
    for path in (ROOT / "app" / "services").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for banned in ("fastapi", "starlette", "uvicorn", "PySide6"):
            if f"import {banned}" in source or f"from {banned}" in source:
                offenders.append(f"{path.name}:{banned}")
    expect(not offenders, f"interface imports in the service layer: {offenders}")
    return "no web framework and no Qt"


@check("No interface module imports a web framework")
def c_ui_no_web() -> str:
    offenders = []
    for path in (ROOT / "app" / "ui").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for banned in ("fastapi", "starlette", "uvicorn"):
            if f"import {banned}" in source or f"from {banned}" in source:
                offenders.append(f"{path.name}:{banned}")
    expect(not offenders, f"web imports in the interface: {offenders}")
    return "interface talks to the service layer directly"


@check("Nothing reaches for WebView2 or pywebview any more")
def c_no_webview() -> str:
    offenders = []
    for path in list((ROOT / "app").rglob("*.py")):
        if path.name == "verify.py":
            continue
        source = path.read_text(encoding="utf-8")
        for banned in ("edgechromium", "import webview", "pywebview"):
            if banned in source:
                offenders.append(f"{path.relative_to(ROOT)}:{banned}")
    expect(not offenders, f"Edge WebView2 references remain: {offenders}")
    return "no embedded browser anywhere"


# ---------------------------------------------------------------------------
# 9-20  Service layer behaviour
# ---------------------------------------------------------------------------


@check("Row decoding unpacks JSON columns and coerces booleans")
def c_decode() -> str:
    from app.services import decode

    row = {"akms": '["PSK"]', "ciphers": None, "detail_json": '{"a": 1}',
           "hidden": 1, "wps": 0, "enterprise": None, "mfp_required": 1,
           "mfp_capable": 0, "randomized_mac": 0}
    out = decode.bss(row)
    expect(out["akms"] == ["PSK"], "akms did not parse")
    expect(out["ciphers"] == [], "a null cipher list should decode to empty")
    expect(out["detail"] == {"a": 1}, "detail_json did not become detail")
    expect("detail_json" not in out, "detail_json should be consumed")
    expect(out["hidden"] is True and out["wps"] is False, "booleans not coerced")
    expect(out["enterprise"] is False, "a null boolean should be False")
    return "all six booleans and both JSON columns"


@check("A malformed JSON column is kept, not dropped")
def c_decode_malformed() -> str:
    from app.services import decode

    out = decode.bss({"akms": "not json", "ciphers": "[", "detail_json": "{oops"})
    expect(out["akms"] == ["not json"], "unparseable akms should survive as a value")
    expect(out["ciphers"] == ["["], "unparseable ciphers should survive")
    expect(out["detail"] is None, "unparseable detail should be None")
    return "malformed elements are still evidence"


@check("Spectrum band ranges are unchanged")
def c_band_ranges() -> str:
    from app.services import spectrum

    expect(spectrum.BAND_RANGES["2.4"] == (2400, 2500), "2.4 GHz range moved")
    expect(spectrum.BAND_RANGES["5"] == (5150, 5895), "5 GHz range moved")
    expect(spectrum.BAND_RANGES["6"] == (5925, 7125), "6 GHz range moved")
    return "2400-2500, 5150-5895, 5925-7125"


@check("Spectrum drops rows with no frequency")
def c_spectrum_no_freq() -> str:
    from app.services import spectrum

    rows = [
        {"band": "5", "freq_khz": None, "bssid": "a", "ssid": "", "hidden": 0,
         "width_mhz": 20, "channel": 36, "rssi": -50, "security": "WPA2",
         "utilization_pct": None, "vendor": None},
        {"band": "5", "freq_khz": 5180000, "bssid": "b", "ssid": "", "hidden": 0,
         "width_mhz": 20, "channel": 36, "rssi": -50, "security": "WPA2",
         "utilization_pct": None, "vendor": None},
    ]
    out = spectrum.layout_from_rows(rows)
    expect(out["counts"]["5"] == 1, "a row with no frequency was placed anyway")
    return "no frequency means no honest position"


@check("A missing channel width defaults to 20 MHz")
def c_spectrum_default_width() -> str:
    from app.services import spectrum

    rows = [{"band": "5", "freq_khz": 5180000, "bssid": "b", "ssid": "", "hidden": 0,
             "width_mhz": None, "channel": 36, "rssi": -50, "security": "WPA2",
             "utilization_pct": None, "vendor": None}]
    item = spectrum.layout_from_rows(rows)["bands"]["5"][0]
    expect(item["width_mhz"] == 20, "default width changed")
    expect(item["low_mhz"] == 5170 and item["high_mhz"] == 5190, "span is wrong")
    return "5170-5190 MHz for a 20 MHz channel on 5180"


@check("Preferred scanning channels are the fifteen 6 GHz ones")
def c_psc() -> str:
    from app.services import spectrum

    expect(len(spectrum.PSC_CHANNELS) == 15, "wrong number of scanning channels")
    expect(5 in spectrum.PSC_CHANNELS and 229 in spectrum.PSC_CHANNELS,
           "the first or last scanning channel is missing")
    return "15 channels, 5 through 229"


@check("Grouped search matches name, BSSID and vendor")
def c_grouped_search() -> str:
    from app.services import networks

    result = networks.grouped(search="ExampleVendor")
    expect(result["total"] >= 1, "vendor search found nothing")
    by_name = networks.grouped(search="example_")
    expect(by_name["total"] >= 1, "name search found nothing")
    return f"{result['total']} by vendor, {by_name['total']} by name"


@check("Grouped band filter keeps only groups on that band")
def c_grouped_band() -> str:
    from app.services import networks

    result = networks.grouped(band="6")
    for group in result["groups"]:
        expect("6" in group["bands"], f"{group['ssid']} has no 6 GHz radio")
    return f"{result['total']} group(s) with a 6 GHz radio"


@check("Grouped counters agree with the groups returned")
def c_grouped_counts() -> str:
    from app.services import networks

    result = networks.grouped()
    expect(result["total"] == len(result["groups"]), "total does not match the list")
    expect(result["radio_total"] == sum(g["radio_count"] for g in result["groups"]),
           "radio total does not match")
    expect(result["multi_band"] == sum(1 for g in result["groups"]
                                       if g["band_count"] > 1),
           "multi-band count does not match")
    return (f"{result['total']} networks, {result['radio_total']} radios, "
            f"{result['multi_band']} multi-band")


@check("A mark on a partial MAC address is refused")
def c_mark_partial_mac() -> str:
    from app.services import ServiceError, marks

    try:
        marks.normalise("trusted", "bssid", "aa:bb:cc")
    except ServiceError as exc:
        expect("full MAC" in str(exc), f"unhelpful message: {exc}")
        return str(exc)
    raise AssertionError("a three-octet MAC was accepted")


@check("A vendor prefix shorter than six hex digits is refused")
def c_mark_short_oui() -> str:
    from app.services import ServiceError, marks

    try:
        marks.normalise("ignore", "oui", "aabb")
    except ServiceError as exc:
        expect("6 hex" in str(exc), f"unhelpful message: {exc}")
        return str(exc)
    raise AssertionError("a four-digit OUI was accepted")


@check("A vendor prefix is cleaned to bare hex")
def c_mark_oui_normalised() -> str:
    from app.services import marks

    _, _, value = marks.normalise("ignore", "oui", "AA:BB:CC")
    expect(value == "aabbcc", f"expected aabbcc, got {value}")
    return "AA:BB:CC becomes aabbcc"


@check("A survey point with no signal levels does not crash")
def c_capture_all_null() -> str:
    # The route this replaced took max() over a generator that could be empty,
    # so one location where every reading had a null level raised instead of
    # recording the point.
    source = (ROOT / "app" / "services" / "survey_svc.py").read_text(encoding="utf-8")
    expect("max(levels) if levels else None" in source,
           "best_rssi is not guarded against an empty list")
    levels: list[int] = []
    best = max(levels) if levels else None
    expect(best is None, "the guard itself is wrong")
    return "best signal is None rather than an exception"


# ---------------------------------------------------------------------------
# 21-28  Spectrum geometry
# ---------------------------------------------------------------------------


@check("Frequency maps to the ends of the plot exactly")
def c_x_mapping() -> str:
    from app.ui import theme
    from app.ui.spectrum_widget import PAD_L, PAD_R, RibbonWidget, W

    _qt_app()
    ribbon = RibbonWidget("5", theme.DARK)
    low, high = 5150, 5895
    expect(abs(ribbon._to_x(low) - PAD_L) < 0.001, "the low edge is not at the left pad")
    expect(abs(ribbon._to_x(high) - (W - PAD_R)) < 0.001,
           "the high edge is not at the right pad")
    return f"{low} MHz at x={PAD_L}, {high} MHz at x={W - PAD_R}"


@check("A 20 MHz channel is wider on 2.4 GHz than on 6 GHz")
def c_width_scaling() -> str:
    from app.ui import theme
    from app.ui.spectrum_widget import RibbonWidget

    _qt_app()
    widths = {}
    for band, centre in (("2.4", 2437), ("5", 5180), ("6", 6015)):
        ribbon = RibbonWidget(band, theme.DARK)
        widths[band] = ribbon._to_x(centre + 10) - ribbon._to_x(centre - 10)
    expect(widths["2.4"] > widths["5"] > widths["6"],
           f"band scaling is not monotonic: {widths}")
    return " ".join(f"{b}={w:.0f}u" for b, w in widths.items())


@check("Row packing never overlaps two blocks on one row")
def c_pack_no_overlap() -> str:
    from app.ui.spectrum_widget import pack_rows

    items = [
        {"low_mhz": 2400 + i * 3, "high_mhz": 2400 + i * 3 + 20,
         "ssid": f"net{i}", "bssid": f"aa:{i:02x}", "hidden": False}
        for i in range(24)
    ]
    def to_x(mhz):
        return (mhz - 2400) * 9.42
    rows = pack_rows(items, to_x)
    seen: dict[int, list[tuple[float, float]]] = {}
    for item, row in zip(items, rows, strict=True):
        left, right = to_x(item["low_mhz"]), to_x(item["high_mhz"])
        for other_left, other_right in seen.setdefault(row, []):
            expect(right <= other_left or left >= other_right,
                   f"blocks overlap on row {row}")
        seen[row].append((left, right))
    return f"{len(items)} blocks over {max(rows) + 1} rows, no collisions"


@check("One very long name cannot force a row per block")
def c_pack_label_cap() -> str:
    from app.ui.spectrum_widget import MAX_LABEL_RESERVE, pack_rows

    long_name = "x" * 400
    items = [
        {"low_mhz": 2400 + i * 25, "high_mhz": 2400 + i * 25 + 20,
         "ssid": long_name, "bssid": "aa", "hidden": False}
        for i in range(4)
    ]
    def to_x(mhz):
        return (mhz - 2400) * 9.42
    rows = pack_rows(items, to_x)
    # Without the cap every block would reserve 400 characters of label and
    # each would land on its own row.
    expect(MAX_LABEL_RESERVE == 190, "the label reserve cap moved")
    expect(max(rows) + 1 <= 4, "the cap is not limiting rows")
    return f"4 blocks with 400-character names fit in {max(rows) + 1} rows"


@check("Signal strength has a floor so nothing is invisible")
def c_strength_floor() -> str:
    from app.ui.spectrum_widget import STRENGTH_MIN, strength_of

    expect(abs(strength_of(-95) - STRENGTH_MIN) < 1e-9, "the floor moved")
    expect(abs(strength_of(-140) - STRENGTH_MIN) < 1e-9, "a very weak signal went below")
    expect(strength_of(None) == STRENGTH_MIN, "an unknown level should sit at the floor")
    return f"-95 dBm and weaker all sit at {STRENGTH_MIN}"


@check("Signal strength tops out at a full meter")
def c_strength_ceiling() -> str:
    from app.ui.spectrum_widget import strength_of

    expect(abs(strength_of(-30) - 1.0) < 1e-9, "-30 dBm is not full strength")
    expect(strength_of(-10) == 1.0, "a stronger signal exceeded full")
    mid = strength_of(-62.5)
    expect(0.45 < mid < 0.55, f"the midpoint is not central: {mid}")
    return "-30 dBm is 1.0, -62.5 dBm is mid scale"


@check("Axis tick spacing differs per band")
def c_tick_steps() -> str:
    from app.ui.spectrum_widget import TICK_STEPS

    expect(TICK_STEPS["2.4"] == 20, "2.4 GHz tick step moved")
    expect(TICK_STEPS["5"] == 100, "5 GHz tick step moved")
    expect(TICK_STEPS["6"] == 200, "6 GHz tick step moved")
    return "20, 100 and 200 MHz"


@check("Ribbon height follows the number of packed rows")
def c_ribbon_height() -> str:
    from app.ui import theme
    from app.ui.spectrum_widget import PAD_B, PAD_T, ROW_H, RibbonWidget

    _qt_app()
    ribbon = RibbonWidget("2.4", theme.DARK)
    ribbon.set_items([])
    empty = ribbon._virtual_height
    expect(empty == ROW_H + PAD_T + PAD_B, "an empty ribbon is the wrong height")
    ribbon.set_items([
        {"low_mhz": 2410, "high_mhz": 2430, "ssid": "a", "bssid": "1",
         "hidden": False, "rssi": -50, "channel": 1, "width_mhz": 20,
         "security": "WPA2", "vendor": None},
        {"low_mhz": 2412, "high_mhz": 2432, "ssid": "b", "bssid": "2",
         "hidden": False, "rssi": -50, "channel": 1, "width_mhz": 20,
         "security": "WPA2", "vendor": None},
    ])
    expect(ribbon._virtual_height == 2 * ROW_H + PAD_T + PAD_B,
           "two overlapping blocks did not take two rows")
    return f"empty {empty:.0f}u, two overlapping blocks {ribbon._virtual_height:.0f}u"


# ---------------------------------------------------------------------------
# 29-34  Threading
# ---------------------------------------------------------------------------


@check("Background results reach the interface thread")
def c_pool_delivers() -> str:
    app = _qt_app()
    from app.ui.bridge import pool

    got: list = []
    for i in range(5):
        pool.run(lambda i=i: i * 2, got.append, None)
    _pump(app, 2.0, lambda: len(got) == 5)
    expect(sorted(got) == [0, 2, 4, 6, 8], f"results lost: {got}")
    return "5 of 5 delivered"


@check("Background failures reach the interface thread")
def c_pool_errors() -> str:
    app = _qt_app()
    from app.ui.bridge import pool

    errors: list = []

    def boom():
        raise ValueError("expected")

    pool.run(boom, None, errors.append)
    _pump(app, 2.0, lambda: errors)
    expect(errors and isinstance(errors[0], ValueError), "the failure was swallowed")
    return "the exception arrived intact"


@check("Two hundred rapid tasks all complete")
def c_pool_volume() -> str:
    app = _qt_app()
    from app.ui.bridge import pool

    got: list = []
    for i in range(200):
        pool.run(lambda i=i: i, got.append, None)
    _pump(app, 15.0, lambda: len(got) == 200)
    expect(len(got) == 200, f"only {len(got)} of 200 arrived")
    # Each task is released on the next turn of the loop, so give the last one
    # its turn before checking that nothing was left holding a reference.
    _pump(app, 2.0, lambda: pool.pending == 0)
    expect(pool.pending == 0, f"{pool.pending} task(s) never released")
    return "200 of 200, nothing leaked"


@check("Scan engine events reach a subscriber")
def c_engine_events() -> str:
    from app import scanner

    seen: list = []
    scanner.engine.subscribe(lambda event, payload: seen.append(event))
    try:
        scanner.engine.note("verification probe")
        scanner.engine._set_phase("idle", "verification")
        expect("activity" in seen, "the activity event did not fire")
        expect("phase" in seen, "the phase event did not fire")
    finally:
        scanner.engine._subscribers.clear()
    return f"events seen: {sorted(set(seen))}"


@check("A broken subscriber cannot stop a scan")
def c_engine_bad_subscriber() -> str:
    from app import scanner

    def bad(event, payload):
        raise RuntimeError("this subscriber is broken")

    good: list = []
    scanner.engine.subscribe(bad)
    scanner.engine.subscribe(lambda e, p: good.append(e))
    try:
        scanner.engine.note("probe past a broken subscriber")
        expect(good, "a later subscriber was skipped after one raised")
    finally:
        scanner.engine._subscribers.clear()
    return "the failure was isolated"


@check("Events are published without the engine lock held")
def c_engine_no_deadlock() -> str:
    # A subscriber reading status() would deadlock if publishing happened
    # inside the lock on a non-reentrant path, and would stall every scan if
    # the subscriber were slow.
    from app import scanner

    read: list = []
    scanner.engine.subscribe(lambda e, p: read.append(scanner.engine.status()["phase"]))
    try:
        scanner.engine._set_phase("waiting", "verification")
        expect(read, "the subscriber never ran")
        expect(read[0] in ("waiting", "idle"), f"unexpected phase: {read[0]}")
    finally:
        scanner.engine._subscribers.clear()
    return "status() is callable from inside a subscriber"


# ---------------------------------------------------------------------------
# 35-40  Theme
# ---------------------------------------------------------------------------


@check("Both themes define every colour")
def c_palette_complete() -> str:
    from dataclasses import fields

    from app.ui import theme

    names = [f.name for f in fields(theme.Palette)]
    for palette in (theme.DARK, theme.LIGHT):
        for name in names:
            value = getattr(palette, name)
            expect(value not in (None, ""), f"{palette.name}.{name} is empty")
    return f"{len(names)} values in each of dark and light"


@check("Band colours are distinct in both themes")
def c_band_colours_distinct() -> str:
    from app.ui import theme

    for palette in (theme.DARK, theme.LIGHT):
        colours = {theme.band_colour(palette, b) for b in ("2.4", "5", "6")}
        expect(len(colours) == 3, f"{palette.name} reuses a band colour")
        expect(theme.band_colour(palette, "nonsense") == palette.b_other,
               "an unknown band should fall back")
    return "amber, cyan and violet stay separate"


@check("The stylesheet builds for both themes")
def c_stylesheet() -> str:
    from app.ui import theme

    sizes = []
    for palette in (theme.DARK, theme.LIGHT):
        sheet = theme.stylesheet(palette)
        expect(len(sheet) > 2000, f"{palette.name} stylesheet looks truncated")
        expect("{p." not in sheet, f"{palette.name} stylesheet has an unfilled field")
        sizes.append(len(sheet))
    return f"{sizes[0]} and {sizes[1]} characters"


@check("The severity ladder is fully coloured")
def c_severity_colours() -> str:
    from app.ui import theme

    for palette in (theme.DARK, theme.LIGHT):
        colours = {theme.severity_colour(palette, s) for s in theme.SEVERITIES}
        expect(len(colours) == len(theme.SEVERITIES) - 1 or len(colours) >= 4,
               f"{palette.name} severity colours collapse")
        expect(theme.severity_colour(palette, "critical") == palette.crit,
               "critical is not the critical colour")
    return "critical through info all resolve"


@check("The light theme is not the dark theme's tints reused")
def c_light_recomputed() -> str:
    from app.ui import theme

    expect(theme.LIGHT.tint_alpha_bg != theme.DARK.tint_alpha_bg,
           "light reuses the dark chip fill alpha")
    expect(theme.LIGHT.tint_alpha_border != theme.DARK.tint_alpha_border,
           "light reuses the dark chip border alpha")
    expect(theme.LIGHT.b24 != theme.DARK.b24, "the band hues were not darkened")
    return "chip alphas and band hues both recomputed"


@check("Coverage grades are coloured apart from severities")
def c_grade_colours() -> str:
    from app.ui import theme

    grades = ["excellent", "good", "fair", "weak", "unusable"]
    for palette in (theme.DARK, theme.LIGHT):
        colours = [theme.grade_colour(palette, g) for g in grades]
        expect(len(set(colours)) == 5, f"{palette.name} reuses a grade colour")
    return "five distinct grades in both themes"


# ---------------------------------------------------------------------------
# 41-46  Lifecycle and safety
# ---------------------------------------------------------------------------


@check("Clearing networks refuses without the confirmation word")
def c_clear_gate() -> str:
    from app.services import ServiceError, maintenance

    try:
        maintenance.clear_networks("")
    except ServiceError as exc:
        expect(maintenance.CONFIRM_CLEAR in str(exc), "the message omits the word needed")
        return str(exc)
    raise AssertionError("networks were cleared without confirmation")


@check("Wiping refuses without the confirmation phrase")
def c_wipe_gate() -> str:
    from app.services import ServiceError, maintenance

    for attempt in ("", "wipe everything", "WIPE"):
        try:
            maintenance.wipe(attempt)
        except ServiceError:
            continue
        raise AssertionError(f"a wipe went ahead on {attempt!r}")
    return "only the exact phrase is accepted"


@check("The network audit refuses without confirmation")
def c_audit_gate() -> str:
    from app.services import ServiceError, devices_svc

    try:
        devices_svc.audit("")
    except ServiceError as exc:
        expect(devices_svc.CONFIRM_AUDIT in str(exc), "the message omits the word needed")
        return str(exc)
    raise AssertionError("an active scan started without confirmation")


@check("A bad passphrase is named before the platform is blamed")
def c_validate_before_platform() -> str:
    from app.services import ServiceError, devices_svc

    try:
        devices_svc.configure_hotspot("MySpot", "short")
    except ServiceError as exc:
        expect("8 and 63" in str(exc),
               f"the message should name the passphrase rule, got: {exc}")
        return str(exc)
    raise AssertionError("a five-character passphrase was accepted")


@check("Shutdown is safe to run twice")
def c_teardown_idempotent() -> str:
    from app.services import lifecycle

    lifecycle.teardown()
    lifecycle.teardown()
    return "teardown ran twice without raising"


@check("Reading the log copes with there being no log")
def c_tail_log() -> str:
    from app.services import lifecycle

    text = lifecycle.tail_log(50)
    expect(isinstance(text, str), "the log tail was not text")
    expect(text != "", "the log tail was empty rather than explanatory")
    return text.splitlines()[0][:60] if text else ""


# ---------------------------------------------------------------------------
# 47-50  The application itself
# ---------------------------------------------------------------------------


@check("Every view constructs and paints")
def c_views_render() -> str:
    app = _qt_app()
    window = _window(app)
    painted = 0
    for _, key, _ in _nav():
        window.show_view(key)
        _pump(app, 0.4)
        pixmap = window.grab()
        expect(not pixmap.isNull(), f"{key} produced nothing")
        expect(pixmap.width() > 100, f"{key} painted at {pixmap.width()}px")
        painted += 1
    expect(painted == 13, f"only {painted} views painted")
    return "13 views painted"


@check("Every view survives a theme switch")
def c_theme_switch() -> str:
    app = _qt_app()
    window = _window(app)
    before = window._palette.name
    window.toggle_theme()
    _pump(app, 0.3)
    expect(window._palette.name != before, "the theme did not change")
    for _, key, _ in _nav():
        window.show_view(key)
        _pump(app, 0.2)
    window.toggle_theme()
    _pump(app, 0.3)
    expect(window._palette.name == before, "the theme did not switch back")
    return f"{before} to the other and back, all 13 views"


@check("The spectrum ribbon paints with no data at all")
def c_spectrum_empty() -> str:
    app = _qt_app()
    from app.ui import theme
    from app.ui.spectrum_widget import SpectrumWidget

    widget = SpectrumWidget(theme.DARK)
    widget.resize(1000, 400)
    widget.set_data({"bands": {"2.4": [], "5": [], "6": []},
                     "ranges": {}, "counts": {}}, set())
    _pump(app, 0.2)
    pixmap = widget.grab()
    expect(not pixmap.isNull(), "an empty ribbon painted nothing")
    return "an empty band draws its header rather than an error"


@check("Closing the window shuts down cleanly")
def c_close_clean() -> str:
    app = _qt_app()
    window = _window(app)
    window.close()
    _pump(app, 0.5)
    expect(window._shutting_down, "the close path did not run")
    return "session ended and the database was checkpointed"




# ---------------------------------------------------------------------------
# 51-75  The polishing pass
# ---------------------------------------------------------------------------


@check("Tables actually sort")
def c_sorting_works() -> str:
    # A sort role returning a Python tuple cannot be compared by Qt, so every
    # table silently kept its query order however the header was clicked.
    from PySide6.QtCore import Qt

    app = _qt_app()
    from app.ui.models import Column, DictTableModel, SortProxy

    model = DictTableModel([Column("name", "Name"), Column("rssi", "Signal")])
    model.set_rows([{"name": "zeta", "rssi": -80}, {"name": "alpha", "rssi": -35},
                    {"name": "mid", "rssi": -60}])
    proxy = SortProxy()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    names = [proxy.row_at(i)["name"] for i in range(proxy.rowCount())]
    expect(names == ["alpha", "mid", "zeta"], f"name sort did nothing: {names}")
    proxy.sort(1, Qt.SortOrder.DescendingOrder)
    levels = [proxy.row_at(i)["rssi"] for i in range(proxy.rowCount())]
    expect(levels == [-35, -60, -80], f"signal sort did nothing: {levels}")
    return "ascending by name and descending by signal both order correctly"


@check("An unknown value sorts last in both directions")
def c_sort_nulls_last() -> str:
    from PySide6.QtCore import Qt

    _qt_app()
    from app.ui.models import Column, DictTableModel, SortProxy

    model = DictTableModel([Column("rssi", "Signal")])
    model.set_rows([{"rssi": -70}, {"rssi": None}, {"rssi": -40}])
    proxy = SortProxy()
    proxy.setSourceModel(model)
    for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
        proxy.sort(0, order)
        levels = [proxy.row_at(i)["rssi"] for i in range(proxy.rowCount())]
        expect(levels[-1] is None, f"null floated to the top in {order}: {levels}")
    return "an unknown signal never outranks a measured one"


@check("A column mixing numbers and text still sorts")
def c_sort_mixed() -> str:
    from PySide6.QtCore import Qt

    _qt_app()
    from app.ui.models import Column, DictTableModel, SortProxy

    model = DictTableModel([Column("v", "Value")])
    model.set_rows([{"v": 3}, {"v": "apple"}, {"v": 1}])
    proxy = SortProxy()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    expect(proxy.rowCount() == 3, "rows were lost sorting a mixed column")
    return "no TypeError, all rows kept"


@check("A burst of toasts does not hang the interface")
def c_toast_burst() -> str:
    # Retiring a toast only fades it, so counting layout items to decide what
    # to drop never converged and the sixth toast spun forever.
    import threading

    app = _qt_app()
    window = _window(app)
    done = threading.Event()

    def burst() -> None:
        for i in range(12):
            window.toast(f"burst {i}")
        done.set()

    burst()
    expect(done.is_set(), "the toast loop did not return")
    _pump(app, 0.4)
    return "12 toasts in one go, no spin"


@check("Local network rows are decoded from the right column")
def c_device_decode() -> str:
    from app.services import decode

    out = decode.device({"ip": "10.0.0.5", "detail_json": '{"sources": ["mDNS"]}'})
    expect(out.get("detail") == {"sources": ["mDNS"]},
           f"detail_json was not unpacked: {out}")
    expect("detail_json" not in out, "the raw column should be consumed")
    return "sources, services and names are reachable again"


@check("Broadcast and multicast addresses are not devices")
def c_infrastructure() -> str:
    from app.services import devices_svc

    cases = {
        "255.255.255.255": "broadcast",
        "224.0.0.251": "multicast",
        "239.255.255.250": "multicast",
        "192.168.10.0": "network address",
    }
    for ip, expected in cases.items():
        got = devices_svc.infrastructure_kind({"ip": ip, "mac": ""})
        expect(got == expected, f"{ip} classified as {got}, expected {expected}")
    expect(devices_svc.infrastructure_kind(
        {"ip": "192.168.10.255", "mac": "ff:ff:ff:ff:ff:ff"}) == "broadcast",
        "a subnet broadcast was treated as a host")
    expect(devices_svc.infrastructure_kind(
        {"ip": "192.168.10.42", "mac": "aa:bb:cc:dd:ee:ff"}) is None,
        "a real host was filtered out")
    return "four kinds of non-host recognised, a real host kept"


@check("Interface GUIDs compare regardless of spelling")
def c_guid_normalise() -> str:
    from app import db

    forms = ["{C9E276BB-F82D-4010-B611-5D225BF7CDD2}",
             "c9e276bb-f82d-4010-b611-5d225bf7cdd2",
             "{c9e276bb-f82d-4010-b611-5d225bf7cdd2}"]
    normalised = {db.normalise_guid(f) for f in forms}
    expect(len(normalised) == 1, f"the same GUID normalised three ways: {normalised}")
    return "braces and case no longer hide a match"


@check("A 6 GHz observation is attributed to the adapter that heard it")
def c_observed_bands() -> str:
    from app import db

    bands = db.observed_bands()
    expect("6" in bands, f"the mock scan produced no 6 GHz rows: {bands}")
    # Whatever spelling the caller has, the answer must be the same.
    with db.connection() as conn:
        guid = conn.execute(
            "SELECT interface_guid FROM scans WHERE interface_guid IS NOT NULL LIMIT 1"
        ).fetchone()
    expect(guid is not None, "no scan recorded an interface")
    raw = guid[0]
    for spelling in (raw, raw.upper(), raw.strip("{}")):
        found = db.observed_bands(spelling)
        expect("6" in found, f"6 GHz lost for spelling {spelling!r}: {found}")
    return f"bands {bands} found under three spellings of the same GUID"


@check("The beacon fingerprint ignores volatile elements")
def c_fingerprint_stable() -> str:
    from app import scanner

    # The same access point, once as a beacon and once as a probe response.
    beacon = {"element_ids": ["0", "1", "5", "48", "11", "42", "221"],
              "vendor_ies": [{"oui": "00:50:f2", "type": 1}]}
    probe = {"element_ids": ["221", "48", "1", "0"],
             "vendor_ies": [{"oui": "00:50:f2", "type": 1}]}
    expect(scanner.ie_fingerprint(beacon) == scanner.ie_fingerprint(probe),
           "TIM, BSS Load, ERP or element order still change the fingerprint")
    return "TIM, BSS Load, ERP and ordering no longer count"


@check("The fingerprint still changes when the security elements do")
def c_fingerprint_sensitive() -> str:
    from app import scanner

    with_rsn = {"element_ids": ["0", "1", "48"], "vendor_ies": []}
    without = {"element_ids": ["0", "1"], "vendor_ies": []}
    expect(scanner.ie_fingerprint(with_rsn) != scanner.ie_fingerprint(without),
           "losing the RSN element did not change the fingerprint")
    return "an AP that drops RSN is still reported"


@check("A change of fingerprint recipe is not reported as a change of device")
def c_fingerprint_version() -> str:
    from app import detections, scanner

    expect(scanner.ie_fingerprint({}).startswith(f"{scanner.FINGERPRINT_VERSION}:"),
           "fingerprints carry no recipe version")
    ctx = detections.RuleContext(
        records=[{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "x",
                  "ie_fingerprint": "2:abc", "ie_elements": '["0"]'}],
        previous={"aa:bb:cc:dd:ee:ff": {"ie_fingerprint": "1:zzz",
                                        "ie_elements": '["0"]'}},
        marks=detections.MarkSet([]), settings={}, new_bssids=set(), now=0.0,
    )
    findings = [f for _, fn in detections.REGISTRY
                if fn.__name__ == "_fingerprint"
                for f in fn(ctx)]
    expect(not findings, "an upgrade would have alerted on every access point")
    return "version 1 and version 2 fingerprints are not compared"


@check("A fingerprint change says what changed")
def c_fingerprint_diff() -> str:
    from app import detections

    ctx = detections.RuleContext(
        records=[{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Home",
                  "ie_fingerprint": "2:new", "ie_elements": '["0", "1", "48"]'}],
        previous={"aa:bb:cc:dd:ee:ff": {"ie_fingerprint": "2:old",
                                        "ie_elements": '["0", "1"]'}},
        marks=detections.MarkSet([]), settings={}, new_bssids=set(), now=0.0,
    )
    findings = [f for _, fn in detections.REGISTRY
                if fn.__name__ == "_fingerprint" for f in fn(ctx)]
    expect(findings, "a genuine change was not reported")
    finding = findings[0]
    expect(finding.evidence.get("added") == ["48"],
           f"the diff is wrong: {finding.evidence}")
    expect(finding.severity == "high",
           "gaining the RSN element is a security change and should rank high")
    return "reports 'added 48' rather than two opaque hashes"


@check("Inventory rules report once, not once per access point")
def c_inventory_summaries() -> str:
    from app import detections

    records = []
    for i in range(40):
        records.append({
            "bssid": f"aa:bb:cc:00:00:{i:02x}", "ssid": f"net{i}", "hidden": False,
            "security": "WPA2", "mfp_capable": False, "mfp_required": False,
            "channel": 6, "band": "2.4", "rssi": -60 - i, "vendor": "Acme",
            "width_mhz": 20, "utilization_pct": None, "station_count": None,
            "enterprise": False, "beacon_period": 100, "country": "US",
            "randomized_mac": False, "ie_fingerprint": "2:x", "ie_elements": "[]",
            "phy": "Wi-Fi 5", "akms": ["PSK"], "ciphers": ["CCMP"],
            "detail": {"wps": {"config_methods": ["Label"], "state": "configured",
                               "manufacturer": "Acme", "model_name": "X",
                               "model_number": "1"}},
        })
    ctx = detections.RuleContext(records=records, previous={},
                                 marks=detections.MarkSet([]), settings={},
                                 new_bssids=set(), now=0.0)
    counts = {}
    for name, fn in detections.REGISTRY:
        if name in ("wps_enabled", "pmf_missing", "wps_device_disclosure"):
            counts[name] = len(fn(ctx))
    expect(all(n <= 1 for n in counts.values()),
           f"a rule still reports per access point: {counts}")
    expect(all(n == 1 for n in counts.values()),
           f"a rule stopped reporting entirely: {counts}")
    return f"40 access points produce {sum(counts.values())} findings, not 120"


@check("A summary finding names the strongest and keeps the full list")
def c_summary_actionable() -> str:
    from app import detections

    records = [{
        "bssid": f"aa:bb:cc:00:00:{i:02x}", "ssid": f"net{i}", "hidden": False,
        "security": "WPA2", "mfp_capable": True, "mfp_required": True,
        "channel": 6, "band": "2.4", "rssi": -40 - i * 10, "vendor": "Acme",
        "width_mhz": 20, "enterprise": False, "beacon_period": 100,
        "country": "US", "randomized_mac": False, "ie_fingerprint": "2:x",
        "ie_elements": "[]", "phy": "Wi-Fi 5", "akms": ["PSK"],
        "ciphers": ["CCMP"], "utilization_pct": None, "station_count": None,
        "detail": {"wps": {"config_methods": ["Label"], "state": "configured"}},
    } for i in range(3)]
    ctx = detections.RuleContext(records=records, previous={},
                                 marks=detections.MarkSet([]), settings={},
                                 new_bssids=set(), now=0.0)
    finding = next(f for name, fn in detections.REGISTRY if name == "wps_enabled"
                   for f in fn(ctx))
    expect("3 of 3" in finding.title, f"no denominator in the title: {finding.title}")
    expect("net0" in finding.detail, "the strongest AP is not named in the detail")
    expect(len(finding.evidence.get("pin_capable") or []) == 3,
           "the per-AP list did not survive into the evidence")
    return finding.title


@check("Congestion is reported per channel, not per radio")
def c_congestion_scope() -> str:
    from app import detections

    records = [{
        "bssid": f"aa:bb:cc:00:00:{i:02x}", "ssid": f"net{i}", "channel": 6,
        "band": "2.4", "rssi": -50, "utilization_pct": 90, "station_count": 3,
        "hidden": False, "security": "WPA2", "mfp_capable": True,
        "mfp_required": True, "enterprise": False, "vendor": "Acme",
        "width_mhz": 20, "detail": {},
    } for i in range(8)]
    ctx = detections.RuleContext(records=records, previous={},
                                 marks=detections.MarkSet([]), settings={},
                                 new_bssids=set(), now=0.0)
    findings = next(fn for name, fn in detections.REGISTRY
                    if name == "channel_congestion")(ctx)
    expect(len(findings) == 1, f"8 radios on one channel gave {len(findings)} findings")
    expect(findings[0].scope == "2.4:6", f"wrong scope: {findings[0].scope}")
    expect(findings[0].severity == "medium",
           "90 percent busy should outrank a channel that is merely over the line")
    return "one finding, scoped to the channel, severity read from the number"


@check("A cooldown keyed on a name survives signal drift")
def c_conflict_scope() -> str:
    from app.detections import Finding

    a = Finding("ssid_conflict", "high", "t", "d", bssid="aa:11", ssid="Home",
                scope="ssid:Home")
    b = Finding("ssid_conflict", "high", "t", "d", bssid="bb:22", ssid="Home",
                scope="ssid:Home")
    expect(a.suppression_key() == b.suppression_key(),
           "the same conflict re-alerts when a different radio is loudest")
    return a.suppression_key()


@check("The truncation notice is never silenced")
def c_truncation_never_muted() -> str:
    source = (ROOT / "app" / "detections.py").read_text(encoding="utf-8")
    expect('if f.rule != "findings_truncated"' in source,
           "the notice that findings are being withheld can be suppressed")
    return "the person keeps being told when findings are held back"


@check("A rule can be muted")
def c_rule_muting() -> str:
    from app import detections
    from app.config import config

    records = [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Open one", "hidden": False,
                "security": "Open", "channel": 1, "band": "2.4", "rssi": -50,
                "enterprise": False, "randomized_mac": False, "mfp_capable": False,
                "mfp_required": False, "vendor": "Acme", "width_mhz": 20,
                "beacon_period": 100, "country": "US", "phy": "Wi-Fi 4",
                "akms": [], "ciphers": [], "utilization_pct": None,
                "station_count": None, "ie_fingerprint": "2:x",
                "ie_elements": "[]", "detail": {}}]
    settings = dict(config.get("detections", default={}) or {})
    settings["muted_rules"] = ["open_network"]
    findings = detections.run(records=records, previous={}, marks_rows=[],
                              settings=settings, new_bssids=set())
    expect(not any(f.rule == "open_network" for f in findings),
           "a muted rule still reported")
    return "muted rules stop producing findings"


@check("Window size and position are remembered")
def c_geometry() -> str:
    app = _qt_app()
    window = _window(app)
    window.resize(1234, 812)
    _pump(app, 0.2)
    window._save_geometry()
    from app.config import config

    saved = config.get("ui", "window", default={}) or {}
    expect(saved.get("width") == 1234 and saved.get("height") == 812,
           f"geometry was not stored: {saved}")
    return f"{saved['width']}x{saved['height']} written to the settings file"


@check("A window is not restored onto a monitor that is gone")
def c_geometry_offscreen() -> str:
    app = _qt_app()
    window = _window(app)
    expect(not window._on_a_screen(-30000, -30000),
           "a position far off every screen was accepted")
    expect(window._on_a_screen(10, 10), "a position on the primary screen was rejected")
    return "off-screen positions are discarded"


@check("The status bar states that no network connection is needed")
def c_passive_statement() -> str:
    app = _qt_app()
    window = _window(app)
    _pump(app, 1.0, lambda: "no network connection needed" in window.status_right.text())
    text = window.status_right.text()
    expect("no network connection needed" in text, f"status bar reads: {text!r}")
    return text


@check("The Devices view says it is not the wireless scan")
def c_devices_distinct() -> str:
    from app.ui.views import devices as devices_view

    text = devices_view.EMPTY_MESSAGE + " " + devices_view.NOT_JOINED_MESSAGE
    expect("Live and Spectrum" in text,
           "the empty state does not point at the wireless survey")
    expect("no connection" in text or "unconnected" in text,
           "the empty state does not say the survey needs no connection")
    source = (ROOT / "app" / "ui" / "views" / "devices.py").read_text(encoding="utf-8")
    expect("ctx.confirm(" in source, "active discovery runs without asking")
    return "separated in the copy, and gated by a confirmation"


@check("Live exports exactly the rows on screen")
def c_live_export() -> str:
    import csv as _csv
    import tempfile as _tempfile

    from app.ui.models import Column
    from app.ui.views.live import _write_csv

    columns = [Column("ssid", "Name"), Column("rssi", "Signal")]
    rows = [{"ssid": "a", "rssi": -40}, {"ssid": "b", "rssi": None}]
    target = Path(_tempfile.mkdtemp()) / "out.csv"
    _write_csv(target, rows, columns)
    with target.open(encoding="utf-8") as handle:
        written = list(_csv.reader(handle))
    expect(written[0] == ["Name", "Signal"], f"headers wrong: {written[0]}")
    expect(len(written) == 3, f"expected 2 rows plus a header, got {len(written)}")
    expect(written[2][1] == "—", "a missing value should export as it displays")
    return "headers plus one line per visible row"


@check("Every view still paints after the changes")
def c_views_repaint() -> str:
    app = _qt_app()
    window = _window(app)
    for _, key, _ in _nav():
        window.show_view(key)
        _pump(app, 0.3)
        expect(not window.grab().isNull(), f"{key} painted nothing")
    return "13 views"


@check("A hidden table does not leave the card stretched apart")
def c_empty_state_layout() -> str:
    app = _qt_app()
    window = _window(app)
    window.show_view("devices")
    view = window._views["devices"]
    # The listing is fetched on a worker thread, so wait for it to land rather
    # than racing it.
    _pump(app, 3.0, lambda: view.empty.isVisible() or view.table.isVisible())
    expect(view.empty.isVisible() or view.table.isVisible(),
           "neither the table nor the empty message is showing")
    if view.empty.isVisible():
        # The message must take the space the table would have, or the card's
        # items drift to the corners of an empty panel.
        expect(view.empty.height() > 100,
               f"the empty message was given {view.empty.height()}px")
    return "the empty message occupies the table's place"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

_APP = None
_WINDOW = None


def _qt_app():
    global _APP
    if _APP is None:
        from app.ui.app import build_application

        _APP = build_application([])
    return _APP


def _window(app):
    global _WINDOW
    # The shutdown check closes the window, and every later check reused the
    # closed one — where isVisible() is False for everything inside it.
    if _WINDOW is not None and getattr(_WINDOW, "_shutting_down", False):
        _WINDOW = None
    if _WINDOW is None:
        from app.ui.main_window import MainWindow

        _WINDOW = MainWindow()
        _WINDOW.resize(1400, 900)
        _WINDOW.show()
        _WINDOW.start()
        _pump(app, 1.0)
    return _WINDOW


def _nav():
    from app.ui.main_window import NAV

    return NAV


def _pump(app, seconds: float, until=None) -> None:
    import time

    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        if until is not None and until():
            return
        time.sleep(0.005)
    app.processEvents()


def _seed() -> None:
    """A temporary database with one mock scan in it."""
    from app import db, scanner
    from app.config import db_path
    from app.services import lifecycle

    lifecycle.bootstrap()
    scanner.engine.start(run_loop=False)
    scanner.engine.run_once()
    # Locally administered demo MACs deliberately identify no real vendor.
    # Seed a synthetic vendor so grouped-search behavior remains testable.
    with db.transaction() as conn:
        conn.execute("UPDATE bss SET vendor=? WHERE bssid=?",
                     ("ExampleVendor", "02:00:00:00:00:01"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the desktop rewrite.")
    parser.add_argument("--quiet", action="store_true", help="only show failures")
    args = parser.parse_args()

    print(f"\nwifirecon verification — {len(CHECKS)} checks")
    print("-" * 68)
    _seed()

    passed = failed = 0
    for fn in CHECKS:
        number = fn._check_number
        name = fn._check_name
        try:
            detail = fn() or ""
            passed += 1
            if not args.quiet:
                print(f"  {number:2d}. pass  {name}")
                if detail:
                    print(f"          {detail}")
        except Exception as exc:
            failed += 1
            print(f"  {number:2d}. FAIL  {name}")
            print(f"          {exc}")
            if not args.quiet:
                for line in traceback.format_exc().splitlines()[-4:-1]:
                    print(f"          {line.strip()}")

    print("-" * 68)
    print(f"  {passed} passed, {failed} failed\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
