"""HTTP API. Everything the UI talks to lives here."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
import time

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .. import alerts as alert_module
from .. import (
    db,
    detections,
    doctor,
    exporters,
    gps,
    installer,
    netaudit,
    oui,
    recovery,
    reporting,
    runtime,
    scanner,
    selfupdate,
    survey,
    updater,
    usbwifi,
)
from .. import hotspot as hotspot_module
from ..config import config, data_dir
from ..services import (
    adapters_svc,
    decode,
    devices_svc,
    lifecycle,
    maintenance,
    settings_svc,
    survey_svc,
)
from ..services import findings as findings_service
from ..services import marks as marks_service
from ..services import networks as networks_service
from ..services import spectrum as spectrum_service

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


async def require_token(request: Request) -> None:
    """No-op unless an API token is configured."""
    token = config.get("server", "api_token", default="")
    if not token:
        return
    supplied = request.headers.get("x-api-token") or request.query_params.get("token")
    if supplied != token:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


Auth = Depends(require_token)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict:
    return {"ok": True, "version": updater.version(), "ts": time.time()}


@router.get("/status", dependencies=[Auth])
async def status() -> dict:
    engine = scanner.engine.status()
    return {
        "engine": engine,
        "alerts": db.alert_counts(),
        "stats": db.stats(),
        "gps": gps.reader.status(),
        "dispatcher": alert_module.dispatcher.status(),
        "update": updater.state(),
        "version": updater.version(),
        "db_size_bytes": db.db_size_bytes(),
        "vendor_db": {"source": oui.db.source, "size": oui.db.size},
        "server_time": time.time(),
    }


@router.get("/stats", dependencies=[Auth])
async def stats() -> dict:
    return db.stats()


# ---------------------------------------------------------------------------
# Networks
# ---------------------------------------------------------------------------


# Kept as a name because several handlers below read better with it. The
# behaviour lives in the service layer so the desktop interface shares it.
_decode = decode.bss


@router.get("/networks", dependencies=[Auth])
async def networks(
    minutes: float | None = Query(None, ge=0, description="Only APs seen in this window"),
    search: str | None = None,
    band: str | None = None,
    security: str | None = None,
    order: str = "rssi",
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> dict:
    return await asyncio.to_thread(
        networks_service.listing, minutes, search, band, security, order,
        limit, offset,
    )


@router.get("/networks/grouped", dependencies=[Auth])
async def grouped_networks(
    minutes: float | None = Query(None, ge=0),
    search: str | None = None,
    band: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
) -> dict:
    """One entry per network name, with every radio serving it.

    A tri-band AP publishes the same SSID on 2.4, 5 and 6 GHz with a different
    BSSID each, so a flat list makes one network look like three.
    """
    return await asyncio.to_thread(
        networks_service.grouped, minutes, search, band, limit)


@router.get("/networks/{bssid}", dependencies=[Auth])
async def network_detail(bssid: str) -> dict:
    row = db.get_bss(oui.normalise(bssid))
    if not row:
        raise HTTPException(status_code=404, detail="That BSSID has not been seen")
    return _decode(row)


@router.get("/networks/{bssid}/history", dependencies=[Auth])
async def network_history(bssid: str, limit: int = Query(500, ge=1, le=5000)) -> dict:
    normalised = oui.normalise(bssid)
    if not db.get_bss(normalised):
        raise HTTPException(status_code=404, detail="That BSSID has not been seen")
    return {"bssid": normalised, "history": db.bss_history(normalised, limit)}


@router.post("/networks/{bssid}/note", dependencies=[Auth])
async def set_note(bssid: str, payload: dict = Body(...)) -> dict:
    normalised = oui.normalise(bssid)
    if not db.get_bss(normalised):
        raise HTTPException(status_code=404, detail="That BSSID has not been seen")
    note = str(payload.get("note", ""))[:2000]
    db.set_note(normalised, note)
    return {"ok": True, "bssid": normalised, "note": note}


@router.get("/ssids", dependencies=[Auth])
async def ssids(minutes: float | None = Query(None, ge=0)) -> dict:
    since = time.time() - minutes * 60 if minutes else None
    return {"ssids": db.ssid_groups(since)}


@router.get("/channels", dependencies=[Auth])
async def channels(minutes: float | None = Query(None, ge=0)) -> dict:
    since = time.time() - minutes * 60 if minutes else None
    return {"channels": db.channel_usage(since)}


@router.get("/spectrum", dependencies=[Auth])
async def spectrum(minutes: float = Query(10, ge=0)) -> dict:
    """Occupancy laid out by frequency: what the ribbon in the UI draws."""
    return await asyncio.to_thread(spectrum_service.layout, minutes)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@router.get("/adapters", dependencies=[Auth])
async def list_adapters(refresh: bool = False) -> dict:
    """Every wireless adapter with enough detail to tell them apart.

    `refresh=true` bypasses the short cache, which is what the Rescan button
    wants. Without it repeated clicks would return the same cached answer.
    """
    return await asyncio.to_thread(adapters_svc.overview, refresh)


# Kept so older links and scripts do not break.
@router.get("/interfaces", dependencies=[Auth])
async def interfaces() -> dict:
    found = await asyncio.to_thread(scanner.engine.list_interfaces)
    return {"interfaces": found, "selected": config.get("scan", "interface_guid", default="")}


@router.get("/adapters/usb", dependencies=[Auth])
async def usb_devices() -> dict:
    """Every USB device that looks like a wireless adapter, working or not.

    The Native Wifi API only lists adapters that reached a usable state, so a
    disabled or driverless radio is invisible there. This is how the app tells
    "nothing plugged in" apart from "plugged in but broken".
    """
    summary = await asyncio.to_thread(usbwifi.summarise)
    return summary


@router.get("/adapters/diagnose", dependencies=[Auth])
async def diagnose_adapters() -> dict:
    """Read-only check of why an adapter is not available, and what would help."""
    return await asyncio.to_thread(recovery.diagnose)


@router.post("/adapters/repair", dependencies=[Auth])
async def repair_adapters(payload: dict = Body(default={})) -> dict:
    """Attempt the repair sequence. Changes device state, so it is never automatic."""
    return await asyncio.to_thread(
        adapters_svc.repair,
        bool(payload.get("dry_run", False)),
        bool(payload.get("elevate", True)),
    )


@router.post("/adapters/elevate", dependencies=[Auth])
async def elevate() -> dict:
    """Relaunch with a UAC prompt so the administrator-only repairs can run."""
    if sys.platform != "win32":
        raise HTTPException(status_code=400, detail="Only applies on Windows.")
    result = await asyncio.to_thread(recovery.relaunch_elevated)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    def shutdown() -> None:
        time.sleep(2)
        scanner.engine.stop()
        import os

        os._exit(0)

    threading.Thread(target=shutdown, daemon=True).start()
    return result


@router.post("/adapters/select", dependencies=[Auth])
@router.post("/interfaces/select", dependencies=[Auth])
async def select_adapter(payload: dict = Body(...)) -> dict:
    result = await asyncio.to_thread(
        adapters_svc.select, str(payload.get("guid", "")))
    return {"ok": True, **result}


@router.post("/scan/start", dependencies=[Auth])
async def start_scanning(payload: dict = Body(default={})) -> dict:
    """Begin a scanning session. Nothing scans until this is called."""
    guid = payload.get("guid")
    result = await asyncio.to_thread(
        scanner.engine.begin, str(guid) if guid is not None else None
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Could not start"))
    config.set(True, "ui", "onboarded")
    return result


@router.post("/scan/stop", dependencies=[Auth])
async def stop_scanning() -> dict:
    return await asyncio.to_thread(scanner.engine.halt)


@router.get("/sessions", dependencies=[Auth])
async def sessions(limit: int = Query(50, ge=1, le=500)) -> dict:
    return {"sessions": db.list_sessions(limit)}


@router.get("/activity", dependencies=[Auth])
async def activity(limit: int = Query(40, ge=1, le=200)) -> dict:
    status = scanner.engine.status()
    return {"activity": status["activity"][-limit:], "phase": status["phase"],
            "phase_detail": status["phase_detail"]}


@router.post("/scan", dependencies=[Auth])
async def scan_now(wait: bool = Query(False)) -> dict:
    """Run a single scan. Works whether or not continuous scanning is on."""
    if wait:
        try:
            result = await asyncio.to_thread(scanner.engine.run_once)
            return {"ok": True, **result}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
    scanner.engine.scan_now()
    return {"ok": True, "message": "Scan queued"}


@router.post("/scan/toggle", dependencies=[Auth])
async def toggle_scan(payload: dict = Body(default={})) -> dict:
    enabled = payload.get("enabled")
    if enabled is None:
        enabled = not config.get("scan", "enabled", default=False)
    if enabled:
        result = await asyncio.to_thread(scanner.engine.begin, None)
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("error"))
        return {"ok": True, "enabled": True, **result}
    await asyncio.to_thread(scanner.engine.halt)
    return {"ok": True, "enabled": False}


@router.get("/scans", dependencies=[Auth])
async def scans(limit: int = Query(50, ge=1, le=500)) -> dict:
    return {"scans": db.recent_scans(limit)}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts", dependencies=[Auth])
async def list_alerts(
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    rule: str | None = None,
    unacked_only: bool = False,
    minutes: float | None = Query(None, ge=0),
) -> dict:
    return await asyncio.to_thread(
        findings_service.listing, limit, offset, severity, rule,
        unacked_only, minutes,
    )


@router.post("/alerts/ack", dependencies=[Auth])
async def ack_alerts(payload: dict = Body(default={})) -> dict:
    count = await asyncio.to_thread(
        findings_service.acknowledge, payload.get("ids"), payload.get("before"))
    return {"ok": True, "acknowledged": count}


@router.post("/alerts/unack", dependencies=[Auth])
async def unacknowledge(payload: dict = Body(default={})) -> dict:
    """Put findings back in the open list so they can be looked at again."""
    result = await asyncio.to_thread(
        findings_service.unacknowledge, payload.get("ids"), payload.get("rule"))
    return {"ok": True, **result}


@router.post("/alerts/clear", dependencies=[Auth])
async def clear_alerts(payload: dict = Body(default={})) -> dict:
    """Delete findings. Their cooldowns go too, so anything still true is
    reported again on the next scan rather than staying quiet."""
    result = await asyncio.to_thread(
        findings_service.clear,
        payload.get("scope", "acknowledged"), payload.get("ids"),
        payload.get("rule"), float(payload.get("days", 30)),
    )
    return {"ok": True, **result}


@router.post("/alerts/reset-cooldowns", dependencies=[Auth])
async def reset_cooldowns() -> dict:
    """Forget every suppression so all current conditions re-report at once."""
    return {"ok": True, **await asyncio.to_thread(findings_service.reset_cooldowns)}


@router.get("/alerts/rules", dependencies=[Auth])
async def alert_rules() -> dict:
    return {"rules": detections.rule_names()}


@router.post("/alerts/test/{sink}", dependencies=[Auth])
async def test_alert(sink: str) -> dict:
    result = await asyncio.to_thread(alert_module.dispatcher.test, sink)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


# ---------------------------------------------------------------------------
# Marks
# ---------------------------------------------------------------------------

VALID_KINDS = {"watch", "trusted", "ignore"}
VALID_MATCH_TYPES = {"bssid", "oui", "ssid", "ssid_prefix"}


@router.get("/marks", dependencies=[Auth])
async def marks() -> dict:
    return {"marks": db.list_marks()}


@router.post("/marks", dependencies=[Auth])
async def add_mark(payload: dict = Body(...)) -> dict:
    marks = await asyncio.to_thread(
        marks_service.add, payload.get("kind"), payload.get("match_type"),
        payload.get("value"), payload.get("label"),
    )
    return {"ok": True, "marks": marks}


@router.delete("/marks/{mark_id}", dependencies=[Auth])
async def remove_mark(mark_id: int) -> dict:
    removed = db.delete_mark(mark_id)
    if not removed:
        raise HTTPException(status_code=404, detail="No mark with that ID")
    return {"ok": True, "marks": db.list_marks()}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@router.get("/settings", dependencies=[Auth])
async def get_settings() -> dict:
    return settings_svc.current()


@router.put("/settings", dependencies=[Auth])
async def update_settings(patch: dict = Body(...)) -> dict:
    updated = settings_svc.update(patch)
    return {"ok": True, "settings": updated,
            "note": "Server host and port need a restart."}


@router.post("/settings/reset", dependencies=[Auth])
async def reset_settings() -> dict:
    return {"ok": True, "settings": settings_svc.reset()}


# Both interfaces push settings into the running workers the same way.
_apply_runtime_settings = settings_svc.apply_runtime


# ---------------------------------------------------------------------------
# GPS
# ---------------------------------------------------------------------------


@router.get("/gps", dependencies=[Auth])
async def gps_status() -> dict:
    return {"status": gps.reader.status(), "ports": gps.list_serial_ports()}


@router.post("/gps/restart", dependencies=[Auth])
async def gps_restart() -> dict:
    _apply_runtime_settings()
    return {"ok": True, "status": gps.reader.status()}


# ---------------------------------------------------------------------------
# Local device discovery
# ---------------------------------------------------------------------------


@router.get("/devices", dependencies=[Auth])
async def list_devices(minutes: float | None = None, site_id: int | None = None,
                       include_infrastructure: bool = False) -> dict:
    """Devices recorded by previous discovery passes.

    Broadcast, multicast and network addresses are filtered out by default,
    the same way the desktop interface filters them.
    """
    rows = await asyncio.to_thread(
        devices_svc.listing, site_id, minutes, include_infrastructure)
    return {"devices": rows, "count": len(rows)}


@router.post("/devices/discover", dependencies=[Auth])
async def discover_devices(payload: dict = Body(default={})) -> dict:
    """Find what is reachable on the networks this machine is attached to.

    This is separate from the wireless survey: Wi-Fi client frames are not
    visible to us, but everything on the local network is.
    """
    return await asyncio.to_thread(
        devices_svc.discover,
        float(payload.get("timeout", 4)),
        include_mdns=bool(payload.get("mdns", True)),
        include_ssdp=bool(payload.get("ssdp", True)),
        include_netbios=bool(payload.get("netbios", True)),
        include_bluetooth=bool(payload.get("bluetooth", True)),
        resolve_hostnames=bool(payload.get("hostnames", True)),
    )


@router.post("/devices/note", dependencies=[Auth])
async def device_note(payload: dict = Body(...)) -> dict:
    ip = str(payload.get("ip", "")).strip()
    if not ip:
        raise HTTPException(status_code=400, detail="An IP address is required")
    db.set_device_note(ip, str(payload.get("mac", "")), str(payload.get("note", ""))[:2000])
    return {"ok": True}


@router.delete("/devices", dependencies=[Auth])
async def forget_devices(days: float | None = None) -> dict:
    removed = db.forget_devices(days)
    return {"ok": True, "removed": removed}


# ---------------------------------------------------------------------------
# Hotspot and internet sharing
# ---------------------------------------------------------------------------


@router.get("/hotspot", dependencies=[Auth])
async def hotspot_status() -> dict:
    return await asyncio.to_thread(hotspot_module.status)


@router.post("/hotspot/configure", dependencies=[Auth])
async def hotspot_configure(payload: dict = Body(...)) -> dict:
    result = await asyncio.to_thread(
        hotspot_module.configure,
        str(payload.get("ssid", "")),
        str(payload.get("passphrase", "")),
        str(payload.get("band", "auto")),
    )
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/hotspot/start", dependencies=[Auth])
async def hotspot_start() -> dict:
    result = await asyncio.to_thread(hotspot_module.start)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/hotspot/stop", dependencies=[Auth])
async def hotspot_stop() -> dict:
    result = await asyncio.to_thread(hotspot_module.stop)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/hotspot/sharing", dependencies=[Auth])
async def hotspot_sharing(payload: dict = Body(...)) -> dict:
    """Point internet sharing at a chosen upstream, typically the VPN adapter."""
    result = await asyncio.to_thread(
        hotspot_module.set_sharing,
        str(payload.get("source", "")),
        str(payload.get("target", "")),
        bool(payload.get("enable", True)),
    )
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


# ---------------------------------------------------------------------------
# Connect and audit
# ---------------------------------------------------------------------------


@router.get("/connect", dependencies=[Auth])
async def connection_status() -> dict:
    return {
        "connection": await asyncio.to_thread(netaudit.current_connection),
        "profiles": await asyncio.to_thread(netaudit.saved_profiles),
        "subnets": await asyncio.to_thread(netaudit.local_subnets),
        "gateway": await asyncio.to_thread(netaudit.gateway),
    }


@router.post("/connect", dependencies=[Auth])
async def connect_network(payload: dict = Body(...)) -> dict:
    ssid = str(payload.get("ssid", "")).strip()
    if not ssid:
        raise HTTPException(status_code=400, detail="A network name is required")

    passphrase = payload.get("passphrase")
    if passphrase:
        created = await asyncio.to_thread(
            netaudit.create_profile, ssid, str(passphrase),
            str(payload.get("security", "WPA2PSK")),
        )
        if not created.get("ok"):
            return JSONResponse(status_code=400, content=created)

    result = await asyncio.to_thread(
        netaudit.connect, ssid, payload.get("interface"),
        float(payload.get("wait", 20)),
    )
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/connect/disconnect", dependencies=[Auth])
async def disconnect_network(payload: dict = Body(default={})) -> dict:
    return await asyncio.to_thread(netaudit.disconnect, payload.get("interface"))


@router.post("/audit", dependencies=[Auth])
async def audit_network(payload: dict = Body(default={})) -> dict:
    """Enumerate and check services on the network this machine is connected to.

    Unlike the wireless survey this touches the network, so it is never
    automatic and only ever covers the local subnet.
    """
    if payload.get("confirm") != "audit":
        raise HTTPException(
            status_code=400,
            detail='This connects to services on the local network. Send '
                   '{"confirm": "audit"} to proceed, and only run it on a network '
                   "you are responsible for.",
        )
    ports = payload.get("ports")
    if ports is not None:
        try:
            ports = [int(p) for p in ports if 0 < int(p) < 65536][:64]
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Ports must be numbers") from None

    result = await asyncio.to_thread(
        netaudit.audit,
        ports,
        max(0.2, min(float(payload.get("timeout", 0.8)), 3.0)),
        max(1, min(int(payload.get("max_hosts", 128)), 512)),
        max(1.0, min(float(payload.get("discovery_timeout", 4)), 10.0)),
    )
    try:
        db.record_devices(result["hosts"], config.get("site", "active_id", default=None))
    except Exception as exc:
        log.warning("Could not record audited hosts: %s", exc)
    return result


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------


@router.get("/sites", dependencies=[Auth])
async def list_sites(include_archived: bool = False) -> dict:
    return {"sites": db.list_sites(include_archived),
            "active": config.get("site", "active_id", default=None)}


@router.post("/sites", dependencies=[Auth])
async def create_site(payload: dict = Body(...)) -> dict:
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="A site name is required")
    if len(name) > 120:
        raise HTTPException(status_code=400, detail="That name is too long")
    try:
        site_id = db.create_site(
            name, payload.get("client", ""), payload.get("address", ""),
            payload.get("contact", ""), payload.get("notes", ""),
        )
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(status_code=400,
                                detail="A site with that name already exists") from exc
        raise
    return {"ok": True, "id": site_id, "sites": db.list_sites()}


@router.put("/sites/{site_id}", dependencies=[Auth])
async def update_site(site_id: int, payload: dict = Body(...)) -> dict:
    if not db.get_site(site_id):
        raise HTTPException(status_code=404, detail="No site with that ID")
    db.update_site(site_id, payload)
    return {"ok": True, "sites": db.list_sites()}


@router.delete("/sites/{site_id}", dependencies=[Auth])
async def delete_site(site_id: int) -> dict:
    if not db.delete_site(site_id):
        raise HTTPException(status_code=404, detail="No site with that ID")
    if config.get("site", "active_id", default=None) == site_id:
        config.set(None, "site", "active_id")
    return {"ok": True, "sites": db.list_sites()}


@router.post("/sites/{site_id}/activate", dependencies=[Auth])
async def activate_site(site_id: int) -> dict:
    if site_id and not db.get_site(site_id):
        raise HTTPException(status_code=404, detail="No site with that ID")
    config.set(site_id or None, "site", "active_id")
    return {"ok": True, "active": site_id or None}


# ---------------------------------------------------------------------------
# Survey points and coverage
# ---------------------------------------------------------------------------


@router.get("/survey/points", dependencies=[Auth])
async def survey_points(site_id: int | None = None) -> dict:
    return {"points": db.list_survey_points(site_id)}


@router.post("/survey/points", dependencies=[Auth])
async def capture_point(payload: dict = Body(...)) -> dict:
    """Record what the radio hears right now at a named location."""
    result = await asyncio.to_thread(
        survey_svc.capture_point,
        payload.get("name", ""),
        bool(payload.get("scan_first", True)),
        payload.get("site_id"),
        payload.get("floor", ""),
        payload.get("notes", ""),
    )
    return {"ok": True, **result}


@router.get("/survey/points/{point_id}", dependencies=[Auth])
async def point_detail(point_id: int) -> dict:
    readings = db.survey_point_readings(point_id)
    if not readings:
        points = {p["id"] for p in db.list_survey_points()}
        if point_id not in points:
            raise HTTPException(status_code=404, detail="No survey point with that ID")
    return {"id": point_id, "readings": readings}


@router.delete("/survey/points/{point_id}", dependencies=[Auth])
async def remove_point(point_id: int) -> dict:
    if not db.delete_survey_point(point_id):
        raise HTTPException(status_code=404, detail="No survey point with that ID")
    return {"ok": True}


@router.get("/survey/coverage", dependencies=[Auth])
async def coverage(site_id: int | None = None, ssid: str | None = None) -> dict:
    return await asyncio.to_thread(survey.coverage_report, site_id, ssid)


@router.get("/survey/channel-plan", dependencies=[Auth])
async def channel_plan(minutes: float = Query(15, ge=1),
                       radios: int = Query(3, ge=1, le=8)) -> dict:
    return await asyncio.to_thread(survey.channel_plan, minutes, radios)


@router.get("/survey/interference", dependencies=[Auth])
async def interference(minutes: float = Query(15, ge=1)) -> dict:
    return {"bands": await asyncio.to_thread(survey.interference_report, minutes)}


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


@router.get("/snapshots", dependencies=[Auth])
async def list_snapshots(site_id: int | None = None) -> dict:
    return {"snapshots": db.list_snapshots(site_id)}


@router.post("/snapshots", dependencies=[Auth])
async def take_snapshot(payload: dict = Body(...)) -> dict:
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Give the snapshot a name")
    site_id = payload.get("site_id", config.get("site", "active_id", default=None))
    snapshot_id = await asyncio.to_thread(
        db.take_snapshot, name, site_id, payload.get("notes", ""),
        float(payload.get("minutes", 15)),
    )
    return {"ok": True, "id": snapshot_id, "snapshots": db.list_snapshots(site_id)}


@router.get("/snapshots/{snapshot_id}/compare", dependencies=[Auth])
async def compare(snapshot_id: int, minutes: float = Query(15, ge=1)) -> dict:
    result = await asyncio.to_thread(survey.compare_snapshot, snapshot_id, minutes)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.delete("/snapshots/{snapshot_id}", dependencies=[Auth])
async def remove_snapshot(snapshot_id: int) -> dict:
    if not db.delete_snapshot(snapshot_id):
        raise HTTPException(status_code=404, detail="No snapshot with that ID")
    return {"ok": True}


# ---------------------------------------------------------------------------
# AP inventory
# ---------------------------------------------------------------------------


@router.get("/inventory", dependencies=[Auth])
async def inventory(site_id: int | None = None) -> dict:
    return {"inventory": db.get_inventory(site_id)}


@router.post("/inventory/{bssid}", dependencies=[Auth])
async def set_inventory(bssid: str, payload: dict = Body(...)) -> dict:
    normalised = oui.normalise(bssid)
    if len(normalised.replace(":", "")) != 12:
        raise HTTPException(status_code=400, detail="That is not a full MAC address")
    fields = dict(payload)
    fields.setdefault("site_id", config.get("site", "active_id", default=None))
    db.set_inventory(normalised, fields)
    return {"ok": True, "entry": db.inventory_for(normalised)}


@router.delete("/inventory/{bssid}", dependencies=[Auth])
async def remove_inventory(bssid: str) -> dict:
    if not db.delete_inventory(oui.normalise(bssid)):
        raise HTTPException(status_code=404, detail="Nothing recorded for that BSSID")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Client report
# ---------------------------------------------------------------------------


@router.get("/report", dependencies=[Auth])
async def client_report(
    site_id: int | None = None,
    title: str = "Wireless Site Survey",
    prepared_by: str = "",
    minutes: float = Query(1440, ge=1),
    inventory: bool = True,
    coverage: bool = True,
    plan: bool = True,
) -> Response:
    if site_id is None:
        site_id = config.get("site", "active_id", default=None)
    body = await asyncio.to_thread(
        reporting.build, site_id, title, prepared_by, minutes, inventory, coverage, plan
    )
    stamp = time.strftime("%Y%m%d-%H%M")
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in title)[:60]
    return Response(
        content=body, media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{safe}-{stamp}.html"'},
    )


# ---------------------------------------------------------------------------
# Diagnostics, maintenance and updates
# ---------------------------------------------------------------------------


@router.get("/diagnostics", dependencies=[Auth])
async def diagnostics() -> dict:
    return await asyncio.to_thread(doctor.run_all)


@router.post("/maintenance/prune", dependencies=[Auth])
async def prune() -> dict:
    removed = await asyncio.to_thread(
        db.prune,
        int(config.get("retention", "observation_days", default=30)),
        int(config.get("retention", "alert_days", default=90)),
        int(config.get("retention", "gps_days", default=30)),
    )
    return {"ok": True, "removed": removed}


@router.post("/maintenance/compact", dependencies=[Auth])
async def compact() -> dict:
    before = db.db_size_bytes()
    await asyncio.to_thread(db.vacuum)
    after = db.db_size_bytes()
    return {
        "ok": True,
        "before_bytes": before,
        "after_bytes": after,
        "reclaimed_bytes": max(0, before - after),
    }


@router.post("/maintenance/reload-vendors", dependencies=[Auth])
async def reload_vendors() -> dict:
    await asyncio.to_thread(oui.autoload, data_dir())
    return {"ok": True, "source": oui.db.source, "size": oui.db.size}


@router.get("/install", dependencies=[Auth])
async def install_status() -> dict:
    try:
        return installer.status()
    except Exception as exc:
        log.warning("Could not read install status: %s", exc)
        return {
            "frozen": runtime.is_frozen(),
            "installed": False,
            "registered": False,
            "autostart": False,
            "version": runtime.version(),
            "error": str(exc),
        }


def _require_installable() -> None:
    """Shared guard so these endpoints fail with a reason, not a generic 500."""
    if sys.platform != "win32":
        raise HTTPException(
            status_code=400,
            detail="Install management only applies on Windows.",
        )
    if not runtime.is_frozen():
        raise HTTPException(
            status_code=400,
            detail="Install management belongs to the packaged build. Running from "
                   "source, start and stop it however you normally would.",
        )


@router.post("/install/autostart", dependencies=[Auth])
async def set_autostart(payload: dict = Body(default={})) -> dict:
    _require_installable()
    enabled = bool(payload.get("enabled", True))
    try:
        if enabled:
            ok = await asyncio.to_thread(
                installer.enable_autostart, runtime.executable_path()
            )
        else:
            ok = await asyncio.to_thread(installer.disable_autostart)
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"Could not change the autostart setting: {exc}"
        ) from exc
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Windows refused the autostart change. Check that Task Scheduler "
                   "is running, or set it up manually.",
        )
    return {"ok": True, "autostart": installer.autostart_enabled()}


@router.post("/install/uninstall", dependencies=[Auth])
async def uninstall_self(payload: dict = Body(default={})) -> dict:
    """Remove the app. The response goes out before the executable disappears."""
    _require_installable()
    if payload.get("confirm") != "uninstall":
        raise HTTPException(
            status_code=400,
            detail='Send {"confirm": "uninstall"} to go ahead. This cannot be undone.',
        )
    keep_data = bool(payload.get("keep_data", False))

    try:
        result = await asyncio.to_thread(
            installer.uninstall, keep_data, True
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Uninstall did not complete: {exc}"
        ) from exc

    def shutdown() -> None:
        time.sleep(1.5)
        scanner.engine.stop()
        gps.reader.stop()
        import os

        os._exit(0)

    threading.Thread(target=shutdown, daemon=True).start()
    result["message"] = "wifirecon has been removed. This page will stop responding."
    return result


@router.get("/updates", dependencies=[Auth])
async def check_updates(force: bool = False) -> dict:
    channel = config.get("updates", "channel", default="main")
    return await asyncio.to_thread(updater.check, channel, force)


@router.post("/updates/apply", dependencies=[Auth])
async def apply_update() -> dict:
    channel = config.get("updates", "channel", default="main")
    result = await asyncio.to_thread(updater.apply, channel, True)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/updates/package", dependencies=[Auth])
async def upload_package(request: Request) -> dict:
    """Update from a package the person supplies, with no repo or release needed.

    This is the path that matters in practice: a new build arrives as a zip and
    the running install becomes that version without being deleted and rebuilt.
    """
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="No file was uploaded")
    if len(body) > selfupdate.MAX_PACKAGE_BYTES:
        raise HTTPException(status_code=400, detail="That file is too large")

    staging = data_dir() / "updates"
    staging.mkdir(parents=True, exist_ok=True)
    package = staging / "uploaded.zip"
    package.write_bytes(body)

    inspection = await asyncio.to_thread(selfupdate.inspect, package)
    if not inspection["ok"]:
        package.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=inspection["error"])

    dry_run = request.query_params.get("inspect") == "true"
    if dry_run:
        return inspection

    result = await asyncio.to_thread(selfupdate.apply_package, package, True)
    package.unlink(missing_ok=True)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.post("/updates/from-url", dependencies=[Auth])
async def update_from_url(payload: dict = Body(...)) -> dict:
    url = str(payload.get("url", "")).strip()
    if not url:
        raise HTTPException(status_code=400, detail="A URL is required")
    result = await asyncio.to_thread(selfupdate.apply_from_url, url, True)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@router.get("/updates/backups", dependencies=[Auth])
async def list_backups() -> dict:
    return {"backups": selfupdate.list_backups()}


@router.post("/updates/backups", dependencies=[Auth])
async def make_backup(payload: dict = Body(default={})) -> dict:
    return await asyncio.to_thread(selfupdate.create_backup,
                                   str(payload.get("label", "manual")))


@router.post("/updates/rollback", dependencies=[Auth])
async def rollback(payload: dict = Body(...)) -> dict:
    """Put a previous version back, for when an update goes wrong."""
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Which backup? Send its name.")
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="That is not a valid backup name")
    result = await asyncio.to_thread(selfupdate.restore, name)
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    selfupdate._schedule_restart()
    result["restarting"] = True
    return result


@router.post("/maintenance/clear-networks", dependencies=[Auth])
async def clear_networks(payload: dict = Body(default={})) -> dict:
    """Forget every observed network. Marks and inventory survive by default."""
    result = await asyncio.to_thread(
        maintenance.clear_networks,
        str(payload.get("confirm", "")),
        bool(payload.get("keep_marks", True)),
        bool(payload.get("keep_inventory", True)),
    )
    return {"ok": True, **result}


@router.post("/maintenance/wipe", dependencies=[Auth])
async def wipe(payload: dict = Body(...)) -> dict:
    """Delete everything: networks, findings, marks, sites, surveys, devices."""
    result = await asyncio.to_thread(
        maintenance.wipe,
        str(payload.get("confirm", "")),
        bool(payload.get("reset_settings", False)),
        bool(payload.get("compact", True)),
    )
    return {"ok": True, **result}


@router.post("/shutdown", dependencies=[Auth])
async def shutdown(payload: dict = Body(default={})) -> dict:
    """Stop cleanly: end the session, close the database, exit.

    Killing the process leaves the session open and the write-ahead log
    uncheckpointed, so this is the tidy way out.
    """
    if payload.get("confirm") != "shutdown":
        raise HTTPException(status_code=400,
                            detail='Send {"confirm": "shutdown"} to stop the app.')

    lifecycle.shutdown_now(delay=0.6)
    return {"ok": True, "message": "Shutting down. You can close this window."}


@router.get("/logs", dependencies=[Auth])
async def logs(lines: int = Query(200, ge=1, le=5000)) -> PlainTextResponse:
    text = await asyncio.to_thread(lifecycle.tail_log, lines)
    return PlainTextResponse(text, media_type="text/plain")


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

EXPORTS = {
    "networks.csv": (exporters.bss_csv, "text/csv"),
    "alerts.csv": (exporters.alerts_csv, "text/csv"),
    "observations.csv": (exporters.observations_csv, "text/csv"),
    "wigle.csv": (exporters.wigle_csv, "text/csv"),
    "survey.kml": (exporters.kml, "application/vnd.google-earth.kml+xml"),
    "survey.json": (exporters.full_json, "application/json"),
    "report.html": (exporters.html_report, "text/html"),
}


@router.get("/export/{name}", dependencies=[Auth])
async def export(name: str) -> Response:
    entry = EXPORTS.get(name)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown export. Available: {', '.join(sorted(EXPORTS))}",
        )
    builder, media_type = entry
    body = await asyncio.to_thread(builder)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base, _, ext = name.rpartition(".")
    filename = f"wifirecon-{base}-{stamp}.{ext}"
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export", dependencies=[Auth])
async def export_index() -> dict:
    return {"available": sorted(EXPORTS)}


# ---------------------------------------------------------------------------
# Live push
# ---------------------------------------------------------------------------


class ConnectionManager:
    def __init__(self) -> None:
        self.active: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active.discard(websocket)

    async def broadcast(self, message: dict) -> None:
        async with self._lock:
            targets = list(self.active)
        payload = json.dumps(message, default=str)
        dead = []
        for websocket in targets:
            try:
                await websocket.send_text(payload)
            except Exception:
                dead.append(websocket)
        if dead:
            async with self._lock:
                for websocket in dead:
                    self.active.discard(websocket)


manager = ConnectionManager()


@router.websocket("/live")
async def live(websocket: WebSocket) -> None:
    token = config.get("server", "api_token", default="")
    if token and websocket.query_params.get("token") != token:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    try:
        last_scan = 0.0
        while True:
            engine_status = scanner.engine.status()
            current = engine_status.get("last_scan_at") or 0.0
            if current != last_scan:
                last_scan = current
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "scan",
                            "engine": engine_status,
                            "alerts": db.alert_counts(),
                        },
                        default=str,
                    )
                )
            await asyncio.sleep(2)
    except Exception:
        pass
    finally:
        await manager.disconnect(websocket)
