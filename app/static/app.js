/* wifirecon-win front end. No build step, no dependencies. */
(() => {
"use strict";

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  view: "live",
  networks: [],
  marks: [],
  settings: null,
  sort: { key: "rssi", dir: -1 },
  token: new URLSearchParams(location.search).get("token") || "",
  flaggedBssids: new Set(),
  watchedBssids: new Set(),
  timers: {},
  socket: null,
  lastScanAt: 0,
  updateAvailable: false,
  adapters: [],
  chosenGuid: null,
  scanning: false,
  gateOpen: false,
  sites: [],
  activeSite: null,
  devices: [],
  pollFailures: 0,
  themeChoice: "dark",
};

/* ---------------------------------------------------------------- helpers */

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) headers["X-Api-Token"] = state.token;
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";

  // Without a timeout a stalled request hangs forever and the poller stacks up
  // behind it, which is what made a busy app look permanently disconnected.
  const controller = new AbortController();
  const limit = options.timeout || 30000;
  const timer = setTimeout(() => controller.abort(), limit);

  let response;
  try {
    response = await fetch(path, Object.assign({}, options,
      { headers, signal: controller.signal }));
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`That request took longer than ${Math.round(limit / 1000)}s `
                    + "and was given up on.");
    }
    throw new Error("The app is not responding. Is the server still running?");
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 401) throw new Error("This session needs an API token.");
  const text = await response.text();
  let payload = null;
  if (text) { try { payload = JSON.parse(text); } catch { payload = text; } }
  if (!response.ok) {
    const detail = payload && payload.detail ? payload.detail
                 : (payload && payload.error) ? payload.error
                 : `Request failed (HTTP ${response.status})`;
    throw new Error(detail);
  }
  return payload;
}

function toast(message, kind = "", title = "") {
  const host = $("#toasts");
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.innerHTML = (title ? `<b>${esc(title)}</b>` : "") + esc(message);
  host.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 200);
  }, kind === "err" ? 7000 : 3800);
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function ago(seconds) {
  if (seconds == null) return "never";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

function bandClass(band) {
  return band === "2.4" ? "b24" : band === "5" ? "b5" : band === "6" ? "b6" : "";
}

function bandColor(band) {
  const map = { "2.4": "--b24", "5": "--b5", "6": "--b6" };
  return `var(${map[band] || "--b60"})`;
}

function bytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function signalWidth(rssi) {
  if (rssi == null) return 0;
  return Math.max(2, Math.min(46, Math.round((rssi + 95) * 0.75)));
}

function debounce(fn, wait) {
  let handle;
  return (...args) => { clearTimeout(handle); handle = setTimeout(() => fn(...args), wait); };
}

/* ------------------------------------------------------------ navigation */

function showView(name) {
  state.view = name;
  $$("#nav button").forEach(b => b.classList.toggle("on", b.dataset.view === name));
  $$(".view").forEach(v => { v.hidden = v.id !== `view-${name}`; });
  const loaders = {
    live: loadNetworks,
    spectrum: loadSpectrum,
    findings: loadFindings,
    ssids: loadSsids,
    marks: loadMarks,
    history: loadHistory,
    devices: loadDevicesView,
    network: loadNetworkView,
    survey: loadSurveyView,
    report: loadReportView,
    adapters: loadAdapterView,
    diagnostics: loadDiagnostics,
    settings: loadSettings,
  };
  if (loaders[name]) loaders[name]();
}

$("#nav").addEventListener("click", e => {
  const button = e.target.closest("button[data-view]");
  if (button) showView(button.dataset.view);
});

/* ----------------------------------------------------------- adapters */

function adapterCard(a, selectedGuid, clickable = true) {
  const on = a.guid === selectedGuid;
  const radioOff = a.radio_on === false;
  const tags = [];
  if (a.recommended) tags.push('<span class="tag pick">recommended</span>');
  if (a.external) tags.push('<span class="tag good">external</span>');
  if (radioOff) tags.push('<span class="tag bad">radio off</span>');
  if (a.state === "connected") tags.push('<span class="tag warn">in use</span>');
  if ((a.bands || []).includes("6")) tags.push('<span class="tag good">6 GHz</span>');

  const fact = (label, value) => value
    ? `<div><span>${esc(label)}</span> <b>${esc(value)}</b></div>` : "";

  return `<div class="adapter${on ? " on" : ""}${radioOff ? " off" : ""}"
    data-guid="${esc(a.guid)}" ${clickable ? 'role="button" tabindex="0"' : ""}>
    ${clickable ? '<span class="radio"></span>' : ""}
    <div class="body">
      <div class="title"><b>${esc(a.label || a.description)}</b>${tags.join("")}</div>
      <div class="desc">${esc(a.description)}</div>
      <div class="facts">
        ${fact("Bands", a.band_label)}
        ${fact("Chipset", a.chipset)}
        ${fact("MAC", a.mac)}
        ${fact("Vendor", a.vendor)}
        ${fact("Driver", a.driver)}
        ${fact("Provider", a.driver_provider)}
        ${fact("Radio", a.radio_on === null ? null : (a.radio_on ? "on" : "off"))}
        ${fact("Status", a.state_label || a.state)}
        ${fact("Connected to", a.connected_ssid)}
        ${fact("Modes", (a.radio_types || []).join(" "))}
      </div>
      ${a.error ? `<div class="note" style="color:var(--crit);margin-top:6px">
        ${esc(a.error)}</div>` : ""}
    </div>
  </div>`;
}

async function loadAdapters(into, refresh = false) {
  const data = await api(`/api/adapters${refresh ? "?refresh=true" : ""}`);
  state.adapters = data.adapters;
  if (state.chosenGuid === null) {
    state.chosenGuid = data.selected
      || (data.adapters.find(a => a.recommended) || {}).guid
      || (data.adapters[0] || {}).guid
      || "";
  }
  return data;
}

async function openGate() {
  state.gateOpen = true;
  $("#gate").hidden = false;
  await renderGate();
}

function closeGate() {
  state.gateOpen = false;
  $("#gate").hidden = true;
}

async function renderGate(refresh = false) {
  const host = $("#gate-adapters");
  host.innerHTML = '<div class="empty">Looking for wireless adapters\u2026</div>';
  let data;
  try {
    data = await loadAdapters(null, refresh);
  } catch (err) {
    host.innerHTML = `<div class="empty"><b>Could not list adapters</b>${esc(err.message)}</div>`;
    return;
  }
  if (!data.adapters.length) {
    host.innerHTML = `<div class="empty"><b>No wireless adapters available</b>
      Checking whether one is plugged in but not working\u2026</div>`;
    $("#gate-start").disabled = true;
    $("#gate-hint").textContent = "";
    // An adapter that is disabled or driverless is invisible to the Wi-Fi API,
    // so go straight to the deeper check rather than saying "nothing found".
    diagnoseAdapters($("#gate-repair"));
    return;
  }
  $("#gate-repair").hidden = true;
  host.innerHTML = data.adapters.map(a => adapterCard(a, state.chosenGuid)).join("");
  const chosen = data.adapters.find(a => a.guid === state.chosenGuid);
  $("#gate-start").disabled = !chosen || chosen.radio_on === false;
  $("#gate-hint").textContent = !data.has_external
    ? "No external adapter detected \u2014 this will scan on the built-in radio."
    : "";
}

$("#gate-adapters").addEventListener("click", e => {
  const card = e.target.closest("[data-guid]");
  if (!card) return;
  state.chosenGuid = card.dataset.guid;
  renderGate();
});
$("#gate-adapters").addEventListener("keydown", e => {
  if (e.key === "Enter" || e.key === " ") {
    const card = e.target.closest("[data-guid]");
    if (card) { e.preventDefault(); state.chosenGuid = card.dataset.guid; renderGate(); }
  }
});
$("#gate-refresh").addEventListener("click", () => renderGate(true));

/* ------------------------------------------------------- adapter recovery */

const STEP_LABEL = {
  fixed: "fixed", no_action: "ok", skipped: "n/a",
  failed: "failed", needs_admin: "needs admin", manual: "do this",
};

function renderRepair(host, report, { diagnosis = false } = {}) {
  const state = report.state || report.before || {};
  const problems = state.problems || [];

  const steps = (report.steps || report.planned || []).map(step => {
    const status = step.status || (step.blocked ? "needs_admin" : "skipped");
    return `<div class="repair-step">
      <span class="mark ${esc(status)}">${esc(STEP_LABEL[status] || status)}</span>
      <div class="body">
        <b>${esc(step.name)}</b>
        ${step.message ? `<span>${esc(step.message)}</span>` : ""}
        ${step.detail ? `<span>${esc(step.detail)}</span>` : ""}
      </div>
    </div>`;
  }).join("");

  const brokenList = problems.length
    ? `<div class="broken-list">${problems.map(p =>
        `${esc(p.model || p.name)} \u2014 ${esc(p.problem)} (code ${p.code})`
      ).join("<br>")}</div>`
    : "";

  const needsAdmin = report.needs_admin
    || (report.steps || []).some(s => s.status === "needs_admin");

  const actions = [];
  if (needsAdmin && !report.admin) {
    actions.push(`<button class="btn primary small" id="repair-run">
      Fix it (asks for permission)</button>`);
    actions.push(`<span class="mono dim">Windows prompts once. wifirecon keeps
      running \u2014 only the repair itself is elevated.</span>`);
  } else if (diagnosis) {
    actions.push(`<button class="btn primary small" id="repair-run">
      Try to fix it</button>`);
    actions.push(`<span class="mono dim">Enables and restarts adapters only. Nothing is
      uninstalled or deleted.</span>`);
  } else {
    actions.push(`<button class="btn small" id="repair-run">Run again</button>`);
    actions.push(`<button class="btn small" id="repair-close">Close</button>`);
  }

  host.hidden = false;
  host.innerHTML = `
    <h3>${diagnosis ? "What is wrong" : "Repair results"}</h3>
    <div class="verdict">${esc(report.verdict || report.summary || "")}</div>
    ${brokenList}
    <div class="repair-steps" style="margin-top:10px">${steps}</div>
    <div class="repair-actions">${actions.join(" ")}</div>`;

  const elevate = host.querySelector("#repair-elevate");
  if (elevate) elevate.addEventListener("click", async () => {
    elevate.disabled = true;
    elevate.textContent = "Waiting for permission\u2026";
    try {
      const result = await api("/api/adapters/elevate", { method: "POST" });
      host.innerHTML = `<h3>Restarting with administrator rights</h3>
        <div class="verdict">${esc(result.message)}</div>
        <div class="repair-steps"><div class="repair-step">
          <span class="mark no_action">wait</span>
          <div class="body"><b>Reconnecting</b><span id="elevate-status">
            The old copy is shutting down\u2026</span></div>
        </div></div>`;

      // The new instance waits for this one to release the port, so reconnection
      // takes a few seconds. Poll until it answers rather than leaving a dead page.
      clearInterval(state.timers.status);
      let tries = 0;
      const poll = setInterval(async () => {
        tries += 1;
        const status = document.getElementById("elevate-status");
        try {
          await api("/api/health");
          clearInterval(poll);
          location.reload();
        } catch {
          if (status) {
            status.textContent = tries < 6
              ? "The old copy is shutting down\u2026"
              : `Waiting for the elevated copy to start (${tries * 2}s)\u2026`;
          }
          if (tries > 30) {
            clearInterval(poll);
            if (status) {
              status.textContent = "It did not come back. If you declined the Windows "
                + "prompt, nothing was changed. Otherwise start wifirecon again from "
                + "the Start Menu.";
            }
          }
        }
      }, 2000);
    } catch (err) {
      toast(err.message, "err");
      elevate.disabled = false;
      elevate.textContent = "Restart as administrator";
    }
  });

  const rerun = host.querySelector("#repair-run");
  if (rerun) rerun.addEventListener("click", () => runRepair(host));

  const close = host.querySelector("#repair-close");
  if (close) close.addEventListener("click", () => { host.hidden = true; });
}

async function diagnoseAdapters(host) {
  host.hidden = false;
  host.innerHTML = '<div class="empty">Checking what Windows can see\u2026</div>';
  try {
    const report = await api("/api/adapters/diagnose");
    renderRepair(host, report, { diagnosis: true });
  } catch (err) {
    host.innerHTML = `<div class="empty"><b>Could not run the check</b>${esc(err.message)}</div>`;
  }
}

async function runRepair(host) {
  // The privileged work happens in a short-lived helper process, so the app and
  // this page stay up. Windows prompts once.
  host.hidden = false;
  let elapsed = 0;
  host.innerHTML = '<div class="empty">Working through the repair steps\u2026<br>'
    + '<span class="dim" id="repair-elapsed">Enumerating devices. This can take a '
    + 'minute or two on a machine with a lot of USB hardware.</span></div>';
  const tick = setInterval(() => {
    elapsed += 2;
    const node = document.getElementById("repair-elapsed");
    if (node) node.textContent = `Still working (${elapsed}s). Device enumeration is `
      + "the slow part; it will finish.";
  }, 2000);
  try {
    const report = await api("/api/adapters/repair", { method: "POST",
      body: JSON.stringify({ elevate: true }) });
    clearInterval(tick);
    renderRepair(host, report, { diagnosis: false });
    if (report.resolved) {
      toast(report.summary, "ok", "Adapter recovered");
      await renderGate();
      if (state.view === "adapters") loadAdapterView();
    } else {
      toast(report.summary, "err", "Still not working");
    }
  } catch (err) {
    clearInterval(tick);
    host.innerHTML = `<div class="empty"><b>Repair could not finish</b>${esc(err.message)}
      <br><span class="dim">You can also run it from a prompt with
      <code>wifirecon --fix-adapter</code>, which shows more detail.</span></div>`;
  }
}

$("#gate-fix").addEventListener("click", () => diagnoseAdapters($("#gate-repair")));
$("#btn-adapters-fix").addEventListener("click", () =>
  diagnoseAdapters($("#adapter-repair")));

$("#gate-start").addEventListener("click", async () => {
  $("#gate-start").disabled = true;
  $("#gate-start").textContent = "Starting\u2026";
  try {
    const result = await api("/api/scan/start", { method: "POST",
      body: JSON.stringify({ guid: state.chosenGuid }) });
    toast(`Scanning on ${result.adapter.label || result.adapter.description}`, "ok");
    closeGate();
    await refreshStatus();
    showView("live");
  } catch (err) {
    toast(err.message, "err");
  } finally {
    $("#gate-start").disabled = false;
    $("#gate-start").textContent = "Start scanning";
  }
});

$("#adapter-chip").addEventListener("click", () => showView("adapters"));

async function loadAdapterView(refresh = false) {
  const host = $("#adapter-cards");
  host.innerHTML = '<div class="empty">Looking for adapters\u2026</div>';
  try {
    const data = await loadAdapters(null, refresh);
    const probe = data.probe || {};
    $("#adapter-count").textContent =
      `${data.adapters.length} adapter${data.adapters.length === 1 ? "" : "s"}`
      + (probe.paused_until ? " \u00b7 probe paused" : "");
    if (probe.consecutive_failures > 0) {
      toast("Reading adapter details is failing, so this list may be out of date. "
            + "The app itself is fine.", "err", "Adapter probe");
    }
    host.innerHTML = data.adapters.length
      ? data.adapters.map(a => adapterCard(a, data.selected || (data.active || {}).guid)).join("")
      : `<div class="empty"><b>No wireless adapters found</b>Plug one in and press
         Rescan.</div>`;
  } catch (err) {
    host.innerHTML = `<div class="empty"><b>Could not list adapters</b>${esc(err.message)}</div>`;
  }

  try {
    const data = await api("/api/activity?limit=60");
    $("#activity-feed").innerHTML = data.activity.length
      ? data.activity.slice().reverse().map(a =>
          `<div class="${esc(a.level)}"><time>${
            new Date(a.ts * 1000).toLocaleTimeString()}</time><span>${
            esc(a.message)}</span></div>`).join("")
      : '<div class="empty" style="padding:16px">Nothing yet.</div>';
  } catch { /* non-fatal */ }

  try {
    const data = await api("/api/sessions?limit=30");
    $("#session-rows").innerHTML = data.sessions.length
      ? data.sessions.map(s => {
          const length = s.ended_at
            ? ago(s.ended_at - s.started_at)
            : `<span style="color:var(--ok)">running</span>`;
          return `<tr>
            <td class="mono dim">${new Date(s.started_at * 1000).toLocaleString()}</td>
            <td>${esc(s.adapter_name || "")}</td>
            <td class="right mono">${s.live_scans ?? s.scan_count ?? 0}</td>
            <td class="right mono">${s.live_bss ?? s.bss_count ?? 0}</td>
            <td class="right mono">${s.live_alerts ?? s.alert_count ?? 0}</td>
            <td class="mono dim">${length}</td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="6"><div class="empty">No sessions recorded yet.</div></td></tr>`;
  } catch { /* non-fatal */ }
}

$("#adapter-cards").addEventListener("click", async e => {
  const card = e.target.closest("[data-guid]");
  if (!card) return;
  try {
    await api("/api/adapters/select", { method: "POST",
      body: JSON.stringify({ guid: card.dataset.guid }) });
    toast(state.scanning
      ? "Adapter switched. It takes effect on the next scan."
      : "Adapter selected.", "ok");
    loadAdapterView();
    refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-adapters-refresh").addEventListener("click", async () => {
  const button = $("#btn-adapters-refresh");
  button.disabled = true;
  try { await loadAdapterView(true); } finally { button.disabled = false; }
});

/* ------------------------------------------------------------- live view */

async function loadNetworks() {
  const minutes = $("#live-window").value;
  const params = new URLSearchParams({ limit: "1000", order: state.sort.key });
  if (minutes) params.set("minutes", minutes);
  const search = $("#live-search").value.trim();
  if (search) params.set("search", search);
  const band = $("#live-band").value;
  if (band) params.set("band", band);

  try {
    const data = await api(`/api/networks?${params}`);
    state.networks = data.networks;
    renderNetworks();
  } catch (err) {
    $("#live-rows").innerHTML = errorRow(9, err.message);
  }
}

function errorRow(colspan, message) {
  return `<tr><td colspan="${colspan}"><div class="empty">
    <b>Could not load this</b>${esc(message)}</div></td></tr>`;
}

function sortNetworks(rows) {
  const { key, dir } = state.sort;
  return rows.slice().sort((a, b) => {
    let x = a[key], y = b[key];
    if (key === "channel") {
      x = `${a.band}-${String(a.channel ?? 0).padStart(4, "0")}`;
      y = `${b.band}-${String(b.channel ?? 0).padStart(4, "0")}`;
    }
    if (x == null) return 1;
    if (y == null) return -1;
    if (typeof x === "string") return x.localeCompare(y) * dir;
    return (x - y) * dir;
  });
}

function renderNetworks() {
  state.recentCount = state.networks.length;
  const onlyFlagged = $("#live-flagged").checked;
  const bandOf = new Map();
  state.networks.forEach(n => {
    if (!n.ssid || n.hidden) return;
    if (!bandOf.has(n.ssid)) bandOf.set(n.ssid, new Set());
    bandOf.get(n.ssid).add(n.band);
  });
  state.siblingBands = bandOf;
  let rows = state.networks;
  if (onlyFlagged) rows = rows.filter(r => state.flaggedBssids.has(r.bssid));
  rows = sortNetworks(rows);

  $("#live-count").textContent = `${rows.length} shown`;
  $("#nav-live").textContent = state.networks.length;

  if (!rows.length) {
    $("#live-rows").innerHTML = `<tr><td colspan="9"><div class="empty">
      <b>Nothing in range yet</b>The first scan takes a few seconds. If it stays empty,
      open Diagnostics to check the adapter.</div></td></tr>`;
    return;
  }

  const now = Date.now() / 1000;
  $("#live-rows").innerHTML = rows.map(r => {
    const age = now - (r.last_seen || 0);
    const classes = [];
    if (state.flaggedBssids.has(r.bssid)) classes.push("flagged");
    else if (state.watchedBssids.has(r.bssid)) classes.push("watched");
    if (age > 300) classes.push("stale");

    const load = r.utilization_pct != null
      ? `${Math.round(r.utilization_pct)}%${r.station_count ? ` / ${r.station_count}` : ""}`
      : "";

    return `<tr class="${classes.join(" ")}" data-bssid="${esc(r.bssid)}">
      <td class="mono">
        <i class="bar ${bandClass(r.band)}" style="width:${signalWidth(r.rssi)}px"></i>${r.rssi ?? "?"}
      </td>
      <td>${r.hidden ? '<span class="dim">(hidden)</span>' : esc(r.ssid || "(no name)")}
        ${siblingHint(r)}</td>
      <td><span class="chip ${bandClass(r.band)}">${esc(r.band || "?")} &middot; ${r.channel ?? "?"}</span>
          <span class="dim mono">${r.width_mhz || 20}</span></td>
      <td>${securityCell(r)}</td>
      <td class="dim">${esc(r.phy || "")}</td>
      <td class="mono dim">${esc(r.bssid)}</td>
      <td class="dim">${esc(r.vendor || "")}</td>
      <td class="right mono dim">${esc(load)}</td>
      <td class="right mono dim">${ago(age)}</td>
    </tr>`;
  }).join("");
}

function siblingHint(r) {
  // Flag names that also appear on another band, so a tri-band AP reads as one
  // network rather than three unrelated rows.
  if (!r.ssid || r.hidden) return "";
  const bands = state.siblingBands && state.siblingBands.get(r.ssid);
  if (!bands || bands.size < 2) return "";
  const others = [...bands].filter(b => b !== r.band).sort();
  return `<span class="chip" title="Same name also on ${others.join(", ")} GHz"
    style="margin-left:6px">+${others.join("/")}</span>`;
}

function securityCell(r) {
  const marks = [];
  if (r.security === "Open") marks.push('<span class="sev high">OPEN</span>');
  else if (r.security === "WEP") marks.push('<span class="sev critical">WEP</span>');
  else marks.push(esc(r.security));
  if (r.wps) marks.push('<span class="chip">WPS</span>');
  if (r.enterprise) marks.push('<span class="chip">802.1X</span>');
  if (!r.mfp_capable && r.security !== "Open" && r.security !== "WEP") {
    marks.push('<span class="chip" title="No management frame protection">no PMF</span>');
  }
  return marks.join(" ");
}

$("#live-table").addEventListener("click", e => {
  const th = e.target.closest("th.sortable");
  if (th) {
    const key = th.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : -1 };
    $$("#live-table th").forEach(h => { const a = h.querySelector(".arrow"); if (a) a.remove(); });
    th.insertAdjacentHTML("beforeend",
      `<span class="arrow">${state.sort.dir < 0 ? "\u25be" : "\u25b4"}</span>`);
    renderNetworks();
    return;
  }
  const row = e.target.closest("tr[data-bssid]");
  if (row) openDrawer(row.dataset.bssid);
});

$("#live-search").addEventListener("input", debounce(loadNetworks, 250));
$("#live-band").addEventListener("change", loadNetworks);
$("#live-window").addEventListener("change", loadNetworks);
$("#live-flagged").addEventListener("change", renderNetworks);

/* -------------------------------------------------------- spectrum ribbon */

async function loadSpectrum() {
  const minutes = $("#spectrum-window").value;
  try {
    const [spectrum, channels] = await Promise.all([
      api(`/api/spectrum?minutes=${minutes}`),
      api(`/api/channels?minutes=${minutes}`),
    ]);
    renderSpectrum(spectrum);
    renderChannels(channels.channels);
  } catch (err) {
    $("#spectrum-host").innerHTML =
      `<div class="empty"><b>Could not draw the spectrum</b>${esc(err.message)}</div>`;
  }
}

// 6 GHz Preferred Scanning Channels. Access points that want to be found put a
// beacon here, so an empty 6 GHz band with quiet PSCs usually means nothing is
// deployed nearby rather than that the radio cannot see the band.
const PSC_CHANNELS = [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229];

function renderSpectrum(data) {
  const host = $("#spectrum-host");
  const labels = { "2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz" };
  const parts = [];

  for (const band of ["2.4", "5", "6"]) {
    const items = (data.bands[band] || []).slice().sort((a, b) => a.low_mhz - b.low_mhz);
    const [lo, hi] = data.ranges[band];
    if (!items.length) {
      const why = band === "6"
        ? "nothing detected \u2014 6 GHz access points are still uncommon, and "
          + "they are only discoverable on the preferred scanning channels"
        : "nothing detected";
      parts.push(`<div class="ribbon"><div class="ribbon-head">
        <h3 style="color:${bandColor(band)}">${labels[band]}</h3>
        <span class="meta">${why}</span></div></div>`);
      continue;
    }
    const pscCount = band === "6"
      ? items.filter(i => PSC_CHANNELS.includes(i.channel)).length : 0;
    parts.push(`<div class="ribbon">
      <div class="ribbon-head">
        <h3 style="color:${bandColor(band)}">${labels[band]}</h3>
        <span class="meta">${items.length} access point${items.length === 1 ? "" : "s"}
        &middot; ${lo}\u2013${hi} MHz${
          band === "6" && pscCount ? ` &middot; ${pscCount} on a scanning channel` : ""}</span>
      </div>
      ${ribbonSvg(band, items, lo, hi)}
    </div>`);
  }
  host.innerHTML = parts.join("");

  $$(".band-block", host).forEach(node => {
    node.addEventListener("click", () => openDrawer(node.dataset.bssid));
  });
}

function ribbonSvg(band, items, lo, hi) {
  const W = 1000, padL = 44, padR = 14, padT = 16, padB = 26;
  const plotW = W - padL - padR;
  const x = mhz => padL + ((mhz - lo) / (hi - lo)) * plotW;

  // Pack blocks into rows so nothing overlaps. A row is only reused when the
  // new block starts clear of everything already on it, INCLUDING the space
  // its label needs, which is what the previous version got wrong.
  const CHAR_W = 6.1, LABEL_PAD = 8;
  const rowEnds = [];
  const placed = items.map(item => {
    const left = x(item.low_mhz);
    const right = x(item.high_mhz);
    const label = item.hidden ? "(hidden)" : (item.ssid || item.bssid);
    // Reserve whichever is wider: the channel itself, or the text on it.
    // Cap what a label may reserve, or one long SSID pushes everything onto
    // its own row and the chart becomes hundreds of rows tall.
    const labelRoom = Math.min(label.length * CHAR_W, 190);
    const needed = Math.max(right, left + labelRoom + LABEL_PAD);
    let row = rowEnds.findIndex(end => left > end);
    if (row === -1) { rowEnds.push(needed); row = rowEnds.length - 1; }
    else rowEnds[row] = needed;
    return { item, left, right, row, label };
  });

  const rowCount = Math.max(rowEnds.length, 1);
  const ROW_H = 19;
  const plotH = rowCount * ROW_H;
  const H = plotH + padT + padB;
  const colour = bandColor(band);

  const ticks = [];
  const step = band === "2.4" ? 20 : band === "6" ? 200 : 100;
  for (let f = Math.ceil(lo / step) * step; f <= hi; f += step) {
    const fx = x(f).toFixed(1);
    ticks.push(`<line x1="${fx}" y1="${padT}" x2="${fx}" y2="${padT + plotH}"
        stroke="var(--line-soft)" stroke-width="1"/>
      <text x="${fx}" y="${H - 8}" fill="var(--dimmer)" font-size="9"
        text-anchor="middle">${f}</text>`);
  }

  const clampText = (x, textWidth) =>
    Math.max(padL + 2, Math.min(x, W - padR - textWidth - 2));

  const blocks = placed.map(({ item, left, right, row, label }) => {
    // Signal maps to opacity and to a filled portion of the block, so strength
    // stays readable now that every row is the same height.
    const strength = Math.max(0.08, Math.min(1, (item.rssi + 95) / 65));
    const y = padT + row * ROW_H;
    const h = ROW_H - 5;
    const w = Math.max(3, right - left);
    const flagged = state.flaggedBssids.has(item.bssid);
    const title = `${label}\n${item.bssid}\nch ${item.channel} \u00b7 ${item.width_mhz} MHz`
                + ` \u00b7 ${item.rssi} dBm \u00b7 ${item.security}`
                + (item.vendor ? ` \u00b7 ${item.vendor}` : "");
    // Truncate to what will actually fit, then clamp inside the plot so a
    // label can never hang off either edge.
    const inside = w > 30;
    const room = inside ? w - 8 : (W - padR) - (right + 6);
    const maxChars = Math.max(3, Math.floor(room / CHAR_W));
    const shown = label.length > maxChars
      ? label.slice(0, Math.max(1, maxChars - 1)) + "\u2026"
      : label;
    const textWidth = shown.length * CHAR_W;
    const textX = clampText(inside ? left + 4 : right + 5, textWidth);
    const textFill = inside ? "var(--text-hi)" : "var(--dim)";
    return `<g class="band-block" data-bssid="${esc(item.bssid)}">
      <title>${esc(title)}</title>
      <rect x="${left.toFixed(1)}" y="${y.toFixed(1)}" width="${w.toFixed(1)}"
        height="${h}" rx="2" fill="${colour}" fill-opacity="${(0.10 + strength * 0.30).toFixed(2)}"
        stroke="${flagged ? "var(--crit)" : colour}"
        stroke-opacity="${flagged ? 1 : (0.35 + strength * 0.5).toFixed(2)}"
        stroke-width="${flagged ? 1.5 : 1}"/>
      <rect x="${left.toFixed(1)}" y="${(y + h - 3).toFixed(1)}"
        width="${(w * strength).toFixed(1)}" height="2" rx="1" fill="${colour}"
        fill-opacity="0.9"/>
      <text x="${textX.toFixed(1)}" y="${(y + h - 5).toFixed(1)}" fill="${textFill}"
        font-size="10">${esc(shown)}</text>
    </g>`;
  }).join("");

  return `<svg viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Occupied spectrum in the ${band} gigahertz band">
    ${ticks.join("")}
    <line x1="${padL}" y1="${padT + plotH}" x2="${W - padR}" y2="${padT + plotH}"
      stroke="var(--line)" stroke-width="1"/>
    ${blocks}
  </svg>`;
}

function renderChannels(rows) {
  if (!rows.length) {
    $("#channel-rows").innerHTML =
      `<tr><td colspan="5"><div class="empty">No channel data yet.</div></td></tr>`;
    return;
  }
  $("#channel-rows").innerHTML = rows.map(r => `<tr>
    <td><span class="chip ${bandClass(r.band)}">${esc(r.band)}</span></td>
    <td class="mono">${r.channel}</td>
    <td class="right mono">${r.count}</td>
    <td class="right mono dim">${r.best_rssi ?? ""} dBm</td>
    <td class="right mono dim">${r.avg_utilization != null
      ? Math.round(r.avg_utilization) + "%" : ""}</td>
  </tr>`).join("");
}

$("#spectrum-window").addEventListener("change", loadSpectrum);

/* --------------------------------------------------------------- findings */

async function refreshFlagged() {
  // The Live table highlights flagged radios, so this set has to stay current
  // whichever view is on screen.
  try {
    const data = await api("/api/alerts?limit=500&unacked_only=true");
    state.flaggedBssids = new Set(
      data.alerts.filter(a => ["critical", "high"].includes(a.severity))
                 .map(a => a.bssid).filter(Boolean)
    );
  } catch { /* the status poll already surfaces connection problems */ }
}

async function loadFindings() {
  const params = new URLSearchParams({ limit: "300" });
  const severity = $("#findings-severity").value;
  if (severity) params.set("severity", severity);
  const rule = $("#findings-rule").value;
  if (rule) params.set("rule", rule);
  if ($("#findings-open").checked) params.set("unacked_only", "true");

  try {
    const data = await api(`/api/alerts?${params}`);
    renderFindings(data.alerts);
    state.flaggedBssids = new Set(
      data.alerts.filter(a => !a.acknowledged && ["critical", "high"].includes(a.severity))
                 .map(a => a.bssid).filter(Boolean)
    );
  } catch (err) {
    $("#findings-list").innerHTML =
      `<div class="empty"><b>Could not load findings</b>${esc(err.message)}</div>`;
  }
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function renderFindings(rows) {
  if ($("#findings-group").checked && rows.length > 12) {
    renderGroupedFindings(rows);
    return;
  }
  if (!rows.length) {
    $("#findings-list").innerHTML = `<div class="card"><div class="empty">
      <b>Nothing flagged</b>Detections run on every scan. Add your own networks under
      Marks so the impersonation rules know what to compare against.</div></div>`;
    return;
  }
  $("#findings-list").innerHTML = rows.map(a => {
    const evidence = a.evidence && typeof a.evidence === "object"
      ? Object.entries(a.evidence).map(([k, v]) =>
          `<span class="chip">${esc(k)}: ${esc(
            typeof v === "object" ? JSON.stringify(v) : v)}</span>`).join(" ")
      : "";
    return `<div class="card${a.acknowledged ? " acked" : ""}" style="padding:13px 16px">
      <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
        <span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
        <b style="color:var(--text-hi)">${esc(a.title)}</b>
        <span class="mono dim" style="margin-left:auto">${esc(a.rule)}</span>
      </div>
      <div style="color:var(--dim);font-size:13px;margin:5px 0 8px">${esc(a.detail)}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        ${a.bssid ? `<button class="btn small" data-open-bssid="${esc(a.bssid)}">${esc(a.bssid)}</button>` : ""}
        ${evidence}
        <span class="mono dim" style="margin-left:auto">
          ${new Date(a.ts * 1000).toLocaleString()}</span>
        ${a.acknowledged ? '<span class="chip">acknowledged</span>'
          : `<button class="btn small" data-ack="${a.id}">Acknowledge</button>`}
      </div>
    </div>`;
  }).join("");
}

function renderGroupedFindings(rows) {
  // A busy environment produces one finding per access point per rule, which is
  // hundreds of rows saying the same thing. Collapse by rule and let the person
  // open the ones that matter.
  const byRule = new Map();
  for (const alert of rows) {
    if (!byRule.has(alert.rule)) byRule.set(alert.rule, []);
    byRule.get(alert.rule).push(alert);
  }

  const groups = [...byRule.entries()].map(([rule, alerts]) => {
    alerts.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    return { rule, alerts, worst: alerts[0].severity, count: alerts.length };
  }).sort((a, b) =>
    SEVERITY_RANK[a.worst] - SEVERITY_RANK[b.worst] || b.count - a.count);

  $("#findings-list").innerHTML = groups.map(g => {
    const open = SEVERITY_RANK[g.worst] <= 1 ? " open" : "";
    const items = g.alerts.map(a => `<div class="finding-row" data-alert="${a.id}">
      <span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
      <span class="what">${esc(a.title)}</span>
      ${a.bssid ? `<button class="btn small" data-open-bssid="${esc(a.bssid)}"
        >${esc(a.bssid)}</button>` : ""}
      ${a.acknowledged ? '<span class="chip">ack</span>'
        : `<button class="btn small" data-ack="${a.id}">Ack</button>`}
    </div>`).join("");

    return `<details class="card finding-group"${open}>
      <summary>
        <span class="sev ${esc(g.worst)}">${esc(g.worst)}</span>
        <b>${esc(g.rule)}</b>
        <span class="mono dim">${g.count} network${g.count === 1 ? "" : "s"}</span>
        <span class="spacer"></span>
        <span class="dim" style="font-size:12.5px">${esc(g.alerts[0].detail.slice(0, 90))}${
          g.alerts[0].detail.length > 90 ? "\u2026" : ""}</span>
        <button class="btn small" data-ack-rule="${esc(g.rule)}">Ack all</button>
      </summary>
      <div class="finding-rows">${items}</div>
    </details>`;
  }).join("");
}

$("#findings-list").addEventListener("click", async e => {
  const ackRule = e.target.closest("[data-ack-rule]");
  if (ackRule) {
    e.preventDefault();
    e.stopPropagation();
    const rule = ackRule.dataset.ackRule;
    const ids = [...document.querySelectorAll(`[data-ack]`)]
      .filter(b => b.closest("details")?.querySelector("b")?.textContent === rule)
      .map(b => Number(b.dataset.ack));
    if (!ids.length) return;
    try {
      await api("/api/alerts/ack", { method: "POST", body: JSON.stringify({ ids }) });
      toast(`Acknowledged ${ids.length} ${rule} finding(s)`, "ok");
      loadFindings(); refreshStatus();
    } catch (err) { toast(err.message, "err"); }
    return;
  }
  const ack = e.target.closest("[data-ack]");
  if (ack) {
    try {
      await api("/api/alerts/ack", { method: "POST",
        body: JSON.stringify({ ids: [Number(ack.dataset.ack)] }) });
      loadFindings(); refreshStatus();
    } catch (err) { toast(err.message, "err"); }
    return;
  }
  const open = e.target.closest("[data-open-bssid]");
  if (open) openDrawer(open.dataset.openBssid);
});

$("#btn-ack-all").addEventListener("click", async () => {
  if (!confirm("Acknowledge every open finding?")) return;
  try {
    const result = await api("/api/alerts/ack", { method: "POST", body: "{}" });
    toast(`Acknowledged ${result.acknowledged}`, "ok");
    loadFindings(); refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-unack-all").addEventListener("click", async () => {
  const rule = $("#findings-rule").value;
  const what = rule ? `every '${rule}' finding` : "every acknowledged finding";
  if (!confirm(`Reopen ${what}? They go back in the open list.`)) return;
  try {
    const result = await api("/api/alerts/unack", { method: "POST",
      body: JSON.stringify(rule ? { rule } : {}) });
    toast(`Reopened ${result.reopened} finding(s)`, "ok");
    loadFindings(); refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-clear-findings").addEventListener("click", async () => {
  const rule = $("#findings-rule").value;
  const choice = prompt(
    "What should be cleared?\n\n"
    + "  1  acknowledged findings only (default)\n"
    + "  2  everything, including open findings\n"
    + (rule ? `  3  every '${rule}' finding\n` : "")
    + "  4  anything older than 30 days\n\n"
    + "Deleting also clears the cooldown, so anything still true is reported "
    + "again on the next scan.",
    "1"
  );
  if (choice === null) return;
  const scope = { "1": "acknowledged", "2": "all", "3": "rule", "4": "older" }[choice.trim()];
  if (!scope) { toast("Nothing cleared", ""); return; }
  if (scope === "all" && !confirm("Delete every finding, open ones included?")) return;
  try {
    const result = await api("/api/alerts/clear", { method: "POST",
      body: JSON.stringify({ scope, rule, days: 30 }) });
    toast(`Cleared ${result.removed} finding(s)`, "ok");
    loadFindings(); refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

["#findings-severity", "#findings-rule", "#findings-open", "#findings-group"]
  .forEach(sel => $(sel).addEventListener("change", loadFindings));

/* ------------------------------------------------------------------ ssids */

async function loadSsids() {
  const params = new URLSearchParams({ limit: "500" });
  const minutes = $("#group-window").value;
  if (minutes) params.set("minutes", minutes);
  const search = $("#group-search").value.trim();
  if (search) params.set("search", search);
  const band = $("#group-band").value;
  if (band) params.set("band", band);

  try {
    const data = await api(`/api/networks/grouped?${params}`);
    let groups = data.groups;
    if ($("#group-multiband").checked) groups = groups.filter(g => g.band_count > 1);

    $("#group-count").textContent =
      `${groups.length} network${groups.length === 1 ? "" : "s"} across `
      + `${data.radio_total} radios \u00b7 ${data.multi_band} multi-band`
      + (data.tri_band ? `, ${data.tri_band} tri-band` : "");

    if (!groups.length) {
      $("#group-list").innerHTML = `<div class="card"><div class="empty">
        <b>Nothing matches</b>Widen the time window or clear the filter.</div></div>`;
      return;
    }
    $("#group-list").innerHTML = groups.map(groupCard).join("");
  } catch (err) {
    $("#group-list").innerHTML =
      `<div class="card"><div class="empty"><b>Could not load networks</b>${esc(err.message)}</div></div>`;
  }
}

function groupCard(g) {
  const name = g.hidden || !g.ssid
    ? '<span class="dim">(hidden network)</span>' : esc(g.ssid);

  const bands = g.bands.map(b =>
    `<span class="chip ${bandClass(b)}">${esc(b)} GHz</span>`).join(" ");

  const flags = [];
  if (g.tri_band) flags.push('<span class="tag good">tri-band</span>');
  else if (g.band_count > 1) flags.push('<span class="tag">dual-band</span>');
  if (g.mixed_security) flags.push('<span class="tag bad">mixed security</span>');
  if (g.enterprise) flags.push('<span class="tag">802.1X</span>');
  if (g.wps) flags.push('<span class="tag warn">WPS</span>');
  if (!g.mfp_required && !g.securities.includes("Open")) {
    flags.push('<span class="tag warn">PMF optional</span>');
  }

  const radios = g.radios.slice().sort((a, b) => {
    const order = { "2.4": 0, "5": 1, "6": 2 };
    return (order[a.band] ?? 9) - (order[b.band] ?? 9) || b.rssi - a.rssi;
  }).map(r => `<tr data-bssid="${esc(r.bssid)}">
    <td><span class="chip ${bandClass(r.band)}">${esc(r.band || "?")}</span></td>
    <td class="mono">${r.channel ?? "?"}<span class="dim"> / ${r.width_mhz || 20}</span></td>
    <td class="mono">
      <i class="bar ${bandClass(r.band)}" style="width:${signalWidth(r.rssi)}px"></i>${r.rssi}
    </td>
    <td>${esc(r.security || "")}</td>
    <td class="dim">${esc(r.phy || "")}</td>
    <td class="mono dim">${esc(r.bssid)}</td>
    <td class="dim">${esc(r.vendor || "")}</td>
  </tr>`).join("");

  return `<div class="card group">
    <div class="group-head">
      <b>${name}</b>
      ${bands}
      ${flags.join(" ")}
      <span class="spacer"></span>
      <span class="mono dim">${g.radio_count} radio${g.radio_count === 1 ? "" : "s"}
        \u00b7 best ${g.best_rssi} dBm</span>
    </div>
    <div class="table-wrap" style="margin-top:10px">
      <table><thead><tr>
        <th>Band</th><th>Ch / width</th><th>Signal</th><th>Security</th>
        <th>PHY</th><th>BSSID</th><th>Vendor</th>
      </tr></thead><tbody>${radios}</tbody></table>
    </div>
  </div>`;
}

$("#group-list").addEventListener("click", e => {
  const row = e.target.closest("tr[data-bssid]");
  if (row) openDrawer(row.dataset.bssid);
});
$("#group-search").addEventListener("input", debounce(loadSsids, 250));
["#group-band", "#group-window", "#group-multiband"].forEach(
  sel => $(sel).addEventListener("change", loadSsids)
);

/* ------------------------------------------------------------------ marks */

async function loadMarks() {
  try {
    const data = await api("/api/marks");
    state.marks = data.marks;
    state.watchedBssids = new Set(
      data.marks.filter(m => m.kind === "watch" && m.match_type === "bssid").map(m => m.value)
    );
    renderMarks();
  } catch (err) {
    $("#mark-rows").innerHTML = errorRow(5, err.message);
  }
}

function renderMarks() {
  if (!state.marks.length) {
    $("#mark-rows").innerHTML = `<tr><td colspan="5"><div class="empty">
      <b>No marks yet</b>Start by adding your own network names as trusted.</div></td></tr>`;
    return;
  }
  const labels = { watch: "Watch", trusted: "Trusted", ignore: "Ignore" };
  const types = { bssid: "BSSID", oui: "Vendor", ssid: "Name", ssid_prefix: "Name starts with" };
  $("#mark-rows").innerHTML = state.marks.map(m => `<tr>
    <td>${esc(labels[m.kind] || m.kind)}</td>
    <td class="dim">${esc(types[m.match_type] || m.match_type)}</td>
    <td class="mono">${esc(m.value)}</td>
    <td class="dim">${esc(m.label || "")}</td>
    <td class="right"><button class="btn small danger" data-del-mark="${m.id}">Remove</button></td>
  </tr>`).join("");
}

$("#mark-rows").addEventListener("click", async e => {
  const button = e.target.closest("[data-del-mark]");
  if (!button) return;
  try {
    await api(`/api/marks/${button.dataset.delMark}`, { method: "DELETE" });
    toast("Mark removed", "ok");
    loadMarks();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-add-mark").addEventListener("click", async () => {
  const value = $("#mark-value").value.trim();
  if (!value) { toast("Enter a value to match on", "err"); return; }
  try {
    await api("/api/marks", { method: "POST", body: JSON.stringify({
      kind: $("#mark-kind").value,
      match_type: $("#mark-type").value,
      value,
      label: $("#mark-label").value.trim() || null,
    })});
    $("#mark-value").value = ""; $("#mark-label").value = "";
    toast("Mark added", "ok");
    loadMarks();
  } catch (err) { toast(err.message, "err"); }
});

/* ---------------------------------------------------------------- history */

async function loadHistory() {
  try {
    const [scans, exports] = await Promise.all([
      api("/api/scans?limit=100"),
      api("/api/export"),
    ]);
    const rows = scans.scans;
    $("#scan-rows").innerHTML = rows.length ? rows.map(s => `<tr>
      <td class="mono dim">${new Date(s.started_at * 1000).toLocaleTimeString()}</td>
      <td class="right mono">${s.bss_count ?? 0}</td>
      <td class="right mono">${s.new_bss_count ?? 0}</td>
      <td class="right mono">${s.alert_count ?? 0}</td>
      <td class="right mono dim">${s.duration_ms ?? "?"} ms</td>
      <td>${s.status === "ok" ? '<span class="dim">ok</span>'
            : `<span class="sev high">${esc(s.error || s.status)}</span>`}</td>
    </tr>`).join("") : `<tr><td colspan="6"><div class="empty">No scans recorded yet.</div></td></tr>`;

    $("#export-links").innerHTML = exports.available.map(name =>
      `<a class="btn small" href="/api/export/${encodeURIComponent(name)}${
        state.token ? `?token=${encodeURIComponent(state.token)}` : ""}">${esc(name)}</a>`
    ).join("");
  } catch (err) {
    $("#scan-rows").innerHTML = errorRow(6, err.message);
  }
}

/* ------------------------------------------------------------ diagnostics */

async function loadDiagnostics() {
  $("#diag-list").innerHTML = '<div class="empty">Running checks\u2026</div>';
  try {
    const report = await api("/api/diagnostics");
    $("#diag-list").innerHTML = report.checks.map(c => `<div class="check">
      <span class="badge ${esc(c.status)}">${esc(c.status)}</span>
      <div class="what">
        <b>${esc(c.name)}</b>
        <span>${esc(c.message)}</span>
        ${c.fix ? `<span class="fix">${esc(c.fix)}</span>` : ""}
      </div>
    </div>`).join("");
  } catch (err) {
    $("#diag-list").innerHTML = `<div class="empty"><b>Diagnostics failed</b>${esc(err.message)}</div>`;
  }

  loadBackups();

  try {
    const text = await fetch("/api/logs?lines=200" +
      (state.token ? `&token=${encodeURIComponent(state.token)}` : "")).then(r => r.text());
    $("#log-tail").textContent = text;
    $("#log-tail").scrollTop = $("#log-tail").scrollHeight;
  } catch { /* non-fatal */ }
}

$("#btn-diag-refresh").addEventListener("click", loadDiagnostics);

/* ------------------------------------------------------------ self update */

async function inspectPackage(file) {
  const info = $("#package-info");
  info.innerHTML = '<div class="empty">Checking the package\u2026</div>';
  try {
    const headers = state.token ? { "X-Api-Token": state.token } : {};
    const response = await fetch("/api/updates/package?inspect=true",
      { method: "POST", body: file, headers });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "That package was rejected");

    info.innerHTML = `<div class="package">
      <div class="row"><span>Version in package</span><b>${esc(data.version)}</b></div>
      <div class="row"><span>Currently installed</span><b>${esc(data.current)}</b></div>
      <div class="row"><span>Files</span><b>${data.file_count}</b></div>
      <div class="row"><span>SHA-256</span><b class="mono"
        style="font-size:10.5px">${esc(data.sha256.slice(0, 32))}\u2026</b></div>
      ${data.same_version ? `<div class="warn-note">This package is the same version
        you already have. Installing it will simply replace the files.</div>` : ""}
      <button class="btn primary" id="btn-install-package" style="margin-top:10px">
        Install ${esc(data.version)}</button>
    </div>`;

    $("#btn-install-package").addEventListener("click", () => applyPackage(file, data));
  } catch (err) {
    info.innerHTML = `<div class="empty"><b>That package cannot be used</b>${
      esc(err.message)}</div>`;
  }
}

async function applyPackage(file, meta) {
  if (!confirm(`Install version ${meta.version}? The current version is backed up `
             + "first and the app restarts itself.")) return;
  const info = $("#package-info");
  info.innerHTML = '<div class="empty">Installing\u2026 do not close this window.</div>';
  clearInterval(state.timers.status);
  try {
    const headers = state.token ? { "X-Api-Token": state.token } : {};
    const response = await fetch("/api/updates/package",
      { method: "POST", body: file, headers });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.detail || "The update failed");

    info.innerHTML = `<div class="empty"><b>${esc(data.message)}</b>
      Waiting for it to come back\u2026</div>`;
    let tries = 0;
    const poll = setInterval(async () => {
      tries += 1;
      try {
        await api("/api/health");
        clearInterval(poll);
        location.reload();
      } catch {
        if (tries > 40) {
          clearInterval(poll);
          info.innerHTML = `<div class="empty"><b>It did not come back on its own</b>
            Start wifirecon again from the Start Menu. The update was applied and the
            previous version is backed up as ${esc(data.backup || "")}.</div>`;
        }
      }
    }, 2000);
  } catch (err) {
    info.innerHTML = `<div class="empty"><b>Update failed</b>${esc(err.message)}
      <br><span class="dim">Nothing was changed.</span></div>`;
    startPolling();
  }
}

const dropzone = $("#dropzone");
if (dropzone) {
  ["dragenter", "dragover"].forEach(event =>
    dropzone.addEventListener(event, e => {
      e.preventDefault(); dropzone.classList.add("over");
    }));
  ["dragleave", "drop"].forEach(event =>
    dropzone.addEventListener(event, e => {
      e.preventDefault(); dropzone.classList.remove("over");
    }));
  dropzone.addEventListener("drop", e => {
    const file = e.dataTransfer.files[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      toast("That is not a zip file", "err"); return;
    }
    inspectPackage(file);
  });
  $("#btn-browse").addEventListener("click", () => $("#package-file").click());
  $("#package-file").addEventListener("change", e => {
    if (e.target.files[0]) inspectPackage(e.target.files[0]);
  });
}

$("#btn-backup").addEventListener("click", async () => {
  try {
    const result = await api("/api/updates/backups", { method: "POST",
      body: JSON.stringify({ label: "manual" }) });
    if (!result.ok) throw new Error(result.error || "Backup failed");
    toast(`Backed up as ${result.name}`, "ok");
    loadBackups();
  } catch (err) { toast(err.message, "err"); }
});

async function loadBackups() {
  try {
    const data = await api("/api/updates/backups");
    const select = $("#backup-select");
    select.innerHTML = '<option value="">Previous versions\u2026</option>'
      + data.backups.map(b => `<option value="${esc(b.name)}">${esc(b.name)}</option>`).join("");
    $("#btn-rollback").disabled = !data.backups.length;
  } catch { /* non-fatal */ }
}

$("#backup-select").addEventListener("change", e => {
  $("#btn-rollback").disabled = !e.target.value;
});

$("#btn-rollback").addEventListener("click", async () => {
  const name = $("#backup-select").value;
  if (!name) return;
  if (!confirm(`Roll back to ${name}? The app restarts afterwards.`)) return;
  try {
    const result = await api("/api/updates/rollback", { method: "POST",
      body: JSON.stringify({ name }) });
    toast(result.message, "ok", "Rolled back");
    setTimeout(() => location.reload(), 6000);
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-check-updates").addEventListener("click", async () => {
  toast("Checking\u2026");
  try {
    const result = await api("/api/updates?force=true");
    if (result.error) { toast(result.error, "err"); return; }
    if (result.available) {
      state.updateAvailable = true;
      $("#btn-apply-update").hidden = false;
      const subjects = (result.changelog || []).slice(0, 3)
        .map(c => c.subject).join("; ");
      toast(`${result.behind} update(s) waiting. ${subjects}`, "", "Update available");
    } else {
      toast(`Version ${result.current} is current`, "ok");
    }
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-apply-update").addEventListener("click", async () => {
  if (!confirm("Download and install the update, then restart?")) return;
  $("#btn-apply-update").disabled = true;
  toast("Downloading\u2026", "", "Update");

  // Poll progress while the download runs.
  const progress = setInterval(async () => {
    try {
      const info = await api("/api/updates");
      if (info.progress != null && info.progress < 100) {
        $("#btn-apply-update").textContent = `Downloading ${Math.round(info.progress)}%`;
      }
    } catch { /* the app may already be restarting */ }
  }, 1200);

  try {
    const result = await api("/api/updates/apply", { method: "POST" });
    clearInterval(progress);
    $("#btn-apply-update").textContent = "Install update";
    toast(result.message, "ok", "Updated");
    if (result.verification) toast(result.verification, "ok");
    if (result.restarting) {
      let tries = 0;
      const waitForRestart = setInterval(async () => {
        tries += 1;
        try {
          await api("/api/health");
          clearInterval(waitForRestart);
          location.reload();
        } catch {
          if (tries > 30) {
            clearInterval(waitForRestart);
            toast("The app did not come back on its own. Start it from the Start Menu.",
                  "err");
          }
        }
      }, 2000);
    }
  } catch (err) {
    clearInterval(progress);
    $("#btn-apply-update").textContent = "Install update";
    toast(err.message, "err");
  } finally {
    $("#btn-apply-update").disabled = false;
  }
});

$("#btn-prune").addEventListener("click", async () => {
  try {
    const result = await api("/api/maintenance/prune", { method: "POST" });
    const total = Object.values(result.removed).reduce((a, b) => a + b, 0);
    toast(`Removed ${total} old rows`, "ok");
    refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-compact").addEventListener("click", async () => {
  toast("Compacting\u2026");
  try {
    const result = await api("/api/maintenance/compact", { method: "POST" });
    toast(`Reclaimed ${bytes(result.reclaimed_bytes)}`, "ok");
    refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------------------------------------------ drawer */

async function openDrawer(bssid) {
  $("#drawer").classList.add("open");
  $("#drawer-back").classList.add("open");
  $("#drawer-title").textContent = bssid;
  $("#drawer-sub").textContent = "";
  $("#drawer-body").innerHTML = '<div class="empty">Loading\u2026</div>';

  try {
    const [detail, history] = await Promise.all([
      api(`/api/networks/${encodeURIComponent(bssid)}`),
      api(`/api/networks/${encodeURIComponent(bssid)}/history?limit=300`),
    ]);
    renderDrawer(detail, history.history);
  } catch (err) {
    $("#drawer-body").innerHTML =
      `<div class="empty"><b>Could not load this access point</b>${esc(err.message)}</div>`;
  }
}

function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer-back").classList.remove("open");
}

$("#drawer-close").addEventListener("click", closeDrawer);
$("#drawer-back").addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

function renderDrawer(d, history) {
  $("#drawer-title").textContent = d.hidden ? "(hidden network)" : (d.ssid || "(no name)");
  $("#drawer-sub").textContent = `${d.bssid} · ${d.vendor || "unknown vendor"}`;

  const ie = (d.detail && d.detail.ie) || {};
  const wps = ie.wps || {};
  const rows = [
    ["Security", `${d.security}${d.enterprise ? " (802.1X)" : ""}`],
    ["Key agreement", (d.akms || []).join(", ") || "\u2014"],
    ["Ciphers", (d.ciphers || []).join(", ") || "\u2014"],
    ["Frame protection", d.mfp_required ? "required" : d.mfp_capable ? "optional" : "not offered"],
    ["Band / channel", `${d.band || "?"} GHz, channel ${d.channel ?? "?"}, ${d.width_mhz || 20} MHz`],
    ["Frequency", d.freq_khz ? `${(d.freq_khz / 1000).toFixed(1)} MHz` : "\u2014"],
    ["Generation", d.phy || "\u2014"],
    ["Signal", `${d.rssi} dBm (best ${d.rssi_max}, worst ${d.rssi_min})`],
    ["Beacon interval", d.beacon_period ? `${d.beacon_period} TU` : "\u2014"],
    ["Regulatory", d.country || "\u2014"],
    ["Load", d.utilization_pct != null
      ? `${Math.round(d.utilization_pct)}% busy, ${d.station_count ?? "?"} clients` : "\u2014"],
    ["Roaming", [ie.ft_80211r && "802.11r", ie.rm_80211k && "802.11k",
                 ie.bss_transition_80211v && "802.11v"].filter(Boolean).join(", ") || "none"],
    ["WPS", d.wps ? `${d.wps_state || "on"}${
      (wps.config_methods || []).length ? ` (${wps.config_methods.join(", ")})` : ""}` : "off"],
    ["Hardware", [wps.manufacturer, wps.model_name, wps.device_name]
      .filter(Boolean).join(" \u00b7 ") || "\u2014"],
    ["MAC type", d.randomized_mac ? "locally administered" : "vendor assigned"],
    ["Beacon fingerprint", d.ie_fingerprint || "\u2014"],
    ["First seen", d.first_seen ? new Date(d.first_seen * 1000).toLocaleString() : "\u2014"],
    ["Times seen", d.times_seen],
  ];

  $("#drawer-body").innerHTML = `
    <p class="eyebrow">Signal over time</p>
    ${sparkline(history)}
    <p class="eyebrow" style="margin-top:20px">Details</p>
    <dl class="kv">${rows.map(([k, v]) =>
      `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
    <p class="eyebrow" style="margin-top:20px">Notes</p>
    <textarea id="drawer-note" rows="3" style="width:100%">${esc(d.notes || "")}</textarea>
    <div class="toolbar" style="margin-top:10px">
      <button class="btn small" id="drawer-save-note">Save note</button>
      <button class="btn small" data-mark-kind="trusted">Mark trusted</button>
      <button class="btn small" data-mark-kind="watch">Watch this</button>
      <button class="btn small" data-mark-kind="ignore">Ignore</button>
      <button class="btn small" id="drawer-inventory">Add to inventory</button>
    </div>`;

  $("#drawer-inventory").addEventListener("click", async () => {
    const label = prompt("Label for this access point", d.ssid || d.bssid);
    if (label === null) return;
    const location = prompt("Where is it? (optional)", "") || "";
    try {
      await api(`/api/inventory/${encodeURIComponent(d.bssid)}`, { method: "POST",
        body: JSON.stringify({ label, location, managed: true,
                               site_id: state.activeSite }) });
      toast("Added to inventory", "ok");
    } catch (err) { toast(err.message, "err"); }
  });

  $("#drawer-save-note").addEventListener("click", async () => {
    try {
      await api(`/api/networks/${encodeURIComponent(d.bssid)}/note`, {
        method: "POST", body: JSON.stringify({ note: $("#drawer-note").value }) });
      toast("Note saved", "ok");
    } catch (err) { toast(err.message, "err"); }
  });

  $$("[data-mark-kind]", $("#drawer-body")).forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await api("/api/marks", { method: "POST", body: JSON.stringify({
          kind: button.dataset.markKind, match_type: "bssid",
          value: d.bssid, label: d.ssid || null }) });
        toast(`Marked as ${button.dataset.markKind}`, "ok");
        loadMarks();
      } catch (err) { toast(err.message, "err"); }
    });
  });
}

function sparkline(history) {
  const points = history.filter(h => h.rssi != null).slice().reverse();
  if (points.length < 2) {
    return '<div class="empty" style="padding:18px">Not enough history yet.</div>';
  }
  const W = 520, H = 74, pad = 6;
  const values = points.map(p => p.rssi);
  const min = Math.min(-95, ...values), max = Math.max(-30, ...values);
  const span = Math.max(1, max - min);
  const path = points.map((p, i) => {
    const x = pad + (i / (points.length - 1)) * (W - pad * 2);
    const y = pad + (1 - (p.rssi - min) / span) * (H - pad * 2);
    return `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join("");
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <path d="${path}" fill="none" stroke="var(--b5)" stroke-width="1.4"/>
    <text x="4" y="11" fill="var(--dimmer)" font-size="9" font-family="var(--mono)">${max} dBm</text>
    <text x="4" y="${H - 4}" fill="var(--dimmer)" font-size="9" font-family="var(--mono)">${min} dBm</text>
  </svg>`;
}

/* ---------------------------------------------------------------- settings */

async function loadSettings() {
  try {
    const settings = await api("/api/settings");
    state.settings = settings;
    const set = (sel, value) => { const el = $(sel); if (el) el.value = value ?? ""; };
    const check = (sel, value) => { const el = $(sel); if (el) el.checked = !!value; };

    set("#set-interval", settings.scan.interval_seconds);
    set("#set-settle", settings.scan.settle_seconds);
    check("#set-autostart-scan", settings.scan.autostart_on_launch);

    check("#set-det-enabled", settings.detections.enabled);
    set("#set-lev", settings.detections.levenshtein_threshold);
    set("#set-rssi-jump", settings.detections.rssi_jump_db);
    set("#set-suppress", settings.detections.suppress_seconds);
    set("#set-floor", settings.detections.severity_floor);

    check("#set-toast", settings.alerts.toast.enabled);
    check("#set-webhook", settings.alerts.webhook.enabled);
    set("#set-webhook-url", settings.alerts.webhook.url);
    check("#set-syslog", settings.alerts.syslog.enabled);
    set("#set-syslog-host", settings.alerts.syslog.host);
    set("#set-syslog-port", settings.alerts.syslog.port);
    set("#set-syslog-proto", settings.alerts.syslog.protocol);
    set("#set-syslog-format", settings.alerts.syslog.format);

    check("#set-gps", settings.gps.enabled);
    set("#set-gps-baud", settings.gps.baud);

    set("#set-obs-days", settings.retention.observation_days);
    set("#set-alert-days", settings.retention.alert_days);
    set("#set-max-db", settings.retention.max_db_mb);

    set("#set-port", settings.server.port);
    check("#set-lan", settings.server.allow_lan);
    check("#set-update-check", settings.updates.check_on_start);
    set("#set-theme", settings.ui.theme || "dark");
    check("#set-native-window", settings.ui.native_window !== false);
    applyTheme(settings.ui.theme || "dark");
    set("#set-channel", settings.updates.channel);

    const gps = await api("/api/gps");
    const select = $("#set-gps-port");
    const ports = gps.ports || [];
    select.innerHTML = ports.length
      ? ports.map(p => `<option value="${esc(p.device)}"${
          p.device === settings.gps.port ? " selected" : ""}>${esc(p.device)} \u2014
          ${esc(p.description)}</option>`).join("")
      : '<option value="">No serial ports detected</option>';
    const status = gps.status;
    $("#gps-status").textContent = !status.available
      ? "pyserial is not installed, so GPS is unavailable"
      : status.fix ? `fix: ${status.fix.lat}, ${status.fix.lon}`
      : status.running ? `reading ${status.port}, waiting for a fix`
      : status.error || "not running";

    await loadInstallCard();

    const rules = await api("/api/alerts/rules");
    $("#findings-rule").innerHTML = '<option value="">All rules</option>' +
      rules.rules.map(r => `<option value="${esc(r)}">${esc(r)}</option>`).join("");
  } catch (err) {
    toast(err.message, "err");
  }
}

async function loadInstallCard() {
  try {
    const info = await api("/api/install");
    const card = $("#install-card");
    if (!info.frozen) { card.hidden = true; return; }
    card.hidden = false;
    state.install = info;

    $("#set-autostart").checked = !!info.autostart;
    $("#install-where").textContent = info.installed && info.registered
      ? `Version ${info.version}, installed at ${info.install_dir} and listed in Apps & features.`
      : info.installed
        ? `Installed at ${info.install_dir}, but not listed in Apps & features yet.`
        : `Running portably from ${info.install_dir}. That works, but installing adds a `
          + `Start Menu entry and a normal uninstall.`;
    $("#btn-install").hidden = info.installed && info.registered;
    $("#install-note").textContent = `Settings and captured data live in ${info.data_dir}`;
  } catch {
    $("#install-card").hidden = true;
  }
}

$("#set-autostart").addEventListener("change", async e => {
  try {
    const result = await api("/api/install/autostart", { method: "POST",
      body: JSON.stringify({ enabled: e.target.checked }) });
    toast(result.autostart ? "Will start when you sign in" : "Autostart turned off", "ok");
  } catch (err) {
    toast(err.message, "err");
    e.target.checked = !e.target.checked;
  }
});

$("#btn-install").addEventListener("click", async () => {
  toast("Run the executable with --install from a prompt to complete this.", "",
        "One step needed");
});

$("#btn-uninstall").addEventListener("click", async () => {
  const keep = confirm(
    "Remove wifirecon.\n\nOK  = keep the database and settings\n" +
    "Cancel = continue to a full removal"
  );
  const phrase = prompt(
    keep
      ? "This removes the app but keeps your data.\n\nType UNINSTALL to confirm."
      : "This removes the app AND every network, finding and setting it has stored."
        + "\n\nType UNINSTALL to confirm."
  );
  if (phrase !== "UNINSTALL") { toast("Cancelled. Nothing was removed."); return; }
  try {
    const result = await api("/api/install/uninstall", { method: "POST",
      body: JSON.stringify({ confirm: "uninstall", keep_data: keep }) });
    clearInterval(state.timers.status);
    document.body.innerHTML =
      '<div style="padding:60px;font-family:var(--ui);color:var(--text);max-width:640px">'
      + '<h1 style="font-size:20px">wifirecon has been removed</h1>'
      + '<p style="color:var(--dim)">' + esc(result.steps.join(". ")) + '.</p>'
      + '<p style="color:var(--dim)">You can close this tab.</p></div>';
  } catch (err) { toast(err.message, "err"); }
});

function num(sel, fallback) {
  const value = Number($(sel).value);
  return Number.isFinite(value) ? value : fallback;
}

$("#btn-save-settings").addEventListener("click", async () => {
  const patch = {
    scan: {
      interval_seconds: num("#set-interval", 20),
      settle_seconds: num("#set-settle", 4),
      autostart_on_launch: $("#set-autostart-scan").checked,
    },
    detections: {
      enabled: $("#set-det-enabled").checked,
      levenshtein_threshold: num("#set-lev", 2),
      rssi_jump_db: num("#set-rssi-jump", 25),
      suppress_seconds: num("#set-suppress", 900),
      severity_floor: $("#set-floor").value,
    },
    alerts: {
      toast: { enabled: $("#set-toast").checked },
      webhook: { enabled: $("#set-webhook").checked, url: $("#set-webhook-url").value.trim() },
      syslog: {
        enabled: $("#set-syslog").checked,
        host: $("#set-syslog-host").value.trim(),
        port: num("#set-syslog-port", 514),
        protocol: $("#set-syslog-proto").value,
        format: $("#set-syslog-format").value,
      },
    },
    gps: {
      enabled: $("#set-gps").checked,
      port: $("#set-gps-port").value,
      baud: num("#set-gps-baud", 4800),
    },
    retention: {
      observation_days: num("#set-obs-days", 30),
      alert_days: num("#set-alert-days", 90),
      max_db_mb: num("#set-max-db", 2048),
    },
    server: { port: num("#set-port", 8722), allow_lan: $("#set-lan").checked },
    updates: { check_on_start: $("#set-update-check").checked,
               channel: $("#set-channel").value.trim() || "main" },
    ui: { theme: $("#set-theme").value,
          native_window: $("#set-native-window").checked },
  };
  try {
    const result = await api("/api/settings", { method: "PUT", body: JSON.stringify(patch) });
    $("#settings-status").textContent = "Saved " + new Date().toLocaleTimeString();
    toast(result.note || "Settings saved", "ok");
    refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#set-theme").addEventListener("change", e => applyTheme(e.target.value));

$("#btn-clear-networks").addEventListener("click", async () => {
  if (!confirm("Forget every network, finding and scan?\n\nYour marks, sites, "
             + "surveys and AP inventory are kept. This cannot be undone.")) return;
  try {
    const result = await api("/api/maintenance/clear-networks", { method: "POST",
      body: JSON.stringify({ confirm: "clear" }) });
    $("#data-status").textContent = result.message;
    toast(result.message, "ok");
    state.networks = []; state.recentCount = 0;
    refreshStatus();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-compact-db").addEventListener("click", async () => {
  $("#data-status").textContent = "Compacting\u2026";
  try {
    const result = await api("/api/maintenance/compact", { method: "POST",
      timeout: 120000 });
    $("#data-status").textContent =
      `Reclaimed ${bytes(result.reclaimed_bytes)} (now ${bytes(result.after_bytes)}).`;
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-wipe").addEventListener("click", async () => {
  const phrase = prompt(
    "This deletes EVERYTHING: networks, findings, marks, sites, survey points, "
    + "AP inventory, snapshots and discovered devices.\n\n"
    + "Settings are kept unless you say otherwise.\n\n"
    + "Type WIPE EVERYTHING to confirm."
  );
  if (phrase !== "WIPE EVERYTHING") { toast("Cancelled. Nothing was deleted."); return; }
  const alsoSettings = confirm("Also reset settings to defaults?\n\n"
    + "OK = reset settings too\nCancel = keep settings");
  try {
    const result = await api("/api/maintenance/wipe", { method: "POST",
      body: JSON.stringify({ confirm: "WIPE EVERYTHING",
                             reset_settings: alsoSettings, compact: true }),
      timeout: 120000 });
    toast(result.message, "ok", "Wiped");
    setTimeout(() => location.reload(), 1500);
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-reset-settings").addEventListener("click", async () => {
  if (!confirm("Put every setting back to its default?")) return;
  try {
    await api("/api/settings/reset", { method: "POST" });
    toast("Settings reset", "ok");
    loadSettings();
  } catch (err) { toast(err.message, "err"); }
});

document.addEventListener("click", async e => {
  const button = e.target.closest("[data-test-sink]");
  if (!button) return;
  const sink = button.dataset.testSink;
  toast(`Testing ${sink}\u2026`);
  try {
    const result = await api(`/api/alerts/test/${sink}`, { method: "POST" });
    toast(result.message || "Sent", "ok");
  } catch (err) { toast(err.message, "err"); }
});

/* ----------------------------------------------------------------- devices */

const CATEGORY_ICON = {
  printer: "PRN", media: "MED", tv: "TV", speaker: "SPK", storage: "NAS",
  network: "NET", camera: "CAM", iot: "IOT", mobile: "PHN", computer: "PC",
  console: "GAME", bluetooth: "BT", unknown: "?",
};

async function loadDevicesView() {
  try {
    const data = await api("/api/devices");
    state.devices = data.devices;
    renderDevices();
  } catch (err) {
    $("#device-rows").innerHTML = errorRow(8, err.message);
  }
}

function renderDevices() {
  const search = $("#device-search").value.trim().toLowerCase();
  const category = $("#device-category").value;
  let rows = state.devices || [];

  const categories = [...new Set(rows.map(d => d.category).filter(Boolean))].sort();
  const select = $("#device-category");
  if (select.options.length - 1 !== categories.length) {
    select.innerHTML = '<option value="">All types</option>'
      + categories.map(c => `<option value="${esc(c)}"${
          c === category ? " selected" : ""}>${esc(c)}</option>`).join("");
  }

  if (search) {
    rows = rows.filter(d =>
      [d.label, d.hostname, d.ip, d.mac, d.vendor].some(
        v => (v || "").toLowerCase().includes(search)));
  }
  if (category) rows = rows.filter(d => d.category === category);

  $("#device-count").textContent =
    `${rows.length} of ${(state.devices || []).length} device${
      (state.devices || []).length === 1 ? "" : "s"}`;
  $("#nav-devices").textContent = (state.devices || []).length || "";

  if (!rows.length) {
    $("#device-rows").innerHTML = `<tr><td colspan="8"><div class="empty">
      <b>Nothing discovered yet</b>Press Discover devices. It takes a few seconds
      and only listens for things that announce themselves.</div></td></tr>`;
    return;
  }

  const now = Date.now() / 1000;
  $("#device-rows").innerHTML = rows.map(d => {
    const detail = d.detail || {};
    const sources = (detail.sources || []).join(", ");
    return `<tr>
      <td><b>${esc(d.label || d.ip)}</b>${d.hostname && d.hostname !== d.label
        ? `<span class="dim"> ${esc(d.hostname)}</span>` : ""}</td>
      <td><span class="tag">${esc(CATEGORY_ICON[d.category] || "?")}</span>
        <span class="dim">${esc(detail.category_label || d.category || "")}</span></td>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono dim">${esc(d.mac || "")}${detail.randomized_mac
        ? ' <span class="tag warn">random</span>' : ""}</td>
      <td class="dim">${esc(d.vendor || "")}</td>
      <td class="mono dim" style="font-size:11px">${esc(sources)}</td>
      <td class="right mono">${d.times_seen ?? 1}</td>
      <td class="right mono dim">${ago(now - (d.last_seen || 0))}</td>
    </tr>`;
  }).join("");
}

$("#device-search").addEventListener("input", debounce(renderDevices, 200));
$("#device-category").addEventListener("change", renderDevices);

$("#btn-discover").addEventListener("click", async () => {
  const button = $("#btn-discover");
  button.disabled = true;
  button.textContent = "Listening\u2026";
  $("#discover-status").innerHTML =
    '<div class="empty">Listening for devices. This takes a few seconds.</div>';
  try {
    const result = await api("/api/devices/discover", { method: "POST",
      body: JSON.stringify({ timeout: 5 }), timeout: 60000 });

    const parts = Object.entries(result.categories || {})
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${v} ${esc(k)}`).join(", ");
    $("#discover-status").innerHTML = `<div class="note" style="margin-bottom:12px">
      Found <b>${result.count}</b> device${result.count === 1 ? "" : "s"} in
      ${(result.duration_ms / 1000).toFixed(1)}s${parts ? ` \u2014 ${parts}` : ""}.
      ${result.errors && result.errors.length
        ? `<span style="color:var(--med)"> Some sources failed: ${
            esc(result.errors.join("; ").slice(0, 120))}</span>` : ""}</div>`;

    if (result.bluetooth && result.bluetooth.length) {
      $("#bluetooth-card").hidden = false;
      $("#bluetooth-rows").innerHTML = result.bluetooth.map(b => `<tr>
        <td>${esc(b.name)}</td>
        <td class="mono dim">${esc(b.address || "")}</td>
        <td class="dim">${esc(b.vendor || "")}</td>
        <td>${b.connected ? '<span class="tag good">ok</span>'
                          : `<span class="tag">${esc(b.status || "")}</span>`}</td>
      </tr>`).join("");
    }
    await loadDevicesView();
    toast(`Discovered ${result.count} device(s)`, "ok");
  } catch (err) {
    $("#discover-status").innerHTML =
      `<div class="empty"><b>Discovery failed</b>${esc(err.message)}</div>`;
  } finally {
    button.disabled = false;
    button.textContent = "Discover devices";
  }
});

$("#btn-forget-devices").addEventListener("click", async () => {
  if (!confirm("Forget every discovered device? Discovery can find them again.")) return;
  try {
    const result = await api("/api/devices", { method: "DELETE" });
    toast(`Forgot ${result.removed} device(s)`, "ok");
    loadDevicesView();
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------------------------------------- my network */

const RISK_CLASS = { critical: "critical", high: "high", medium: "medium",
                     low: "low", info: "info" };

async function loadNetworkView() {
  await Promise.all([loadConnection(), loadHotspot()]);
}

async function loadConnection() {
  try {
    const data = await api("/api/connect");
    const c = data.connection || {};
    $("#connection-state").innerHTML = c.connected
      ? `<div class="package"><div class="row"><span>Connected to</span>
           <b>${esc(c.ssid || "?")}</b></div>
         <div class="row"><span>Security</span><b>${esc(c.security || "?")}
           ${esc(c.cipher || "")}</b></div>
         <div class="row"><span>Signal</span><b>${esc(c.signal || "?")}</b></div>
         <div class="row"><span>Channel</span><b>${esc(c.channel || "?")}</b></div>
         <div class="row"><span>Gateway</span><b class="mono">${esc(data.gateway || "?")}</b></div>
         ${(data.subnets || []).map(s => `<div class="row"><span>Subnet</span>
           <b class="mono">${esc(s.network)} on ${esc(s.interface)}</b></div>`).join("")}
         </div>`
      : `<div class="note" style="margin-bottom:12px">Not connected to any wireless
         network. Scanning does not need a connection &mdash; this is only for
         examining a network from the inside.</div>`;

    const select = $("#connect-ssid");
    select.innerHTML = '<option value="">Saved networks\u2026</option>'
      + (data.profiles || []).map(p =>
          `<option value="${esc(p)}"${p === c.ssid ? " selected" : ""}>${esc(p)}</option>`
        ).join("");
  } catch (err) {
    $("#connection-state").innerHTML =
      `<div class="empty">${esc(err.message)}</div>`;
  }
}

$("#btn-connect").addEventListener("click", async () => {
  const ssid = $("#connect-manual").value.trim() || $("#connect-ssid").value;
  if (!ssid) { toast("Pick a network or type its name", "err"); return; }
  const button = $("#btn-connect");
  button.disabled = true;
  button.textContent = "Connecting\u2026";
  try {
    const body = { ssid };
    const passphrase = $("#connect-pass").value;
    if (passphrase) body.passphrase = passphrase;
    const result = await api("/api/connect", { method: "POST",
      body: JSON.stringify(body), timeout: 60000 });
    toast(result.message, "ok");
    $("#connect-pass").value = "";
    loadConnection();
  } catch (err) { toast(err.message, "err"); }
  finally { button.disabled = false; button.textContent = "Connect"; }
});

$("#btn-disconnect").addEventListener("click", async () => {
  try {
    await api("/api/connect/disconnect", { method: "POST", body: "{}" });
    toast("Disconnected", "ok");
    loadConnection();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-audit").addEventListener("click", async () => {
  if (!confirm("This connects to services on the local network to see what is "
             + "running.\n\nOnly do this on a network you are responsible for.\n\n"
             + "Continue?")) return;
  const button = $("#btn-audit");
  button.disabled = true;
  button.textContent = "Auditing\u2026";
  $("#audit-status").textContent = "Discovering hosts, then checking services. "
    + "This takes up to a minute.";
  try {
    const thorough = $("#audit-thorough").checked;
    const result = await api("/api/audit", { method: "POST",
      body: JSON.stringify({
        confirm: "audit",
        timeout: thorough ? 1.5 : 0.8,
        ports: thorough
          ? [21,22,23,25,53,80,139,443,445,515,554,631,1883,3306,3389,5000,5432,5900,8080,8443,8883,9100]
          : undefined,
      }), timeout: 300000 });

    $("#audit-status").innerHTML = `Checked <b>${result.host_count}</b> host(s) in
      ${(result.duration_ms / 1000).toFixed(0)}s. ${result.with_services} had
      services responding.`;
    renderAuditFindings(result);
  } catch (err) {
    $("#audit-status").textContent = "";
    toast(err.message, "err");
  } finally {
    button.disabled = false;
    button.textContent = "Run audit";
  }
});

function renderAuditFindings(result) {
  const findings = result.findings || [];
  $("#audit-findings").innerHTML = findings.length
    ? `<div class="card"><h2>Findings</h2>${findings.map(f => `
        <div class="finding-row">
          <span class="sev ${esc(RISK_CLASS[f.risk] || "info")}">${esc(f.risk)}</span>
          <span class="what"><b>${esc(f.title)}</b>
            <span class="dim"> ${esc(f.detail)}</span></span>
          ${f.host ? `<span class="mono dim">${esc(f.host)}${
            f.port ? ":" + f.port : ""}</span>` : ""}
        </div>`).join("")}</div>`
    : `<div class="card"><div class="empty"><b>Nothing flagged</b>
       No exposed services of concern were found.</div></div>`;

  const hosts = (result.hosts || []).filter(h => h.services && h.services.length);
  $("#audit-hosts-card").hidden = !hosts.length;
  $("#audit-hosts").innerHTML = hosts.map(h => `<tr>
    <td><b>${esc(h.label || h.ip)}</b>${h.is_gateway
      ? ' <span class="tag good">gateway</span>' : ""}</td>
    <td class="mono">${esc(h.ip)}</td>
    <td class="dim">${esc(h.vendor || "")}</td>
    <td>${h.services.map(sv =>
      `<span class="tag ${sv.risk === "critical" || sv.risk === "high" ? "bad"
        : sv.risk === "medium" ? "warn" : ""}"
        title="${esc(sv.why)}">${sv.port} ${esc(sv.service)}</span>`).join(" ")}</td>
  </tr>`).join("");
}

async function loadHotspot() {
  try {
    const data = await api("/api/hotspot");
    if (!data.supported) {
      $("#hotspot-state").innerHTML =
        `<div class="note">${esc(data.reason || "Not available here")}</div>`;
      return;
    }
    const h = data.hotspot || {};
    $("#hotspot-state").innerHTML = `<div class="package" style="margin-bottom:12px">
      <div class="row"><span>Hotspot</span><b style="color:${
        h.on ? "var(--ok)" : "var(--dim)"}">${esc(h.state || "Off")}</b></div>
      ${h.ssid ? `<div class="row"><span>Name</span><b>${esc(h.ssid)}</b></div>` : ""}
      ${h.on ? `<div class="row"><span>Connected devices</span>
        <b>${h.clients ?? 0} of ${h.maxClients ?? "?"}</b></div>` : ""}
      ${h.source ? `<div class="row"><span>Sharing</span><b>${esc(h.source)}</b></div>` : ""}
      </div>`;
    if (h.ssid && !$("#hs-ssid").value) $("#hs-ssid").value = h.ssid;

    const select = $("#hs-source");
    select.innerHTML = '<option value="">Choose an adapter\u2026</option>'
      + (data.adapters || []).map(a =>
          `<option value="${esc(a.name)}"${
            a.name === data.suggested_source ? " selected" : ""}>${esc(a.name)}${
            a.vpn ? " \u2014 looks like a VPN" : ""}${
            a.up ? "" : " (down)"}</option>`).join("");

    $("#hotspot-advice").innerHTML = (data.advice || []).length
      ? `<ul class="reco" style="margin-top:12px">${
          data.advice.map(a => `<li>${esc(a)}</li>`).join("")}</ul>` : "";
  } catch (err) {
    $("#hotspot-state").innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
}

$("#btn-hs-configure").addEventListener("click", async () => {
  const ssid = $("#hs-ssid").value.trim();
  const passphrase = $("#hs-pass").value;
  if (!ssid) { toast("Give the hotspot a name", "err"); return; }
  if (passphrase.length < 8) { toast("The passphrase needs at least 8 characters", "err"); return; }
  try {
    const result = await api("/api/hotspot/configure", { method: "POST",
      body: JSON.stringify({ ssid, passphrase, band: $("#hs-band").value }),
      timeout: 60000 });
    toast(result.message, "ok");
    loadHotspot();
  } catch (err) { toast(err.message, "err"); }
});

for (const [id, path, label] of [
  ["#btn-hs-start", "/api/hotspot/start", "Starting"],
  ["#btn-hs-stop", "/api/hotspot/stop", "Stopping"],
]) {
  $(id).addEventListener("click", async () => {
    const button = $(id);
    const original = button.textContent;
    button.disabled = true;
    button.textContent = label + "\u2026";
    try {
      const result = await api(path, { method: "POST", timeout: 120000 });
      toast(result.message, "ok");
      loadHotspot();
    } catch (err) { toast(err.message, "err"); }
    finally { button.disabled = false; button.textContent = original; }
  });
}

$("#btn-hs-share").addEventListener("click", async () => {
  const source = $("#hs-source").value;
  if (!source) { toast("Pick the adapter that has internet", "err"); return; }
  const target = prompt(
    "Which adapter is the hotspot using?\n\nUsually 'Local Area Connection* 1' or "
    + "similar. Check Network Connections if unsure.",
    "Local Area Connection* 1"
  );
  if (!target) return;
  try {
    const result = await api("/api/hotspot/sharing", { method: "POST",
      body: JSON.stringify({ source, target, enable: true }), timeout: 60000 });
    toast(result.message, "ok");
    loadHotspot();
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------------------------------------------ survey */

const GRADE_LABEL = {
  excellent: "Excellent", good: "Good", fair: "Fair",
  weak: "Weak", unusable: "Unusable", none: "Not detected",
};

function gradeOf(rssi) {
  if (rssi == null) return "none";
  if (rssi >= -60) return "excellent";
  if (rssi >= -67) return "good";
  if (rssi >= -72) return "fair";
  if (rssi >= -80) return "weak";
  return "unusable";
}

async function loadSurveyView() {
  await Promise.all([loadPoints(), loadCoverage(), loadPlan(),
                     loadSnapshots(), loadInventory()]);
}

function siteParam(prefix = "?") {
  return state.activeSite ? `${prefix}site_id=${state.activeSite}` : "";
}

async function loadPoints() {
  try {
    const data = await api(`/api/survey/points${siteParam()}`);
    $("#point-rows").innerHTML = data.points.length
      ? data.points.map(p => {
          const grade = gradeOf(p.best_rssi);
          return `<tr>
            <td>${esc(p.name)}</td>
            <td class="dim">${esc(p.floor || "")}</td>
            <td class="right mono">${p.ap_count}</td>
            <td><span class="grade-pill ${grade}">${esc(GRADE_LABEL[grade])}</span>
              <span class="mono dim">${p.best_rssi ?? ""}</span></td>
            <td class="right mono dim">${new Date(p.captured_at * 1000).toLocaleTimeString()}</td>
            <td class="right"><button class="btn small danger"
              data-del-point="${p.id}">Remove</button></td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="6"><div class="empty"><b>No locations captured</b>
         Name a spot and press capture to start building a coverage picture.</div></td></tr>`;
  } catch (err) {
    $("#point-rows").innerHTML = errorRow(6, err.message);
  }
}

$("#point-rows").addEventListener("click", async e => {
  const button = e.target.closest("[data-del-point]");
  if (!button) return;
  try {
    await api(`/api/survey/points/${button.dataset.delPoint}`, { method: "DELETE" });
    toast("Location removed", "ok");
    loadPoints(); loadCoverage();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-capture").addEventListener("click", async () => {
  const name = $("#point-name").value.trim();
  if (!name) { toast("Give the location a name first", "err"); return; }
  const button = $("#btn-capture");
  button.disabled = true;
  button.textContent = "Scanning\u2026";
  $("#capture-status").textContent = "Running a fresh scan at this location\u2026";
  try {
    const result = await api("/api/survey/points", { method: "POST",
      body: JSON.stringify({
        name, floor: $("#point-floor").value.trim(),
        notes: $("#point-notes").value.trim(), site_id: state.activeSite,
      })});
    const grade = gradeOf(result.best_rssi);
    $("#capture-status").innerHTML =
      `Recorded <b>${esc(name)}</b>: ${result.ap_count} networks, strongest `
      + `${result.best_rssi} dBm (${GRADE_LABEL[grade]}).`;
    $("#point-name").value = ""; $("#point-notes").value = "";
    toast(`Captured ${name}`, "ok");
    loadPoints(); loadCoverage();
  } catch (err) {
    $("#capture-status").textContent = "";
    toast(err.message, "err");
  } finally {
    button.disabled = false;
    button.textContent = "Scan here and record";
  }
});

async function loadCoverage() {
  try {
    const data = await api(`/api/survey/coverage${siteParam()}`);
    if (!data.points.length) {
      $("#coverage-table").innerHTML =
        '<div class="empty">Capture at least one location to build the matrix.</div>';
      $("#coverage-recs").innerHTML = "";
      return;
    }
    const headers = data.points.map(p => `<th>${esc(p.name)}</th>`).join("");
    const rows = data.rows.slice(0, 40).map(r => {
      const cells = r.cells.map(c =>
        `<td class="cov ${esc(c.grade)}" title="${esc(c.point)}: ${esc(c.label)}">${
          c.rssi ?? "\u2014"}</td>`).join("");
      return `<tr><td>${esc(r.ssid)}</td>
        <td><span class="chip ${bandClass(r.band)}">${esc(r.band)}</span></td>
        ${cells}<td class="mono right">${r.coverage_pct}%</td></tr>`;
    }).join("");
    $("#coverage-table").innerHTML = `<table><thead><tr><th>Network</th><th>Band</th>
      ${headers}<th class="right">Covered</th></tr></thead><tbody>${rows}</tbody></table>`;

    $("#coverage-recs").innerHTML = data.recommendations.length
      ? `<p class="eyebrow" style="margin-top:16px">Recommendations</p>`
        + `<ul class="reco">${data.recommendations.map(r =>
            `<li>${esc(r)}</li>`).join("")}</ul>`
      : "";
  } catch (err) {
    $("#coverage-table").innerHTML =
      `<div class="empty"><b>Could not build the matrix</b>${esc(err.message)}</div>`;
  }
}

async function loadPlan() {
  try {
    const plan = await api("/api/survey/channel-plan?minutes=60");
    const blocks = ["2.4", "5", "6"].map(band => {
      const entry = plan[band];
      if (!entry) return "";
      const picks = entry.recommended.map(c =>
        `<div class="pick">
          <b class="${bandClass(band)}">${c.channel}</b>
          <span>${esc(c.reasons.join(", "))}</span>
          <em class="mono">${c.score}</em>
        </div>`).join("");
      return `<div class="plan-band">
        <div class="eyebrow">${esc(band)} GHz &middot; ${entry.channels_in_use} in use</div>
        ${picks}</div>`;
    }).join("");
    const notes = plan.summary && plan.summary.length
      ? `<ul class="reco">${plan.summary.map(n => `<li>${esc(n)}</li>`).join("")}</ul>`
      : "";
    $("#plan-output").innerHTML = blocks + notes;
  } catch (err) {
    $("#plan-output").innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
}

async function loadSnapshots() {
  try {
    const data = await api(`/api/snapshots${siteParam()}`);
    $("#snapshot-rows").innerHTML = data.snapshots.length
      ? data.snapshots.map(s => `<tr>
          <td>${esc(s.name)}</td>
          <td class="right mono">${s.ap_count}</td>
          <td class="right mono dim">${new Date(s.taken_at * 1000).toLocaleString()}</td>
          <td class="right">
            <button class="btn small" data-compare="${s.id}">Compare</button>
            <button class="btn small danger" data-del-snap="${s.id}">&times;</button>
          </td></tr>`).join("")
      : `<tr><td colspan="4"><div class="empty">No snapshots yet.</div></td></tr>`;
  } catch (err) {
    $("#snapshot-rows").innerHTML = errorRow(4, err.message);
  }
}

$("#btn-snapshot").addEventListener("click", async () => {
  const name = $("#snap-name").value.trim();
  if (!name) { toast("Give the snapshot a name", "err"); return; }
  try {
    await api("/api/snapshots", { method: "POST",
      body: JSON.stringify({ name, site_id: state.activeSite, minutes: 30 }) });
    $("#snap-name").value = "";
    toast("Snapshot taken", "ok");
    loadSnapshots();
  } catch (err) { toast(err.message, "err"); }
});

$("#snapshot-rows").addEventListener("click", async e => {
  const del = e.target.closest("[data-del-snap]");
  if (del) {
    try {
      await api(`/api/snapshots/${del.dataset.delSnap}`, { method: "DELETE" });
      toast("Snapshot removed", "ok");
      loadSnapshots();
    } catch (err) { toast(err.message, "err"); }
    return;
  }
  const compare = e.target.closest("[data-compare]");
  if (!compare) return;
  $("#diff-output").innerHTML = '<div class="empty">Comparing\u2026</div>';
  try {
    const diff = await api(`/api/snapshots/${compare.dataset.compare}/compare?minutes=30`);
    const list = (items, kind) => items.length
      ? `<div class="diff-group ${kind}"><b>${kind}</b>${items.slice(0, 12).map(i =>
          `<div>${esc(i.ssid || "(hidden)")} <span class="mono dim">${esc(i.bssid)}</span></div>`
        ).join("")}</div>` : "";
    const changed = diff.changed.length
      ? `<div class="diff-group changed"><b>changed</b>${diff.changed.slice(0, 12).map(c =>
          `<div>${esc(c.ssid || c.bssid)} <span class="dim">${
            Object.entries(c.changes).map(([k, v]) =>
              `${esc(k)}: ${esc(v.before)} \u2192 ${esc(v.after)}`).join("; ")}</span></div>`
        ).join("")}</div>` : "";
    $("#diff-output").innerHTML = `<p class="eyebrow" style="margin-top:16px">
      ${esc(diff.summary)}</p>${list(diff.added, "added")}${list(diff.removed, "removed")}${changed}`;
  } catch (err) {
    $("#diff-output").innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
});

async function loadInventory() {
  try {
    const data = await api(`/api/inventory${siteParam()}`);
    $("#inventory-rows").innerHTML = data.inventory.length
      ? data.inventory.map(i => `<tr>
          <td>${esc(i.label || i.ssid || "")}</td>
          <td class="mono dim">${esc(i.bssid)}</td>
          <td>${esc(i.location || "")}</td>
          <td class="mono">${esc(i.asset_tag || "")}</td>
          <td>${esc(i.band || "?")} / ${esc(i.channel ?? "?")}</td>
          <td>${i.managed ? '<span class="tag good">managed</span>'
                          : '<span class="tag">unmanaged</span>'}</td>
          <td class="right"><button class="btn small danger"
            data-del-inv="${esc(i.bssid)}">Remove</button></td>
        </tr>`).join("")
      : `<tr><td colspan="7"><div class="empty"><b>Nothing catalogued yet</b>
         Open any network from the Live tab and use "Add to inventory".</div></td></tr>`;
  } catch (err) {
    $("#inventory-rows").innerHTML = errorRow(7, err.message);
  }
}

$("#inventory-rows").addEventListener("click", async e => {
  const button = e.target.closest("[data-del-inv]");
  if (!button) return;
  try {
    await api(`/api/inventory/${encodeURIComponent(button.dataset.delInv)}`,
              { method: "DELETE" });
    toast("Removed from inventory", "ok");
    loadInventory();
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------------------------------------------ report */

async function loadReportView() {
  await loadSites();
  try {
    const exports = await api("/api/export");
    $("#export-links-2").innerHTML = exports.available.map(name =>
      `<a class="btn small" href="/api/export/${encodeURIComponent(name)}${
        state.token ? `?token=${encodeURIComponent(state.token)}` : ""}">${esc(name)}</a>`
    ).join("");
  } catch { /* non-fatal */ }
}

function reportUrl() {
  const params = new URLSearchParams({
    title: $("#report-title").value.trim() || "Wireless Site Survey",
    prepared_by: $("#report-by").value.trim(),
    minutes: $("#report-window").value,
    plan: $("#report-plan").checked,
    coverage: $("#report-coverage").checked,
    inventory: $("#report-inventory").checked,
  });
  if (state.activeSite) params.set("site_id", state.activeSite);
  if (state.token) params.set("token", state.token);
  return `/api/report?${params}`;
}

$("#btn-report-open").addEventListener("click", () => {
  window.open(reportUrl(), "_blank");
});
$("#btn-report-download").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = reportUrl();
  link.download = "";
  link.click();
});

async function loadSites() {
  try {
    const data = await api("/api/sites");
    state.sites = data.sites;
    state.activeSite = data.active || null;

    const select = $("#site-select");
    select.innerHTML = '<option value="">No site selected</option>'
      + data.sites.map(s => `<option value="${s.id}"${
          s.id === data.active ? " selected" : ""}>${esc(s.name)}</option>`).join("");

    const rows = $("#site-rows");
    if (rows) {
      rows.innerHTML = data.sites.length
        ? data.sites.map(s => `<tr>
            <td>${esc(s.name)}</td><td class="dim">${esc(s.client || "")}</td>
            <td class="right mono">${s.point_count}</td>
            <td class="right mono">${s.ap_count}</td>
            <td class="right"><button class="btn small danger"
              data-del-site="${s.id}">Remove</button></td></tr>`).join("")
        : `<tr><td colspan="5"><div class="empty">No sites yet. Add one to keep
           client work separate.</div></td></tr>`;
    }
  } catch { /* non-fatal */ }
}

$("#site-select").addEventListener("change", async e => {
  const id = e.target.value;
  try {
    await api(`/api/sites/${id || 0}/activate`, { method: "POST" });
    state.activeSite = id ? Number(id) : null;
    toast(id ? "Site selected" : "Site cleared", "ok");
    if (state.view === "survey") loadSurveyView();
    if (state.view === "report") loadReportView();
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-add-site").addEventListener("click", async () => {
  const name = $("#new-site-name").value.trim();
  if (!name) { toast("Give the site a name", "err"); return; }
  try {
    await api("/api/sites", { method: "POST", body: JSON.stringify({
      name, client: $("#new-site-client").value.trim(),
      address: $("#new-site-address").value.trim(),
      contact: $("#new-site-contact").value.trim(),
    })});
    ["#new-site-name", "#new-site-client", "#new-site-address", "#new-site-contact"]
      .forEach(sel => { $(sel).value = ""; });
    toast("Site added", "ok");
    loadSites();
  } catch (err) { toast(err.message, "err"); }
});

$("#site-rows").addEventListener("click", async e => {
  const button = e.target.closest("[data-del-site]");
  if (!button) return;
  if (!confirm("Remove this site and everything recorded against it?")) return;
  try {
    await api(`/api/sites/${button.dataset.delSite}`, { method: "DELETE" });
    toast("Site removed", "ok");
    loadSites();
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------------------------------------------- theme */

function systemPrefersLight() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
}

function resolveTheme(choice) {
  if (choice === "system") return systemPrefersLight() ? "light" : "dark";
  return choice === "light" ? "light" : "dark";
}

function applyTheme(choice) {
  state.themeChoice = choice;
  const resolved = resolveTheme(choice);
  document.documentElement.setAttribute("data-theme", resolved);
  const button = $("#btn-theme");
  if (button) button.textContent = resolved === "light" ? "Dark" : "Light";
  // Redraw anything that bakes colours into SVG at render time.
  if (state.view === "spectrum") loadSpectrum();
}

$("#btn-theme").addEventListener("click", async () => {
  const next = resolveTheme(state.themeChoice) === "light" ? "dark" : "light";
  applyTheme(next);
  const select = $("#set-theme");
  if (select) select.value = next;
  try {
    await api("/api/settings", { method: "PUT",
      body: JSON.stringify({ ui: { theme: next } }) });
  } catch { /* the look already changed; persistence is a bonus */ }
});

if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (state.themeChoice === "system") applyTheme("system");
  });
}

/* -------------------------------------------------------------- shutdown */

$("#btn-quit").addEventListener("click", async () => {
  if (!confirm("Stop wifirecon?\n\nScanning stops and the database is closed "
             + "properly. Any running session is closed out.")) return;
  clearInterval(state.timers.status);
  try {
    await api("/api/shutdown", { method: "POST",
      body: JSON.stringify({ confirm: "shutdown" }), timeout: 10000 });
  } catch { /* it may exit before answering, which is fine */ }
  document.body.innerHTML =
    '<div style="padding:60px;font-family:var(--ui);color:var(--text);max-width:560px">'
    + '<h1 style="font-size:20px">wifirecon has stopped</h1>'
    + '<p style="color:var(--dim)">Scanning stopped and the database was closed '
    + 'cleanly. You can close this window.</p></div>';
});

/* ------------------------------------------------------------------ status */

const PHASE_TEXT = {
  idle: "idle", starting: "starting", selecting: "choosing adapter",
  requesting: "scanning", settling: "listening", reading: "reading",
  analysing: "analysing", waiting: "waiting", error: "error",
};
const PHASE_BUSY = ["starting", "selecting", "requesting", "settling", "reading", "analysing"];

async function refreshStatus() {
  try {
    const status = await api("/api/status", { timeout: 8000 });
    const engine = status.engine;
    state.scanning = !!engine.scanning;

    // --- adapter chip: always says which radio, and whether it is working ---
    const adapter = engine.adapter;
    const dot = $("#pulse-dot");
    if (!engine.running) {
      dot.className = "dot down";
    } else if (engine.last_error) {
      dot.className = "dot down";
    } else if (engine.scanning) {
      dot.className = "dot live";
    } else {
      dot.className = "dot";
    }

    $("#adapter-name").textContent = adapter
      ? (adapter.label || adapter.description || "Adapter")
      : "No adapter";
    $("#adapter-sub").textContent = !adapter
      ? "click to choose"
      : !engine.scanning
        ? `ready \u00b7 ${adapter.band_label || "idle"}`
        : engine.last_error
          ? "scan failing"
          : (adapter.band_label || "scanning");
    state.adapterState = adapter ? adapter.state_label : null;
    $("#adapter-chip").title = adapter
      ? `${adapter.description}\n${adapter.mac || ""} ${adapter.driver ? "driver " + adapter.driver : ""}`
        + "\nClick to change adapter"
      : "Click to choose an adapter";

    // --- phase strip ---
    const phase = engine.phase || "idle";
    $("#phase-text").textContent = PHASE_TEXT[phase] || phase;
    const fill = $("#phase-fill");
    if (PHASE_BUSY.includes(phase)) {
      fill.className = "sweep";
      fill.style.width = "";
    } else if (phase === "waiting" && engine.next_scan_in != null) {
      const interval = Math.max(engine.interval_seconds || 20, 1);
      const done = Math.max(0, Math.min(1, 1 - engine.next_scan_in / interval));
      fill.className = "";
      fill.style.width = `${(done * 100).toFixed(0)}%`;
      $("#phase-text").textContent = `next in ${Math.ceil(engine.next_scan_in)}s`;
    } else {
      fill.className = "";
      fill.style.width = "0%";
    }
    if (engine.last_error && phase === "error") {
      $("#phase-text").textContent = "scan failed";
    }

    // --- start/stop button ---
    const button = $("#btn-startstop");
    button.textContent = engine.scanning ? "Stop scanning" : "Start scanning";
    button.classList.toggle("primary", !engine.scanning);
    button.classList.toggle("danger", engine.scanning);

    /* Before this process has scanned, "in range" would read 0 even with a
       database full of networks. Fall back to what was recently loaded. */
    const inRange = engine.stats.bss_seen || state.recentCount || 0;
    $("#stat-visible").textContent = inRange;
    $("#nav-live").textContent = inRange;
    $("#stat-known").textContent = status.stats.total_bss ?? 0;
    $("#stat-open").textContent = status.alerts.unacked ?? 0;
    $("#nav-findings").textContent = status.alerts.unacked ?? 0;
    $("#nav-findings").classList.toggle("hot", (status.alerts.unacked ?? 0) > 0);

    $("#foot-version").textContent = status.version + (engine.mock ? " mock" : "");
    $("#foot-adapter").textContent = adapter
      ? (adapter.label || adapter.description || "").slice(0, 18) : "none";
    $("#foot-db").textContent = bytes(status.db_size_bytes);

    if (status.update && status.update.available && !state.updateAvailable) {
      state.updateAvailable = true;
      $("#btn-apply-update").hidden = false;
      toast("A new build is available. Install it from Diagnostics.", "", "Update available");
    }

    if (engine.mock && !state.warnedMock) {
      state.warnedMock = true;
      toast("Running on synthetic data. Native Wifi is not available on this host.",
            "err", "Mock mode");
    }

    // Surface a scan failure once rather than silently sitting there.
    if (engine.last_error && engine.last_error !== state.lastReportedError) {
      state.lastReportedError = engine.last_error;
      toast(engine.last_error, "err", "Scan problem");
    } else if (!engine.last_error) {
      state.lastReportedError = null;
    }

    if (engine.last_scan_at && engine.last_scan_at !== state.lastScanAt) {
      state.lastScanAt = engine.last_scan_at;
      await refreshFlagged();
      if (state.view === "live") loadNetworks();
      if (state.view === "spectrum") loadSpectrum();
      if (state.view === "findings") loadFindings();
      if (state.view === "adapters") loadAdapterView();
    }
    state.pollFailures = 0;
  } catch (err) {
    // A single slow or dropped poll is not a disconnection. Only say so after
    // several in a row, or a transient hiccup makes a working app look dead.
    state.pollFailures = (state.pollFailures || 0) + 1;
    if (state.pollFailures >= 3) {
      $("#pulse-dot").className = "dot down";
      $("#phase-text").textContent = "reconnecting";
      $("#adapter-sub").textContent = `no reply (${state.pollFailures} tries)`;
    }
    if (state.pollFailures === 10) {
      toast("The app has stopped responding. If it does not come back, restart it "
            + "from the Start Menu.", "err", "Connection lost");
    }
  }
}

$("#btn-startstop").addEventListener("click", async () => {
  const button = $("#btn-startstop");
  button.disabled = true;
  try {
    if (state.scanning) {
      await api("/api/scan/stop", { method: "POST" });
      toast("Scanning stopped", "ok");
    } else {
      // No adapter chosen yet, so show the picker rather than guessing.
      const data = await loadAdapters();
      if (!data.selected && data.adapters.length > 1) {
        await openGate();
        return;
      }
      const result = await api("/api/scan/start", { method: "POST", body: "{}" });
      toast(`Scanning on ${result.adapter.label || result.adapter.description}`, "ok");
    }
    await refreshStatus();
  } catch (err) {
    toast(err.message, "err");
  } finally {
    button.disabled = false;
  }
});

$("#btn-scan").addEventListener("click", async () => {
  const button = $("#btn-scan");
  button.disabled = true;
  button.textContent = "Scanning\u2026";
  try {
    const result = await api("/api/scan?wait=true", { method: "POST" });
    toast(`Found ${result.count} networks in ${(result.duration_ms / 1000).toFixed(1)}s`
          + (result.adapter ? ` on ${result.adapter}` : ""), "ok");
    await refreshStatus();
    if (state.view === "live") loadNetworks();
    if (state.view === "spectrum") loadSpectrum();
  } catch (err) {
    toast(err.message, "err");
  } finally {
    button.disabled = false;
    button.textContent = "Single scan";
  }
});

/* ---------------------------------------------------------------- shortcuts */

document.addEventListener("keydown", e => {
  if (e.target.matches("input, textarea, select")) return;
  const map = { "1": "live", "2": "spectrum", "3": "findings", "4": "ssids",
                "5": "devices", "6": "network", "7": "survey", "8": "report",
                "9": "adapters", "0": "settings" };
  if (e.key === "s") { $("#btn-startstop").click(); return; }
  if (map[e.key]) { showView(map[e.key]); return; }
  if (e.key === "/") { e.preventDefault(); showView("live"); $("#live-search").focus(); }
  if (e.key === "r") refreshStatus();
});

/* --------------------------------------------------------------- lifecycle */

function startPolling() {
  clearInterval(state.timers.status);
  state.timers.status = setInterval(refreshStatus, 4000);
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) clearInterval(state.timers.status);
  else { refreshStatus(); startPolling(); }
});

(async function init() {
  // Theme first, so nothing flashes in the wrong colours.
  try {
    const settings = await api("/api/settings", { timeout: 8000 });
    applyTheme(settings.ui?.theme || "dark");
  } catch {
    applyTheme("dark");
  }

  await refreshStatus();
  await loadMarks();
  await loadFindings();
  await loadSites();
  showView("live");
  startPolling();

  // First run, or nothing scanning and no adapter chosen: show the picker
  // rather than silently doing nothing.
  try {
    const status = await api("/api/status");
    if (!status.engine.scanning) {
      const data = await loadAdapters();
      if (!data.selected) await openGate();
    }
  } catch { /* the status poll reports connection trouble */ }
})();

})();
