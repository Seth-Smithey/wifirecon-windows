# Detection rules

26 rules. Every one runs on every scan.

## Two kinds of rule

**Event rules** report one finding per radio, because what they describe belongs
to that radio: a lookalike name, an enterprise downgrade, a security change, a
beacon fingerprint change, a channel move.

**Inventory rules** describe a standing property of the neighbourhood - WPS
being on, PMF being absent, a channel being busy - and report **one summary
finding carrying a count**, not one per access point:

> WPS enabled on 17 of 286 nearby APs (9 PIN-capable)

The strongest three by signal are named in the detail; the full per-radio list
is in the evidence. In a dense area the per-AP form produced hundreds of rows a
scan and buried the handful that mattered. The rules that work this way are
marked *summary* below.

Every rule runs on every scan. Findings are written to the database, then pushed
to whichever notification channels are switched on. A finding is suppressed for
`suppress_seconds` (15 minutes by default) after it fires for the same rule and
BSSID, so a persistent condition does not repeat every 20 seconds.

Severity ladder: `info` < `low` < `medium` < `high` < `critical`. The
`severity_floor` setting decides what is worth recording at all; it ships at
`low`, which keeps inventory-style rules like `open_network` out of the way until
you ask for them.

## Impersonation and rogue APs

| Rule | Severity | What it catches |
|---|---|---|
| `lookalike_ssid` | critical / high | A name within a couple of edits of one you marked trusted or watched, after folding out homoglyphs and leetspeak. `Example_Hоme` with a Cyrillic о scores as identical. |
| `enterprise_downgrade_bait` | critical | The same SSID offered both with 802.1X and without. That is the shape of a credential-capture AP. |
| `ssid_conflict` | high | One SSID served with inconsistent security across BSSIDs. Enterprise and PSK count as different postures. |
| `security_downgrade` | high | A BSSID now advertising weaker security than it did before. Config change, or someone reusing the MAC. |
| `mixed_script_ssid` | medium | A name mixing Latin with another alphabet. |
| `lure_ssid` | medium | An open network using a name devices auto-join, such as `attwifi`. |
| `bssid_multi_ssid` | high | One radio answering to more names than a multi-BSSID AP plausibly would. |
| `randomized_bssid` | high / info | Locally administered MAC. Routine for phone hotspots, notable on a tracked SSID. |
| `vendor_mismatch` | medium | A tracked network appearing on hardware from a vendor it has never used. |
| `new_bssid` | medium | A radio you have not seen before broadcasting a name you track. |

## Weak configuration

| Rule | Severity | What it catches |
|---|---|---|
| `weak_crypto` | high / medium / low | WEP, TKIP, or WPA1 still advertised. |
| `wps_enabled` | medium / info | *Summary.* How many nearby APs advertise WPS, and how many offer PIN methods. Medium when any do. |
| `pmf_missing` | low | *Summary.* How many encrypted APs offer no management frame protection at all. |
| `wpa3_pmf_optional` | medium | WPA3 advertised without PMF required. Invalid per the specification, and the shape a downgrade wants, so this one is per radio. |
| `wps_device_disclosure` | low | *Summary.* How many APs publish make, model and firmware in every beacon, and how many add a serial number. |
| `open_network` | info | No encryption. |
| `hidden_ssid` | info | SSID suppressed in beacons. |

## Change and anomaly

| Rule | Severity | What it catches |
|---|---|---|
| `rssi_anomaly` | medium | A known AP suddenly much stronger than its baseline. |
| `channel_change` | medium / info | An AP moved channel. |
| `ie_fingerprint_change` | high / low | The set of elements an AP advertises changed, reported with what was added and removed. High when the elements carrying the security posture were among them. Ten volatile element IDs are excluded, so a beacon and a probe response from the same AP fingerprint identically. |
| `beacon_interval_anomaly` | medium / low | Beacon interval well away from the usual 100 TU, or changed at runtime. |
| `malformed_ie` | medium | Elements that did not decode cleanly. |
| `watched_ap_missing` | medium | A watched AP has stopped appearing. |

## Environment

| Rule | Severity | What it catches |
|---|---|---|
| `channel_congestion` | medium / low | *Summary, per channel.* A channel whose occupants report high utilisation. Medium once the worst reading passes 85%. Eight APs on channel 6 are one finding, not eight. |
| `adjacent_channel_overlap` | info | *Summary.* How many APs run wide channels on 2.4 GHz off the 1/6/11 grid. |
| `country_mismatch` | low | An AP claiming a regulatory domain different from everything around it. |

## Tuning

In the order worth trying:

1. **Add trusted marks.** Not tuning as such, but it is what switches the most
   valuable rules on. Nothing else matters as much.
2. **Mute a rule.** Right-click any finding, then *Mute the rule*. Existing
   findings stay; no new ones are raised. Stored in `detections.muted_rules`.
3. **Raise the severity floor.** Settings then Detections. Ships at `low`.
4. **Lengthen the cooldown.** `suppress_seconds`, per rule and target.
5. **Add an ignore mark** for a specific BSSID, vendor prefix or name.

Marks are the main control:

- **Trusted** teaches `lookalike_ssid` what the real thing is. Add your own
  network names here first, or that rule has nothing to compare against.
- **Watch** raises the severity of changes on a network and enables
  `watched_ap_missing`.
- **Ignore** silences a specific BSSID, OUI or name entirely.
