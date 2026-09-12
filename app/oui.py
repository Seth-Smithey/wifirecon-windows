"""
MAC address vendor lookup.

Ships with a compact table of vendors you actually meet in a Wi-Fi survey, and
can load the full IEEE registry (or a Wireshark `manuf` file) from the data
directory for complete coverage. Supports MA-L (24-bit), MA-M (28-bit) and
MA-S (36-bit) assignments.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path

log = logging.getLogger(__name__)

# Common access-point and client vendors. Enough to be useful with zero setup.
BUILTIN: dict[str, str] = {
    "002586": "Ubiquiti", "0015 6d": "Ubiquiti", "00156d": "Ubiquiti",
    "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti", "68d79a": "Ubiquiti",
    "788a20": "Ubiquiti", "802aa8": "Ubiquiti", "b4fbe4": "Ubiquiti",
    "dc9fdb": "Ubiquiti", "e0631d": "Ubiquiti", "f09fc2": "Ubiquiti",
    "fcecda": "Ubiquiti", "74acb9": "Ubiquiti", "d021f9": "Ubiquiti",
    "18e829": "Ubiquiti", "245a4c": "Ubiquiti", "9c05d6": "Ubiquiti",
    "704ff8": "Ubiquiti", "e438832": "Ubiquiti",
    "000c29": "VMware", "005056": "VMware", "001c14": "VMware",
    "080027": "Oracle VirtualBox", "0a0027": "Oracle VirtualBox",
    "00155d": "Microsoft Hyper-V", "0050f2": "Microsoft",
    "001a11": "Google", "3c5ab4": "Google", "f4f5d8": "Google",
    "6466b3": "Google", "d84c90": "Google", "a4778b": "Google",
    "001b63": "Apple", "0017f2": "Apple", "3c0754": "Apple",
    "7cd1c3": "Apple", "a4b197": "Apple", "f0989d": "Apple",
    "dc2b2a": "Apple", "9801a7": "Apple", "b8e856": "Apple",
    "001d0f": "TP-Link", "5c63bf": "TP-Link", "b0be76": "TP-Link",
    "a42bb0": "TP-Link", "9c5322": "TP-Link", "3c84f6": "TP-Link",
    "5cf9dd": "Dell", "b083fe": "Dell", "18dbf2": "Dell", "d067e5": "Dell",
    "0018f3": "ASUSTek", "1c872c": "ASUSTek", "382c4a": "ASUSTek",
    "f832e4": "ASUSTek", "d850e6": "ASUSTek", "2c4d54": "ASUSTek",
    "001e2a": "NETGEAR", "204e7f": "NETGEAR", "a00460": "NETGEAR",
    "9c3dcf": "NETGEAR", "b03956": "NETGEAR", "cc40d0": "NETGEAR",
    "000c41": "Linksys", "c0562d": "Linksys", "48f8b3": "Linksys",
    "0024b2": "Netgear", "001f33": "Netgear",
    "00408c": "Axis", "000b86": "Aruba/HPE", "6cf37f": "Aruba/HPE",
    "94b40f": "Aruba/HPE", "204c03": "Aruba/HPE", "9c1c12": "Aruba/HPE",
    "d8c7c8": "Aruba/HPE", "186472": "Aruba/HPE", "b4b5fe": "Aruba/HPE",
    "004096": "Cisco Aironet", "0022bd": "Cisco", "00235e": "Cisco",
    "1ce6c7": "Cisco", "588d09": "Cisco", "70df2f": "Cisco",
    "e8ba70": "Cisco", "f07f06": "Cisco", "bc16f5": "Cisco",
    "00fd45": "Cisco Meraki", "e0cb bc": "Cisco Meraki", "88153": "Cisco Meraki",
    "0018 0a": "Cisco Meraki", "00180a": "Cisco Meraki", "ac17c8": "Cisco Meraki",
    "e0553d": "Cisco Meraki", "342c c4": "Cisco Meraki",
    "d4ca6d": "Routerboard/MikroTik", "4c5e0c": "MikroTik",
    "6c3b6b": "MikroTik", "dc2c6e": "MikroTik", "2cc81b": "MikroTik",
    "748114": "Ruckus", "c4013":  "Ruckus", "8ccda8": "Ruckus",
    "0013 92": "Ruckus", "001392": "Ruckus", "204c9e": "Ruckus",
    "e81d a8": "Ruckus", "58935d": "Ruckus",
    "001018": "Broadcom", "0090 4c": "Broadcom", "00904c": "Broadcom",
    "00e04c": "Realtek", "525400": "QEMU/KVM",
    "18fe34": "Espressif", "246f28": "Espressif", "3c6105": "Espressif",
    "8caab5": "Espressif", "a4cf12": "Espressif", "c45bbe": "Espressif",
    "0c8ddb": "MediaTek", "000ce7": "MediaTek", "d8324c": "MediaTek",
    "00037f": "Atheros", "001374": "Atheros",
    "000c43": "Ralink", "5c521e": "Sagemcom", "f8ab82": "Sagemcom",
    "3872c0": "Comtrend", "0026 f2": "Netgear",
    "687251": "D-Link", "1cbdb9": "D-Link", "b0c554": "D-Link",
    "78542e": "D-Link", "c0a0bb": "D-Link",
    "84d47e": "Aruba", "0021 d8": "Cisco", "40167e": "ASUSTek",
    "e4956e": "IEEE Registration Authority", "00cd fe": "Apple",
    "ac8112": "Sercomm", "44e137": "CommScope/ARRIS",
    "0026 5a": "D-Link", "a0f3c1": "TP-Link", "50c7bf": "TP-Link",
    "b4750e": "Belkin", "944452": "Belkin", "08863b": "Belkin",
    "001e58": "WildPackets", "20e52a": "NETGEAR",
    "6cb0ce": "NETGEAR", "38940": "NETGEAR",
    "3480 4f": "Hewlett Packard", "3c2af4": "Brother",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "d83add": "Raspberry Pi", "2ccf67": "Raspberry Pi",
    "00c0ca": "Alfa Network", "00c0 ca": "Alfa Network",
}


class OuiDatabase:
    """Vendor lookup over MA-L / MA-M / MA-S prefixes."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._mal: dict[str, str] = {}
        self._mam: dict[str, str] = {}
        self._mas: dict[str, str] = {}
        self._source = "builtin"
        self._load_builtin()

    def _load_builtin(self) -> None:
        for prefix, vendor in BUILTIN.items():
            clean = re.sub(r"[^0-9a-fA-F]", "", prefix).lower()
            if len(clean) >= 6:
                self._mal[clean[:6]] = vendor

    @property
    def source(self) -> str:
        return self._source

    @property
    def size(self) -> int:
        return len(self._mal) + len(self._mam) + len(self._mas)

    def load_file(self, path: Path) -> int:
        """Load a Wireshark `manuf` file or an IEEE CSV/TXT registry."""
        if not path.exists():
            raise FileNotFoundError(path)
        mal: dict[str, str] = {}
        mam: dict[str, str] = {}
        mas: dict[str, str] = {}
        count = 0

        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = _parse_oui_line(line)
            if not entry:
                continue
            prefix, bits, vendor = entry
            if bits <= 24:
                mal[prefix[:6]] = vendor
            elif bits <= 28:
                mam[prefix[:7]] = vendor
            else:
                mas[prefix[:9]] = vendor
            count += 1

        if count == 0:
            raise ValueError(f"No vendor records found in {path.name}")

        with self._lock:
            self._mal.update(mal)
            self._mam.update(mam)
            self._mas.update(mas)
            self._source = path.name
        log.info("Loaded %d vendor prefixes from %s", count, path.name)
        return count

    def lookup(self, mac: str) -> str | None:
        clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
        if len(clean) < 6:
            return None
        with self._lock:
            # Most specific first.
            if len(clean) >= 9 and clean[:9] in self._mas:
                return self._mas[clean[:9]]
            if len(clean) >= 7 and clean[:7] in self._mam:
                return self._mam[clean[:7]]
            return self._mal.get(clean[:6])


def _parse_oui_line(line: str) -> tuple[str, int, str] | None:
    """Handle both `manuf` (AA:BB:CC[/28]<tab>Short<tab>Long) and IEEE CSV rows."""
    # IEEE CSV: Registry,Assignment,Organization Name,Organization Address
    if "," in line and line.count(",") >= 2 and line.startswith(("0", "1", "2", "3",
                                                                    "4", "5", "6", "7",
                                                                    "8", "9", "A", "B",
                                                                    "C", "D", "E", "F")) is not False:
        parts = _split_csv(line)
        if len(parts) >= 3 and parts[0].upper() in {"MA-L", "MA-M", "MA-S", "IAB"}:
            assignment = re.sub(r"[^0-9a-fA-F]", "", parts[1]).lower()
            vendor = parts[2].strip().strip('"')
            if not assignment or not vendor:
                return None
            bits = {"MA-L": 24, "MA-M": 28, "MA-S": 36, "IAB": 36}[parts[0].upper()]
            return assignment, bits, vendor

    # manuf format
    m = re.match(r"^([0-9A-Fa-f:.\-]+)(?:/(\d+))?\s+(\S+)(?:\s+(.*))?$", line)
    if m:
        raw, bits_s, short, long_name = m.group(1), m.group(2), m.group(3), m.group(4)
        clean = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        if len(clean) < 6:
            return None
        bits = int(bits_s) if bits_s else 24
        vendor = (long_name or short).strip()
        if not vendor:
            return None
        return clean, bits, vendor
    return None


def _split_csv(line: str) -> list[str]:
    """Minimal CSV splitter that respects double quotes."""
    out, cur, in_quotes = [], [], False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            if in_quotes and i + 1 < len(line) and line[i + 1] == '"':
                cur.append('"')
                i += 1
            else:
                in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur))
    return out


def is_locally_administered(mac: str) -> bool:
    """True when the U/L bit is set, which usually means a randomised MAC."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) < 2:
        return False
    try:
        return bool(int(clean[:2], 16) & 0x02)
    except ValueError:
        return False


def is_multicast(mac: str) -> bool:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) < 2:
        return False
    try:
        return bool(int(clean[:2], 16) & 0x01)
    except ValueError:
        return False


def normalise(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) != 12:
        return mac.lower()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


db = OuiDatabase()


def autoload(data_dir: Path) -> None:
    """Pick up a vendor file dropped in the data directory, if present."""
    for name in ("manuf", "manuf.txt", "oui.csv", "oui.txt"):
        candidate = data_dir / name
        if candidate.exists():
            try:
                db.load_file(candidate)
                return
            except Exception as exc:
                log.warning("Could not load %s: %s", candidate, exc)
