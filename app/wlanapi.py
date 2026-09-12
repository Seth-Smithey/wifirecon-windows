"""
Native Wifi (wlanapi.dll) bindings via ctypes.

This is the only module that touches Windows APIs directly. Everything above it
works on plain dicts so the rest of the app can be developed and tested on any
platform against the mock source in tools/mock_source.py.

Key call we care about is WlanGetNetworkBssList: unlike `netsh wlan show networks`
it hands back the raw information-element blob from each beacon / probe response,
which is where RSN, WPS, HT/VHT/HE and vendor data actually live.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import POINTER, Structure, byref, c_void_p, sizeof
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LONG,
    ULONG,
    USHORT,
    WCHAR,
)
from typing import Any

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ERROR_SUCCESS = 0
ERROR_INVALID_PARAMETER = 87
ERROR_NDIS_DOT11_MEDIA_IN_USE = 2150899714
ERROR_NDIS_DOT11_POWER_STATE_INVALID = 2150899715
ERROR_BUSY = 170
ERROR_ACCESS_DENIED = 5
ERROR_SERVICE_NOT_ACTIVE = 1062

WLAN_API_VERSION_2_0 = 2

# DOT11_BSS_TYPE
DOT11_BSS_TYPE_INFRASTRUCTURE = 1
DOT11_BSS_TYPE_INDEPENDENT = 2
DOT11_BSS_TYPE_ANY = 3

# WLAN_INTERFACE_STATE
INTERFACE_STATE = {
    0: "not_ready",
    1: "connected",
    2: "ad_hoc_network_formed",
    3: "disconnecting",
    4: "disconnected",
    5: "associating",
    6: "discovering",
    7: "authenticating",
}

# DOT11_PHY_TYPE
PHY_TYPE = {
    0: "unknown",
    1: "fhss",
    2: "dsss",
    3: "irbaseband",
    4: "ofdm",          # 802.11a
    5: "hrdsss",        # 802.11b
    6: "erp",           # 802.11g
    7: "ht",            # 802.11n
    8: "vht",           # 802.11ac
    9: "dmg",           # 802.11ad
    10: "he",           # 802.11ax
    11: "eht",          # 802.11be
}

WLAN_NOTIFICATION_SOURCE_NONE = 0

# WLAN_INTF_OPCODE
WLAN_INTF_OPCODE_INTERFACE_STATE = 5
WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
WLAN_INTF_OPCODE_CHANNEL_NUMBER = 8
WLAN_INTF_OPCODE_RADIO_STATE = 4
WLAN_INTF_OPCODE_CURRENT_OPERATION_MODE = 12

# DOT11_RADIO_STATE
RADIO_STATE = {0: "unknown", 1: "on", 2: "off"}

# Interface types reported by the capability query
INTERFACE_TYPE = {
    0: "emulated 802.11",
    1: "native 802.11",
    2: "unknown",
}

BAND_LABELS = {
    "2.4": "2.4 GHz",
    "5": "5 GHz",
    "6": "6 GHz",
}

# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------


class GUID(Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self) -> str:
        d4 = "".join(f"{b:02x}" for b in self.Data4)
        return f"{{{self.Data1:08x}-{self.Data2:04x}-{self.Data3:04x}-{d4[:4]}-{d4[4:]}}}"


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", WCHAR * 256),
        ("isState", ctypes.c_int),
    ]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [
        ("dwNumberOfItems", DWORD),
        ("dwIndex", DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class DOT11_SSID(Structure):
    _fields_ = [
        ("uSSIDLength", ULONG),
        ("ucSSID", ctypes.c_ubyte * 32),
    ]


class WLAN_RATE_SET(Structure):
    _fields_ = [
        ("uRateSetLength", ULONG),
        ("usRateSet", USHORT * 126),
    ]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", ULONG),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_int),
        ("dot11BssPhyType", ctypes.c_int),
        ("lRssi", LONG),
        ("uLinkQuality", ULONG),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", USHORT),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", USHORT),
        ("ulChCenterFrequency", ULONG),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ULONG),
        ("ulIeSize", ULONG),
    ]


class WLAN_BSS_LIST(Structure):
    _fields_ = [
        ("dwTotalSize", DWORD),
        ("dwNumberOfItems", DWORD),
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1),
    ]


class WLAN_INTERFACE_CAPABILITY(Structure):
    _fields_ = [
        ("interfaceType", ctypes.c_int),
        ("bDot11DSupported", BOOL),
        ("dwMaxDesiredSsidListSize", DWORD),
        ("dwMaxDesiredBssidListSize", DWORD),
        ("dwNumberOfSupportedPhys", DWORD),
        ("dot11PhyTypes", ctypes.c_int * 64),
    ]


class WLAN_RADIO_STATE(Structure):
    _fields_ = [
        ("dwNumberOfPhys", DWORD),
        ("PhyRadioState", ctypes.c_int * 192),   # 64 entries x 3 ints
    ]


class WLAN_RAW_DATA(Structure):
    _fields_ = [
        ("dwDataSize", DWORD),
        ("DataBlob", ctypes.c_ubyte * 1),
    ]


class WlanError(RuntimeError):
    """A wlanapi.dll call returned a non-zero status."""

    def __init__(self, func: str, code: int):
        self.func = func
        self.code = code
        super().__init__(f"{func} failed: {describe_error(code)} (0x{code:08X})")


def describe_error(code: int) -> str:
    known = {
        ERROR_SUCCESS: "success",
        ERROR_ACCESS_DENIED: "access denied - run as Administrator",
        ERROR_INVALID_PARAMETER: "invalid parameter",
        ERROR_BUSY: "adapter busy, another scan is in flight",
        ERROR_SERVICE_NOT_ACTIVE: "the WLAN AutoConfig service (wlansvc) is not running",
        1168: "element not found",
        1610: "the configuration data is invalid",
        ERROR_NDIS_DOT11_MEDIA_IN_USE: "radio is in use by another operation",
        ERROR_NDIS_DOT11_POWER_STATE_INVALID: "the radio is turned off",
    }
    if code in known:
        return known[code]
    if IS_WINDOWS:
        try:
            return ctypes.FormatError(code).strip()
        except Exception:  # pragma: no cover - defensive
            pass
    return "unknown error"


# ---------------------------------------------------------------------------
# Function prototypes
# ---------------------------------------------------------------------------

_wlanapi: Any = None


def _load() -> Any:
    global _wlanapi
    if _wlanapi is not None:
        return _wlanapi
    if not IS_WINDOWS:
        raise OSError("wlanapi.dll is only available on Windows")

    dll = ctypes.windll.LoadLibrary("wlanapi.dll")

    dll.WlanOpenHandle.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)]
    dll.WlanOpenHandle.restype = DWORD

    dll.WlanCloseHandle.argtypes = [HANDLE, c_void_p]
    dll.WlanCloseHandle.restype = DWORD

    dll.WlanFreeMemory.argtypes = [c_void_p]
    dll.WlanFreeMemory.restype = None

    dll.WlanEnumInterfaces.argtypes = [
        HANDLE,
        c_void_p,
        POINTER(POINTER(WLAN_INTERFACE_INFO_LIST)),
    ]
    dll.WlanEnumInterfaces.restype = DWORD

    dll.WlanScan.argtypes = [
        HANDLE,
        POINTER(GUID),
        POINTER(DOT11_SSID),
        POINTER(WLAN_RAW_DATA),
        c_void_p,
    ]
    dll.WlanScan.restype = DWORD

    dll.WlanGetInterfaceCapability.argtypes = [
        HANDLE, POINTER(GUID), c_void_p, POINTER(POINTER(WLAN_INTERFACE_CAPABILITY))
    ]
    dll.WlanGetInterfaceCapability.restype = DWORD

    dll.WlanQueryInterface.argtypes = [
        HANDLE, POINTER(GUID), ctypes.c_int, c_void_p,
        POINTER(DWORD), POINTER(c_void_p), POINTER(ctypes.c_int),
    ]
    dll.WlanQueryInterface.restype = DWORD

    dll.WlanGetNetworkBssList.argtypes = [
        HANDLE,
        POINTER(GUID),
        POINTER(DOT11_SSID),
        ctypes.c_int,
        BOOL,
        c_void_p,
        POINTER(POINTER(WLAN_BSS_LIST)),
    ]
    dll.WlanGetNetworkBssList.restype = DWORD

    _wlanapi = dll
    return dll


def available() -> bool:
    """True when the Native Wifi API can be loaded on this host."""
    if not IS_WINDOWS:
        return False
    try:
        _load()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Handle wrapper
# ---------------------------------------------------------------------------


class WlanHandle:
    """RAII wrapper around a WLAN client handle."""

    def __init__(self) -> None:
        self._dll = _load()
        self._handle = HANDLE()
        negotiated = DWORD()
        rc = self._dll.WlanOpenHandle(
            WLAN_API_VERSION_2_0, None, byref(negotiated), byref(self._handle)
        )
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanOpenHandle", rc)
        self.negotiated_version = negotiated.value
        self._closed = False

    @property
    def handle(self) -> HANDLE:
        if self._closed:
            raise RuntimeError("WLAN handle already closed")
        return self._handle

    def close(self) -> None:
        if not self._closed:
            try:
                self._dll.WlanCloseHandle(self._handle, None)
            finally:
                self._closed = True

    def __enter__(self) -> WlanHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass

    # -- operations ---------------------------------------------------------

    def interfaces(self) -> list[dict]:
        ptr = POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = self._dll.WlanEnumInterfaces(self.handle, None, byref(ptr))
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanEnumInterfaces", rc)
        try:
            count = ptr.contents.dwNumberOfItems
            array = ctypes.cast(
                ctypes.addressof(ptr.contents.InterfaceInfo),
                POINTER(WLAN_INTERFACE_INFO * count),
            ).contents
            out = []
            for item in array:
                out.append(
                    {
                        "guid": str(item.InterfaceGuid),
                        "_guid_struct": GUID.from_buffer_copy(item.InterfaceGuid),
                        "description": item.strInterfaceDescription,
                        "state": INTERFACE_STATE.get(item.isState, f"unknown({item.isState})"),
                    }
                )
            return out
        finally:
            self._dll.WlanFreeMemory(ptr)

    def scan(self, guid: GUID) -> None:
        """Ask the driver to run a fresh scan. Asynchronous - results land in the
        BSS list a few seconds later. Windows rate-limits this to roughly four
        per minute per interface; exceeding it returns ERROR_BUSY."""
        rc = self._dll.WlanScan(self.handle, byref(guid), None, None, None)
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanScan", rc)

    def capability(self, guid: GUID) -> dict:
        """Supported PHY types and list sizes. Tells us which bands the radio
        can actually see, which is how we identify a 6 GHz-capable adapter."""
        ptr = POINTER(WLAN_INTERFACE_CAPABILITY)()
        rc = self._dll.WlanGetInterfaceCapability(self.handle, byref(guid), None, byref(ptr))
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanGetInterfaceCapability", rc)
        try:
            cap = ptr.contents
            count = min(cap.dwNumberOfSupportedPhys, 64)
            phys = [PHY_TYPE.get(cap.dot11PhyTypes[i], f"unknown({cap.dot11PhyTypes[i]})")
                    for i in range(count)]
            return {
                "interface_type": INTERFACE_TYPE.get(cap.interfaceType, "unknown"),
                "supports_dot11d": bool(cap.bDot11DSupported),
                "max_ssid_list": cap.dwMaxDesiredSsidListSize,
                "max_bssid_list": cap.dwMaxDesiredBssidListSize,
                "phy_types": phys,
                "phy_count": count,
            }
        finally:
            self._dll.WlanFreeMemory(ptr)

    def radio_state(self, guid: GUID) -> dict:
        """Whether the radio is on, and whether software or hardware turned it off."""
        size = DWORD()
        data = c_void_p()
        opcode_type = ctypes.c_int()
        rc = self._dll.WlanQueryInterface(
            self.handle, byref(guid), WLAN_INTF_OPCODE_RADIO_STATE, None,
            byref(size), byref(data), byref(opcode_type),
        )
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanQueryInterface(radio_state)", rc)
        try:
            state = ctypes.cast(data, POINTER(WLAN_RADIO_STATE)).contents
            count = min(state.dwNumberOfPhys, 64)
            radios = []
            for i in range(count):
                base = i * 3
                radios.append({
                    "phy_index": state.PhyRadioState[base],
                    "software": RADIO_STATE.get(state.PhyRadioState[base + 1], "unknown"),
                    "hardware": RADIO_STATE.get(state.PhyRadioState[base + 2], "unknown"),
                })
            on = any(r["software"] == "on" and r["hardware"] == "on" for r in radios)
            return {"radios": radios, "on": on, "count": count}
        finally:
            self._dll.WlanFreeMemory(data)

    def channel(self, guid: GUID) -> int | None:
        size = DWORD()
        data = c_void_p()
        opcode_type = ctypes.c_int()
        rc = self._dll.WlanQueryInterface(
            self.handle, byref(guid), WLAN_INTF_OPCODE_CHANNEL_NUMBER, None,
            byref(size), byref(data), byref(opcode_type),
        )
        if rc != ERROR_SUCCESS:
            return None
        try:
            return int(ctypes.cast(data, POINTER(ULONG)).contents.value)
        finally:
            self._dll.WlanFreeMemory(data)

    def bss_list(self, guid: GUID) -> list[dict]:
        """Return the driver's cached BSS list, including raw IE blobs."""
        ptr = POINTER(WLAN_BSS_LIST)()
        rc = self._dll.WlanGetNetworkBssList(
            self.handle,
            byref(guid),
            None,
            DOT11_BSS_TYPE_ANY,
            False,
            None,
            byref(ptr),
        )
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanGetNetworkBssList", rc)
        try:
            return _decode_bss_list(ptr)
        finally:
            self._dll.WlanFreeMemory(ptr)


def _decode_bss_list(ptr) -> list[dict]:
    blist = ptr.contents
    count = blist.dwNumberOfItems
    if count == 0:
        return []

    entries_addr = ctypes.addressof(blist.wlanBssEntries)
    total_size = blist.dwTotalSize
    list_base = ctypes.addressof(blist)
    results: list[dict] = []

    for i in range(count):
        entry_addr = entries_addr + i * sizeof(WLAN_BSS_ENTRY)
        # Guard against a malformed list walking us off the allocation.
        if entry_addr + sizeof(WLAN_BSS_ENTRY) > list_base + total_size:
            log.warning("BSS list truncated at entry %d of %d", i, count)
            break
        entry = WLAN_BSS_ENTRY.from_address(entry_addr)

        ssid_len = min(entry.dot11Ssid.uSSIDLength, 32)
        ssid_bytes = bytes(entry.dot11Ssid.ucSSID[:ssid_len])
        bssid = ":".join(f"{b:02x}" for b in entry.dot11Bssid)

        ie = b""
        if entry.ulIeSize:
            ie_addr = entry_addr + entry.ulIeOffset
            if ie_addr + entry.ulIeSize <= list_base + total_size:
                ie = ctypes.string_at(ie_addr, entry.ulIeSize)
            else:
                log.warning("IE blob for %s exceeds the reported list size", bssid)

        rates = []
        rate_len = min(entry.wlanRateSet.uRateSetLength, 126)
        for r in entry.wlanRateSet.usRateSet[:rate_len]:
            # Bit 15 marks a basic rate; low bits are the rate in 500 kbps units.
            value = r & 0x7FFF
            if value:
                rates.append({"mbps": value * 0.5, "basic": bool(r & 0x8000)})

        results.append(
            {
                "bssid": bssid,
                "ssid_bytes": ssid_bytes,
                "phy_type": PHY_TYPE.get(entry.dot11BssPhyType, "unknown"),
                "bss_type": "infrastructure"
                if entry.dot11BssType == DOT11_BSS_TYPE_INFRASTRUCTURE
                else "independent",
                "rssi": entry.lRssi,
                "link_quality": entry.uLinkQuality,
                "in_reg_domain": bool(entry.bInRegDomain),
                "beacon_period": entry.usBeaconPeriod,
                "timestamp": entry.ullTimestamp,
                "host_timestamp": entry.ullHostTimestamp,
                "capability": entry.usCapabilityInformation,
                "freq_khz": entry.ulChCenterFrequency,
                "rates": rates,
                "ie": ie,
            }
        )
    return results
