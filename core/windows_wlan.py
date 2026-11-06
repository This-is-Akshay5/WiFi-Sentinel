"""Windows Native WLAN API scan support.

Uses WlanGetNetworkBssList so nearby APs are taken from per-BSSID OS scan
records. This module imports ctypes only on demand and remains importable on
macOS/Linux for parser tests.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import time

DWORD = ctypes.c_uint32
ULONG = ctypes.c_uint32
LONG = ctypes.c_int32
USHORT = ctypes.c_uint16
WCHAR16 = ctypes.c_uint16


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ULONG), ("ucSSID", ctypes.c_ubyte * 32)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", ctypes.c_byte * 16),
                ("strInterfaceDescription", WCHAR16 * 256), ("isState", DWORD)]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", ULONG), ("usRateSet", ctypes.c_ushort * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID), ("uPhyId", ULONG),
        ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11BssType", DWORD),
        ("dot11BssPhyType", ctypes.c_uint32), ("lRssi", LONG),
        ("uLinkQuality", ULONG), ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", USHORT), ("ullTimestamp", ctypes.c_uint64),
        ("ullHostTimestamp", ctypes.c_uint64), ("usCapabilityInformation", USHORT),
        ("ulChCenterFrequency", ULONG), ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ULONG), ("ulIeSize", ULONG),
    ]


_INTERFACE_STATES = {
    0: "not_ready", 1: "connected", 2: "ad_hoc_network_formed", 3: "disconnecting",
    4: "disconnected", 5: "associating", 6: "discovering", 7: "authenticating",
}


def _interface_name(item, index):
    raw = bytes(item.strInterfaceDescription)
    return raw.decode("utf-16-le", errors="replace").split("\0", 1)[0].strip() or f"Wi-Fi interface {index + 1}"


def _channel(frequency_khz):
    mhz = frequency_khz / 1000
    if 2412 <= mhz <= 2472 and (mhz - 2407) % 5 == 0:
        return (int((mhz - 2407) / 5), 2.4)
    if mhz == 2484:
        return 14, 2.4
    if 5000 <= mhz < 5925 and mhz % 5 == 0:
        return int((mhz - 5000) / 5), 5.0
    if 5925 <= mhz <= 7125 and (mhz - 5950) % 5 == 0:
        return int((mhz - 5950) / 5), 6.0
    return None, None


def _security(ies, privacy):
    """Read advertised RSN suite selectors; malformed IEs stay unknown."""
    ciphers, akms = set(), set()
    rsn_seen = False
    legacy_wpa_seen = False
    pos = 0
    while pos + 2 <= len(ies):
        element_id, length = ies[pos], ies[pos + 1]
        pos += 2
        if pos + length > len(ies):
            break
        body = ies[pos:pos + length]
        pos += length
        if element_id == 221 and body.startswith(b"\x00\x50\xf2\x01"):
            legacy_wpa_seen = True
        if element_id != 48 or length < 8:  # RSN information element
            continue
        rsn_seen = True
        try:
            cursor = 2  # version
            group = body[cursor + 3]
            cursor += 4
            pair_count = int.from_bytes(body[cursor:cursor + 2], "little")
            cursor += 2
            pair_suites = [body[cursor + 4 * i + 3] for i in range(pair_count)]
            cursor += 4 * pair_count
            akm_count = int.from_bytes(body[cursor:cursor + 2], "little")
            cursor += 2
            akm_suites = [body[cursor + 4 * i + 3] for i in range(akm_count)]
            ciphers.update([group, *pair_suites])
            akms.update(akm_suites)
        except (IndexError, ValueError):
            return None, None
        break
    cipher_names = {2: "TKIP", 4: "CCMP", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
    cipher = "/".join(sorted({cipher_names[x] for x in ciphers if x in cipher_names})) or None
    if akms.intersection({8, 9}):
        auth = "WPA3 Personal"
    elif akms.intersection({1, 3, 5, 11, 12, 13, 14}):
        auth = "WPA2 Enterprise"
    elif akms.intersection({2, 4, 6, 7}):
        auth = "WPA2 Personal"
    elif ciphers:
        auth = "WPA2 (AKM not classified)"
    elif legacy_wpa_seen:
        auth = "WPA (legacy; suites not classified)"
    elif rsn_seen:
        auth = "RSN advertised; suites not classified"
    elif privacy:
        auth = "Legacy protected (WEP or WPA not classified)"
    else:
        auth = "Open"
    return auth, cipher


_IE_NAMES = {0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM",
             7: "Country", 32: "Power Constraint", 45: "HT Capabilities",
             48: "RSN", 50: "Extended Supported Rates", 61: "HT Operation",
             191: "VHT Capabilities", 192: "VHT Operation", 201: "RSNXE",
             255: "Extension"}


def _information_elements(ies):
    """Return bounded IE summaries and explicit SSID/PMF evidence."""
    items, ssid_seen, ssid_hidden, pmf = [], False, False, None
    pos = 0
    while pos + 2 <= len(ies) and len(items) < 256:
        element_id, length = ies[pos], ies[pos + 1]
        pos += 2
        if pos + length > len(ies):
            break
        body = ies[pos:pos + length]
        pos += length
        items.append({"id": element_id, "name": _IE_NAMES.get(element_id, "Element"), "length": length})
        if element_id == 0:
            ssid_seen = True
            ssid_hidden = length == 0
        if element_id == 48:
            try:
                offset = 2 + 4
                pairwise_count = int.from_bytes(body[offset:offset + 2], "little")
                offset += 2 + 4 * pairwise_count
                akm_count = int.from_bytes(body[offset:offset + 2], "little")
                offset += 2 + 4 * akm_count
                if offset + 2 <= len(body):
                    capabilities = int.from_bytes(body[offset:offset + 2], "little")
                    pmf = {"advertised_capable": bool(capabilities & (1 << 7)),
                           "advertised_required": bool(capabilities & (1 << 6)),
                           "negotiated_or_enforced": "unknown"}
            except (IndexError, ValueError, OverflowError):
                pmf = None
    return items, ssid_seen, ssid_hidden, pmf


_PHY_NAMES = {1: "802.11 FHSS", 2: "802.11 DSSS", 3: "802.11 IR", 4: "802.11a",
              5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac",
              9: "802.11ad", 10: "802.11ax", 11: "802.11be"}
_CAPABILITY_FLAGS = {0x0001: "ESS", 0x0002: "IBSS", 0x0004: "CF Pollable",
                     0x0008: "CF Poll Request", 0x0010: "Privacy", 0x0020: "Short Preamble",
                     0x0040: "PBCC", 0x0080: "Channel Agility", 0x0100: "Spectrum Management",
                     0x0200: "QoS", 0x0400: "Short Slot Time", 0x0800: "APSD",
                     0x1000: "Radio Measurement", 0x2000: "DSSS-OFDM",
                     0x4000: "Delayed Block Ack", 0x8000: "Immediate Block Ack"}


def _decode_entry(entry, entry_address, list_start, total_size, interface):
    ssid_len = int(entry.dot11Ssid.uSSIDLength)
    if not 0 <= ssid_len <= 32:
        return None
    ssid_bytes = bytes(entry.dot11Ssid.ucSSID[:ssid_len])
    ssid = ssid_bytes.decode("utf-8", errors="replace") if ssid_len else None
    offset, size = int(entry.ulIeOffset), int(entry.ulIeSize)
    # Validate offsets before dereferencing the OS-allocated buffer.
    start = entry_address + offset
    end = start + size
    if (size > 2324 or offset < ctypes.sizeof(WLAN_BSS_ENTRY) or start < list_start
            or end > list_start + total_size or start < entry_address):
        ies = b""
    else:
        ies = ctypes.string_at(start, size)
    information_elements, ssid_ie_seen, ssid_ie_hidden, pmf = _information_elements(ies)
    privacy = bool(int(entry.usCapabilityInformation) & 0x0010)
    auth, cipher = _security(ies, privacy)
    frequency_khz = int(entry.ulChCenterFrequency)
    channel, band = _channel(frequency_khz)
    bssid = ":".join(f"{value:02X}" for value in entry.dot11Bssid)
    if not bssid or bssid == "00:00:00:00:00:00":
        return None
    rate_count = min(int(entry.wlanRateSet.uRateSetLength), len(entry.wlanRateSet.usRateSet))
    rates = sorted({(int(entry.wlanRateSet.usRateSet[i]) & 0x7FFF) / 2
                    for i in range(rate_count)})
    capability = int(entry.usCapabilityInformation)
    phy_type = int(entry.dot11BssPhyType)
    return {
        "ssid": ssid, "ssid_data_hex": ssid_bytes.hex() if ssid_bytes else None,
        "ssid_observed": bool(ssid_len or ssid_ie_seen),
        "ssid_hidden": bool(ssid_ie_seen and ssid_ie_hidden),
        "bssid": bssid, "signal_dbm": int(entry.lRssi),
        "signal_pct": int(entry.uLinkQuality) if int(entry.uLinkQuality) <= 100 else None,
        "auth": auth, "cipher": cipher, "radio_type": _PHY_NAMES.get(phy_type), "channel": channel,
        "frequency_ghz": frequency_khz / 1_000_000 if frequency_khz else None,
        "beacon_interval_ms": int(entry.usBeaconPeriod) or None,
        "supported_rates_mbps": rates or None,
        "capability_flags": [label for bit, label in _CAPABILITY_FLAGS.items() if capability & bit],
        "information_elements": information_elements or None,
        "pmf_advertisement": pmf,
        "band": band, "interface": interface, "source": "Windows Native WLAN API",
        "vendor": None, "vendor_note": "Not derivable offline (no OUI database bundled)",
        "client_count": None, "client_count_note": "Not exposed by Windows WLAN scan",
    }


class WindowsWLAN:
    """Small, bounded wrapper around wlanapi.dll; native scan results only."""

    def __init__(self, api=None, settle_seconds=1.0):
        self.api = api
        self.settle_seconds = max(0.0, min(float(settle_seconds), 2.0))

    def _api(self):
        if self.api is not None:
            return self.api
        if not hasattr(ctypes, "WinDLL"):
            raise OSError("Windows WLAN API is only available on Windows.")
        return ctypes.WinDLL("wlanapi.dll")

    @staticmethod
    def _guid(raw):
        return ctypes.cast(raw, ctypes.POINTER(ctypes.c_byte * 16)).contents

    def scan(self):
        api = self._api()
        handle = wintypes.HANDLE()
        version = DWORD()
        open_status = api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle))
        if open_status:
            raise OSError(int(open_status), "WlanOpenHandle failed")
        allocations = []
        try:
            interface_list = ctypes.c_void_p()
            status = api.WlanEnumInterfaces(handle, None, ctypes.byref(interface_list))
            if status:
                raise OSError(int(status), "WlanEnumInterfaces failed")
            allocations.append(interface_list)
            base = interface_list.value
            if not base:
                return [], [], "Windows WLAN returned no interface list."
            count = ctypes.cast(base, ctypes.POINTER(DWORD)).contents.value
            count = min(int(count), 64)
            records, aps, errors = [], [], []
            first = base + ctypes.sizeof(DWORD) * 2
            stride = ctypes.sizeof(WLAN_INTERFACE_INFO)
            for index in range(count):
                address = first + index * stride
                item = ctypes.cast(address, ctypes.POINTER(WLAN_INTERFACE_INFO)).contents
                guid = self._guid(ctypes.addressof(item))
                name = _interface_name(item, index)
                state = _INTERFACE_STATES.get(int(item.isState), "unknown")
                records.append({"name": name, "description": name, "guid": bytes(guid).hex(), "state": state})
                if state == "not_ready":
                    continue
                try:
                    api.WlanScan(handle, ctypes.byref(item.InterfaceGuid), None, None, None)
                except Exception:
                    pass
            if records and self.settle_seconds:
                time.sleep(self.settle_seconds)
            for index in range(count):
                address = first + index * stride
                item = ctypes.cast(address, ctypes.POINTER(WLAN_INTERFACE_INFO)).contents
                state = _INTERFACE_STATES.get(int(item.isState), "unknown")
                if state == "not_ready":
                    continue
                name = _interface_name(item, index)
                bss_list = ctypes.c_void_p()
                status = api.WlanGetNetworkBssList(handle, ctypes.byref(item.InterfaceGuid), None, 3, False,
                                                    None, ctypes.byref(bss_list))
                if status:
                    errors.append(f"{name}: WlanGetNetworkBssList returned {int(status)}")
                    continue
                allocations.append(bss_list)
                if not bss_list.value:
                    continue
                total_size, entries_count = ctypes.cast(bss_list, ctypes.POINTER(DWORD * 2)).contents
                total_size, entries_count = int(total_size), min(int(entries_count), 4096)
                entries_base = bss_list.value + ctypes.sizeof(DWORD) * 2
                available = max(0, total_size - ctypes.sizeof(DWORD) * 2)
                entries_count = min(entries_count, available // ctypes.sizeof(WLAN_BSS_ENTRY))
                for row in range(entries_count):
                    entry_address = entries_base + row * ctypes.sizeof(WLAN_BSS_ENTRY)
                    entry = ctypes.cast(entry_address, ctypes.POINTER(WLAN_BSS_ENTRY)).contents
                    decoded = _decode_entry(entry, entry_address, bss_list.value, total_size, name)
                    if decoded:
                        aps.append(decoded)
            unique = {}
            for ap in aps:
                unique.setdefault((ap["interface"], ap["bssid"]), ap)
            error = "; ".join(errors) if errors and not unique else None
            if not records:
                error = "Windows WLAN reports no enabled wireless interfaces."
            return records, sorted(unique.values(), key=lambda ap: (ap["signal_dbm"] is None,
                           -(ap["signal_dbm"] or -999))), error
        finally:
            for pointer in allocations:
                if pointer:
                    try:
                        api.WlanFreeMemory(pointer)
                    except Exception:
                        pass
            try:
                api.WlanCloseHandle(handle, None)
            except Exception:
                pass
