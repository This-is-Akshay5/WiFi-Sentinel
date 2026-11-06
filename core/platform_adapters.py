"""Operating-system adapters for Wi-Fi and local neighbor observations.

Adapters expose only values returned by the host OS. A missing command, field,
or permission produces an unavailable value and an explanatory state.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import time


class MacOSAdapter:
    """macOS discovery using networksetup, ifconfig, route, arp and airport."""

    def __init__(self, engine):
        self.engine = engine
        self._interfaces_cache = None
        self._interfaces_cache_at = 0.0

    @staticmethod
    def _corewlan():
        try:
            import CoreWLAN
            return CoreWLAN, CoreWLAN.CWWiFiClient.sharedWiFiClient()
        except Exception:
            return None, None

    @staticmethod
    def _objc_value(obj, name, default=None):
        try:
            value = getattr(obj, name)
            return value() if callable(value) else value
        except Exception:
            return default

    @staticmethod
    def _security_label(value):
        names = {
            0: ("Open", "None"), 1: ("WEP", "WEP"), 2: ("WPA Personal", None),
            3: ("WPA/WPA2 Personal", None), 4: ("WPA2 Personal", None),
            5: ("Personal", None), 6: ("Dynamic WEP", "WEP"),
            7: ("WPA Enterprise", None), 8: ("WPA/WPA2 Enterprise", None),
            9: ("WPA2 Enterprise", None), 10: ("Enterprise", None),
            11: ("WPA3 Personal", None), 12: ("WPA3 Enterprise", None),
            13: ("WPA3 Transition", None), 14: ("OWE", None), 15: ("OWE Transition", None),
        }
        if value is None:
            return None, None
        try:
            return names.get(int(value), (None, None))
        except (TypeError, ValueError):
            return None, None

    @staticmethod
    def _channel_data(channel):
        if channel is None:
            return None, None
        number = MacOSAdapter._objc_value(channel, "channelNumber")
        band_id = MacOSAdapter._objc_value(channel, "channelBand")
        try:
            number = int(number) if number is not None else None
        except (TypeError, ValueError):
            number = None
        try:
            band_id = int(band_id) if band_id is not None else None
        except (TypeError, ValueError):
            band_id = None
        band = {1: 2.4, 2: 5.0, 3: 6.0}.get(band_id)
        return number, band

    @staticmethod
    def _information_elements(data):
        """Expose IE identity/length only and conservative RSN PMF advertisement."""
        names = {0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM",
                 7: "Country", 45: "HT Capabilities", 48: "RSN", 50: "Extended Rates",
                 61: "HT Operation", 191: "VHT Capabilities", 192: "VHT Operation", 201: "RSNXE"}
        if data is None:
            return None, False, False, None
        try:
            raw = bytes(data)
        except (TypeError, ValueError):
            return None, False, False, None
        result, ssid_seen, ssid_hidden, pmf = [], False, False, None
        offset = 0
        while offset + 2 <= len(raw) and len(result) < 256:
            element_id, length = raw[offset], raw[offset + 1]
            offset += 2
            if offset + length > len(raw):
                break
            body = raw[offset:offset + length]
            offset += length
            result.append({"id": element_id, "name": names.get(element_id, "Element"), "length": length})
            if element_id == 0:
                ssid_seen, ssid_hidden = True, length == 0
            if element_id == 48:
                try:
                    cursor = 6
                    pairwise_count = int.from_bytes(body[cursor:cursor + 2], "little")
                    cursor += 2 + 4 * pairwise_count
                    akm_count = int.from_bytes(body[cursor:cursor + 2], "little")
                    cursor += 2 + 4 * akm_count
                    if cursor + 2 <= len(body):
                        capabilities = int.from_bytes(body[cursor:cursor + 2], "little")
                        pmf = {"advertised_capable": bool(capabilities & (1 << 7)),
                               "advertised_required": bool(capabilities & (1 << 6)),
                               "negotiated_or_enforced": "unknown"}
                except (IndexError, ValueError, OverflowError):
                    pmf = None
        return result or None, ssid_seen, ssid_hidden, pmf

    def _corewlan_records(self):
        """Discover the adapter through Apple's CoreWLAN API when PyObjC is installed."""
        corewlan, client = self._corewlan()
        if not client:
            return None, None
        try:
            names = self._objc_value(client, "interfaceNames") or []
            records = []
            for name in names:
                interface = client.interfaceWithName_(name)
                power = self._objc_value(interface, "powerOn") if interface else None
                enabled = bool(power) if power is not None else True
                records.append({"name": str(name), "description": "Wi-Fi", "guid": None,
                                "state": "available" if enabled else "disabled", "radio": None})
            return records, None
        except Exception as exc:
            return None, str(exc)

    def _corewlan_scan(self, name):
        corewlan, client = self._corewlan()
        if not client:
            return None, "CoreWLAN is unavailable."
        try:
            interface = client.interfaceWithName_(name)
            if interface is None:
                return None, "CoreWLAN did not expose the selected Wi-Fi interface."
            if hasattr(interface, "scanForNetworksWithSSID_includeHidden_error_"):
                scan_method = "CoreWLAN scanForNetworksWithSSID(includeHidden=True)"
                result = interface.scanForNetworksWithSSID_includeHidden_error_(None, True, None)
            elif hasattr(interface, "scanForNetworksWithName_includeHidden_error_"):
                scan_method = "CoreWLAN scanForNetworksWithName(includeHidden=True)"
                result = interface.scanForNetworksWithName_includeHidden_error_(None, True, None)
            elif hasattr(interface, "scanForNetworksWithName_error_"):
                scan_method = "CoreWLAN scanForNetworksWithName"
                result = interface.scanForNetworksWithName_error_(None, None)
            else:
                return None, "CoreWLAN does not expose a supported general network scan method."
            error = None
            if isinstance(result, tuple):
                result, error = result[0], result[1]
            if error:
                return None, str(error)
            aps = []
            for network in result or []:
                native_ssid = self._objc_value(network, "ssid")
                ssid = native_ssid
                ssid_data = self._objc_value(network, "ssidData")
                try:
                    ssid_bytes = bytes(ssid_data) if ssid_data is not None else None
                except (TypeError, ValueError):
                    ssid_bytes = None
                if ssid is None and ssid_bytes:
                    try:
                        ssid = ssid_bytes.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        pass
                bssid = self._objc_value(network, "bssid")
                native_channel_object = self._objc_value(network, "wlanChannel")
                native_channel = self._objc_value(native_channel_object, "channelNumber")
                try:
                    native_channel = int(native_channel) if native_channel is not None else None
                except (TypeError, ValueError):
                    native_channel = str(native_channel) if native_channel is not None else None
                channel, band = self._channel_data(native_channel_object)
                native_width = self._objc_value(native_channel_object, "channelWidth")
                try:
                    native_width = int(native_width) if native_width is not None else None
                except (TypeError, ValueError):
                    native_width = None
                channel_width = {1: "20 MHz", 2: "40 MHz", 3: "80 MHz", 4: "160 MHz",
                                 5: "80+80 MHz"}.get(native_width)
                # CWNetwork exposes strongestSupportedSecurity (and older
                # securityMode), not a `security` property on all macOS builds.
                security = self._objc_value(network, "strongestSupportedSecurity")
                if security is None:
                    security = self._objc_value(network, "security")
                if security is None:
                    legacy_mode = self._objc_value(network, "securityMode")
                    security = {0: 0, 1: 1, 2: 2, 3: 3, 4: 6, 5: 7, 6: 9}.get(legacy_mode)
                try:
                    native_security = int(security) if security is not None else None
                except (TypeError, ValueError):
                    native_security = str(security) if security is not None else None
                auth, cipher = self._security_label(security)
                information_elements, ssid_ie_seen, ssid_ie_hidden, pmf = self._information_elements(
                    self._objc_value(network, "informationElementData"))
                if ssid is None and ssid_bytes is None and ssid_ie_seen:
                    ssid_observed = True
                else:
                    ssid_observed = ssid is not None or ssid_bytes is not None
                if not ssid_observed and ssid_ie_hidden:
                    ssid_observed = True
                try:
                    rssi = int(self._objc_value(network, "rssiValue"))
                except (TypeError, ValueError):
                    rssi = None
                ssid_hidden = bool(ssid_ie_seen and ssid_ie_hidden)
                aps.append({"ssid": str(ssid) if ssid is not None and ssid else None,
                            "ssid_observed": ssid_observed, "ssid_hidden": ssid_hidden,
                            "ssid_data_hex": ssid_bytes.hex() if ssid_bytes is not None else None,
                            "bssid": str(bssid).upper() if bssid else None,
                            "signal_dbm": rssi, "signal_pct": None, "auth": auth, "cipher": cipher,
                            "radio_type": None, "channel": channel, "frequency_ghz": None, "band": band,
                            "channel_width": channel_width,
                            "beacon_interval_ms": self._objc_value(network, "beaconInterval"),
                            "country_code": self._objc_value(network, "countryCode"),
                            "noise_dbm": self._objc_value(network, "noiseMeasurement"),
                            "ibss": self._objc_value(network, "ibss"),
                            "information_elements": information_elements, "pmf_advertisement": pmf,
                            "source": "macOS CoreWLAN", "scan_method": scan_method,
                            "vendor": None, "vendor_note": "Not derivable offline (no OUI database bundled)",
                            "client_count": None, "client_count_note": "Not exposed by macOS Wi-Fi scan",
                            "diagnostic_fields": {
                                "ssid": {"native": str(native_ssid) if native_ssid is not None else None,
                                         "normalized": str(ssid) if ssid is not None and ssid else None},
                                "ssidData": {"native": ssid_bytes.hex() if ssid_bytes is not None else None,
                                             "normalized": str(ssid) if ssid is not None and ssid else None},
                                "bssid": {"native": str(bssid) if bssid is not None else None,
                                          "normalized": str(bssid).upper() if bssid else None},
                                "channel": {"native": native_channel, "normalized": channel},
                                "signal_dbm": {"native": self._objc_value(network, "rssiValue"),
                                               "normalized": rssi},
                                "security": {"native": native_security, "normalized": auth},
                                "beaconInterval": {"native": self._objc_value(network, "beaconInterval"),
                                                   "normalized": self._objc_value(network, "beaconInterval")},
                                "countryCode": {"native": self._objc_value(network, "countryCode"),
                                                 "normalized": self._objc_value(network, "countryCode")},
                                "noiseMeasurement": {"native": self._objc_value(network, "noiseMeasurement"),
                                                     "normalized": self._objc_value(network, "noiseMeasurement")},
                                "channelWidth": {"native": native_width, "normalized": channel_width},
                                "informationElementData": {"native": information_elements,
                                                            "normalized": information_elements},
                            }})
            return aps, None
        except Exception as exc:
            return None, str(exc)

    def _corewlan_connection(self, name):
        corewlan, client = self._corewlan()
        if not client:
            return None
        try:
            interface = client.interfaceWithName_(name)
            if interface is None:
                return None
            ssid = self._objc_value(interface, "ssid")
            bssid = self._objc_value(interface, "bssid")
            channel, band = self._channel_data(self._objc_value(interface, "wlanChannel"))
            security = self._objc_value(interface, "strongestSupportedSecurity")
            if security is None:
                security = self._objc_value(interface, "security")
            auth, cipher = self._security_label(security)
            try:
                rssi = int(self._objc_value(interface, "rssiValue"))
            except (TypeError, ValueError):
                rssi = None
            return {"ssid": str(ssid) if ssid is not None and ssid else None,
                    "ssid_observed": ssid is not None, "ssid_hidden": ssid is not None and not bool(ssid),
                    "bssid": str(bssid).upper() if bssid else None,
                    "connected": bool(ssid), "signal_dbm": rssi, "channel": channel,
                    "frequency_ghz": None, "band": band, "auth": auth, "cipher": cipher}
        except Exception:
            return None

    def interfaces(self):
        if self._interfaces_cache is not None and time.monotonic() - self._interfaces_cache_at < 3:
            return self._interfaces_cache, self._interfaces_error
        rc, output, error = self.engine._run(["networksetup", "-listallhardwareports"], 6)
        if rc != 0:
            records, error = [], error or "networksetup could not list hardware ports."
        elif re.search(r"authorizationcreate|operation not permitted|permission denied", output + error, re.I):
            records, error = [], (
                "macOS denied system Wi-Fi interface enumeration (AuthorizationCreate/permission error). "
                "Launch WiFiSentinel with run_simulator.command from a normal Terminal session; if scanning "
                "is still denied, allow Location Services for the app that launched it (usually Terminal) in "
                "System Settings → Privacy & Security → Location Services."
            )
        else:
            error = None
            records = []
            for block in re.split(r"\n\s*\n", output):
                port = re.search(r"^Hardware Port:\s*(.+)$", block, re.M | re.I)
                device = re.search(r"^Device:\s*(\S+)$", block, re.M | re.I)
                if not device:
                    continue
                desc = port.group(1).strip() if port else "Unknown hardware port"
                if not re.search(r"wi-?fi|airport|wireless", desc, re.I):
                    continue
                state = "available"
                rc_if, if_output, _ = self.engine._run(["ifconfig", device.group(1)], 4)
                if rc_if == 0 and re.search(r"\bstatus: inactive\b", if_output, re.I):
                    state = "disabled"
                records.append({"name": device.group(1), "description": desc, "guid": None,
                                "state": state, "radio": None})
        if not records:
            core_records, core_error = self._corewlan_records()
            if core_records:
                records, error = core_records, None
            elif core_error and not error:
                error = str(core_error)
        self._interfaces_cache = records
        self._interfaces_error = error
        self._interfaces_cache_at = time.monotonic()
        return records, error

    def _airport(self):
        candidate = shutil.which("airport")
        if candidate:
            return candidate
        legacy = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        return legacy if __import__("pathlib").Path(legacy).is_file() else None

    @staticmethod
    def _parse_channel(value):
        match = re.search(r"\b(\d{1,3})\b", value or "")
        return int(match.group(1)) if match else None

    def wifi_info(self):
        stamp = self.engine._timestamp()
        info = {"capability": "macos_native", "observed_at": stamp, "connected": False,
                "ssid": None, "bssid": None, "signal_pct": None, "signal_dbm": None,
                "radio_type": None, "auth": None, "cipher": None, "channel": None,
                "frequency_ghz": None, "band": None, "interface": None,
                "interface_description": None, "nearby_aps": [], "state": "unknown", "scan_outcome": "unavailable",
                "error": None, "native_error": None,
                "unavailable_fields": ["signal_pct", "radio_type", "cipher"]}
        ports, error = self.interfaces()
        info["interfaces"] = ports
        usable_ports = [port for port in ports if port.get("state") != "disabled"]
        wifi_port = usable_ports[0] if usable_ports else None
        if not wifi_port:
            denied = bool(error and re.search(r"authorizationcreate|permission|denied|not permitted|location services", error, re.I))
            state = "permission_required" if denied else "no_wireless_interface"
            info.update(state=state, scan_outcome="permission_required" if denied else "unavailable",
                        error=error or "No Wi-Fi interface was exposed by networksetup.", native_error=error)
            return info
        current = ""
        current_error = None
        for port in usable_ports:
            rc, candidate, candidate_error = self.engine._run(["networksetup", "-getairportnetwork", port["name"]], 5)
            match = re.search(r"(?:Current Wi-?Fi Network|Current AirPort Network)\s*:\s*(.+)$", candidate, re.I | re.M) if rc == 0 else None
            if match:
                wifi_port, current = port, candidate
                break
            if not current_error:
                current_error = candidate_error
        iface = wifi_port["name"]
        info.update(interface=iface, interface_description=wifi_port.get("description"))
        match = re.search(r"(?:Current Wi-?Fi Network|Current AirPort Network)\s*:\s*(.+)$", current, re.I | re.M)
        if match:
            info["ssid"] = match.group(1).strip()
            info["connected"] = bool(info["ssid"])

        core_connection = self._corewlan_connection(iface)
        if core_connection:
            for key, value in core_connection.items():
                if value is not None:
                    info[key] = value
        core_aps, core_error = self._corewlan_scan(iface)
        scan_source = "CoreWLAN"
        # CoreWLAN is the supported native path, but a successful API call may
        # still return an empty set on restricted/older macOS builds. In that
        # case try the available system scan fallback before publishing an
        # empty success; keep the API result if the fallback is absent or empty.
        if core_aps:
            info["nearby_aps"] = core_aps
            info["state"] = "ok" if info["connected"] or core_aps else "disconnected"
            info["scan_outcome"] = "success"
            info["error"] = None
        else:
            airport = self._airport()
        if not core_aps and airport:
            rc, details, detail_error = self.engine._run([airport, "-I"], 5)
            if rc == 0:
                fields = {}
                for line in details.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        fields[key.strip().lower()] = value.strip()
                info["ssid"] = fields.get("ssid") or info["ssid"]
                info["bssid"] = fields.get("bssid") or None
                info["connected"] = info["connected"] or fields.get("state", "").lower() == "running"
                try:
                    info["signal_dbm"] = int(fields["agrctlrssi"])
                except (KeyError, ValueError):
                    pass
                info["channel"] = self._parse_channel(fields.get("channel"))
                info["auth"] = fields.get("802.11 auth") or fields.get("link auth")
                info["radio_type"] = fields.get("802.11 protocol")
            elif detail_error and not current_error:
                current_error = detail_error
            rc, scan, scan_error = self.engine._run([airport, "-s"], 12)
            if rc == 0 and not re.search(r"authorizationcreate|operation not permitted|permission denied|location services required", scan, re.I):
                fallback_aps = self._parse_scan(scan)
                info["nearby_aps"] = fallback_aps or (core_aps or [])
                scan_source = "airport utility" if fallback_aps else "CoreWLAN"
                info["state"] = "ok" if info["connected"] or info["nearby_aps"] else "disconnected"
            else:
                failure_text = scan_error or scan or "Wi-Fi scan failed."
                permission = bool(re.search(r"authorizationcreate|location|privacy|permission|denied|not permitted", failure_text, re.I))
                timeout = bool(re.search(r"timed?\s*out|timeout", failure_text, re.I))
                info["state"] = "permission_required" if permission else ("timeout" if timeout else ("partial" if info["connected"] else "scan_unavailable"))
                info["scan_outcome"] = "permission_required" if permission else ("timeout" if timeout else "error")
                info["error"] = self._scan_error(failure_text)
                info["native_error"] = "; ".join(x for x in (core_error, failure_text) if x) or None
        elif not core_aps:
            if core_aps is not None and not airport:
                info["nearby_aps"] = []
                info["state"] = "ok" if info["connected"] else "disconnected"
                info["scan_outcome"] = "empty"
                info["error"] = None
            elif core_error and re.search(r"authorizationcreate|location|permission|denied|not permitted", core_error, re.I):
                info["state"] = "permission_required"
                info["scan_outcome"] = "permission_required"
                info["error"] = self._scan_error(core_error)
                info["native_error"] = core_error
            elif current_error and re.search(r"authorizationcreate|operation not permitted|permission denied", current_error, re.I):
                info["state"] = "permission_required"
                info["scan_outcome"] = "permission_required"
                info["error"] = self._scan_error(current_error)
                info["native_error"] = current_error
            else:
                info["state"] = "partial" if info["connected"] else "scan_unavailable"
                info["scan_outcome"] = "unavailable"
                info["error"] = "macOS Wi-Fi scan utility is unavailable; current network data may still be available."
                info["native_error"] = core_error or current_error

        if info["connected"] and info["state"] == "unknown":
            info["state"] = "partial"
        if info["channel"] is None:
            info["unavailable_fields"].append("channel")
        if info["band"] is None:
            info["unavailable_fields"].append("band")
        for ap in info["nearby_aps"]:
            ap.setdefault("interface", iface)
            ap.setdefault("source", scan_source)
            ap.setdefault("scan_method", scan_source)
            ap.setdefault("observed_at", stamp)
        if scan_source == "CoreWLAN" and info["nearby_aps"] and not any(ap.get("bssid") for ap in info["nearby_aps"]):
            info["identifier_access"] = "limited"
            info["identifier_limitation"] = (
                "CoreWLAN returned scan records but exposed no BSSIDs. macOS Location Services permission "
                "may be withholding wireless identifiers; grant access to the app that launched WiFiSentinel "
                "(usually Terminal), restart it, and scan again. No identifiers were substituted."
            )
        if info["scan_outcome"] not in {"permission_required", "unavailable", "error"}:
            info["scan_outcome"] = "success" if info["nearby_aps"] else "empty"
        return info

    @staticmethod
    def _scan_error(error):
        text = (error or "").strip()
        if re.search(r"authorizationcreate|location|privacy|permission|denied|operation not permitted", text, re.I):
            return "macOS requires Location Services permission for Wi-Fi scan details. Allow WiFiSentinel in System Settings → Privacy & Security → Location Services, then rescan."
        return text or "The macOS Wi-Fi scan did not return data. Check Wi-Fi status and retry."

    @staticmethod
    def _parse_scan(output):
        aps = []
        bssid_pattern = re.compile(r"(?i)([0-9a-f]{2}(?::[0-9a-f]{2}){5})")
        for line in (output or "").splitlines():
            match = bssid_pattern.search(line)
            if not match:
                continue
            raw_ssid = line[:match.start()].strip()
            ssid = raw_ssid or None
            tail = line[match.end():].split()
            rssi = None
            channel = None
            try:
                rssi = int(tail[0])
            except (IndexError, ValueError):
                pass
            try:
                channel = MacOSAdapter._parse_channel(tail[1])
            except IndexError:
                pass
            security = " ".join(tail[4:]) if len(tail) > 4 else None
            aps.append({"ssid": ssid, "ssid_observed": True, "ssid_hidden": not bool(raw_ssid),
                        "bssid": match.group(1).upper(), "signal_dbm": rssi,
                        "signal_pct": None, "auth": security or None, "cipher": None,
                        "radio_type": None, "channel": channel, "frequency_ghz": None,
                        "band": 2.4 if channel == 14 else None, "source": "macOS airport utility",
                        "scan_method": "airport -s",
                        "vendor": None, "vendor_note": "Not derivable offline (no OUI database bundled)",
                        "client_count": None, "client_count_note": "Not exposed by macOS Wi-Fi scan"})
        return sorted(aps, key=lambda ap: (ap["signal_dbm"] is None, -(ap["signal_dbm"] or -999)))

    def network_context(self, interface=None):
        blank = {"local_ip": None, "gateway": None, "subnet_mask": None, "network": None,
                 "interface": interface}
        rc, route, _ = self.engine._run(["route", "-n", "get", "default"], 5)
        if rc == 0:
            gw = re.search(r"^\s*gateway:\s*(\S+)", route, re.M | re.I)
            dev = re.search(r"^\s*interface:\s*(\S+)", route, re.M | re.I)
            route_interface = dev.group(1) if dev else None
            if not interface or (route_interface and route_interface == interface):
                blank["gateway"] = gw.group(1) if gw else None
            if not blank["interface"] and dev:
                blank["interface"] = route_interface
        iface = interface or blank["interface"]
        if not iface:
            return blank
        rc, output, _ = self.engine._run(["ifconfig", iface], 5)
        if rc != 0:
            return blank
        ip = re.search(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\b", output, re.M)
        mask = re.search(r"^\s*inet\s+\d+\.\d+\.\d+\.\d+\s+netmask\s+(0x[0-9a-f]+|\d+\.\d+\.\d+\.\d+)", output, re.M | re.I)
        local_ip = ip.group(1) if ip else None
        subnet = mask.group(1) if mask else None
        if subnet and subnet.lower().startswith("0x"):
            try:
                subnet = str(ipaddress.IPv4Address(int(subnet, 16)))
            except ipaddress.AddressValueError:
                subnet = None
        blank.update(local_ip=local_ip, subnet_mask=subnet)
        if local_ip and subnet:
            try:
                blank["network"] = str(ipaddress.ip_network(f"{local_ip}/{subnet}", strict=False))
            except ValueError:
                pass
        return blank

    def neighbors(self):
        rc, output, error = self.engine._run(["arp", "-an"], 5)
        if rc != 0:
            return [], error or "arp could not read the local neighbor cache."
        entries = []
        pattern = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:.-]+)\s+on\s+(\S+)")
        for line in output.splitlines():
            match = pattern.search(line)
            if not match or "incomplete" in line.lower():
                continue
            mac = match.group(2).replace("-", ":").upper()
            if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
                continue
            entries.append({"ip": match.group(1), "mac": mac, "state": "observed", "interface": match.group(3)})
        return entries, None
