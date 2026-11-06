"""Cross-platform live Wi-Fi and local-network discovery.

Every value produced here is an operating-system observation. When the OS does
not expose a value the key stays ``None`` and the UI renders "Not exposed"; the
engine never substitutes a plausible-looking number.

Performance contract
--------------------
Nothing in this module runs on the UI thread's critical path. A background
worker refreshes the snapshot on a fixed interval and publishes it atomically.
:meth:`RealWiFiEngine.live_snapshot` returns the last known good result
immediately, plus a ``refreshing`` flag, so a page can paint instantly while
native discovery commands and reverse DNS are still running.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone

from .logging_setup import get_logger
from .platform_adapters import MacOSAdapter
from .windows_wlan import WindowsWLAN

log = get_logger("wifi")

#: Refresh cadence for the background collector. A WLAN scan is expensive, so the
#: interval is deliberately conservative; the UI can request a faster foreground
#: refresh via :meth:`refresh_now` without blocking the caller.
REFRESH_INTERVAL_SECONDS = 12.0
SNAPSHOT_TTL_SECONDS = 3.0
DNS_CACHE_TTL_SECONDS = 300.0

CLIENT_COUNT_NOTE = "Not exposed by the OS WLAN scan"
LOCAL_NEIGHBOR_NOTE = "Local neighbor cache entries; not a Wi-Fi association count"

# netsh label aliases. Windows localises its output, so each field is matched
# against the English label plus the common localisations. Anything still
# unmatched stays None instead of being guessed.
_LABEL_ALIASES = {
    "name": ("Name", "Name"),
    "description": ("Description", "Beschreibung"),
    "guid": ("GUID", "GUID"),
    "state": ("State", "Status"),
    "radio": ("Radio type", "Funktyp"),
    "ssid": ("SSID", "SSID"),
    "bssid": ("BSSID", "BSSID"),
    "authentication": ("Authentication", "Authentifizierung"),
    "cipher": ("Cipher", "Chiffre"),
    "signal": ("Signal", "Signal"),
    "channel": ("Channel", "Kanal"),
    "network_type": ("Network type", "Netzwerktyp"),
    "ipv4": ("IPv4 Address", "IPv4-Adresse"),
    "subnet": ("Subnet Mask", "Subnetzmaske"),
    "gateway": ("Default Gateway", "Standardgateway"),
}

_VENDOR_UNAVAILABLE = "Not derivable offline (no OUI database bundled)"


class RealWiFiEngine:
    def __init__(self, refresh_interval=REFRESH_INTERVAL_SECONDS, snapshot_collector=None):
        self.os_type = platform.system()
        self.adapter = MacOSAdapter(self) if self.os_type == "Darwin" else None
        self.windows_adapter = WindowsWLAN() if self.os_type == "Windows" else None
        self.refresh_interval = float(refresh_interval)
        self._cache = None
        self._cache_at = 0.0
        self._retry_after = 0.0
        self._future = None
        self._future_generation = None
        self._generation = 0
        self._scan_attempt = {"id": None, "status": "idle", "started_at": None,
                              "finished_at": None, "successful_at": None,
                              "source": None, "error": None}
        self._last_success_at = None
        self._snapshot_collector = snapshot_collector or self._collect_live_snapshot
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._worker = None
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="ws-discovery")
        self._host_cache = {}
        self._host_lock = threading.RLock()
        self._active_device_scans = {}
        self._active_scan_lock = threading.RLock()
        self._device_discovery_callback = None
        self._ap_first_seen = {}

    # ------------------------------------------------------------------ process
    def _run(self, cmd, timeout=8):
        """Run a command and never raise. Returns ``(returncode, stdout, stderr)``."""
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, shell=False,
            )
            return completed.returncode, completed.stdout, completed.stderr
        except FileNotFoundError:
            return -2, "", f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return -3, "", f"Command timed out after {timeout}s: {cmd[0]}"
        except Exception as exc:  # defensive: a discovery failure must not kill the app
            return -1, "", f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _label_pattern(field):
        labels = _LABEL_ALIASES.get(field, (field,))
        return "|".join(re.escape(x) for x in labels)

    @classmethod
    def _val(cls, text, field):
        pattern = rf"^\s*(?:{cls._label_pattern(field)})\s*:\s*(.*?)\s*$"
        match = re.search(pattern, text or "", re.M | re.I)
        return match.group(1).strip() if match else None

    @classmethod
    def _interface_blocks(cls, text):
        """Split localized netsh interface output into independently parsed adapters."""
        name_pattern = cls._label_pattern("name")
        blocks = re.split(rf"(?m)(?=^\s*(?:{name_pattern})\s*:)", text or "")
        return [block for block in blocks if cls._val(block, "name") or cls._val(block, "description")]

    # --------------------------------------------------------------- inference
    @staticmethod
    def _type_from_identity(hostname=None, vendor=None):
        """Infer a device *class* from identity strings.

        This is explicitly an inference, not OS telemetry, and callers must label
        it as such. Returns ``"Unknown"`` rather than guessing.
        """
        text = f"{hostname or ''} {vendor or ''}".lower()
        rules = (
            ("Mobile phone / tablet", ("android", "iphone", "ipad", "pixel", "galaxy", "oneplus", "redmi",
                                       "xiaomi", "oppo", "vivo", "realme", "phone", "tablet")),
            ("Printer / scanner", ("printer", "epson", "canon", "brother", "xerox", "laserjet", "deskjet", "mfp")),
            ("Smart TV / media device", ("tv", "roku", "chromecast", "firetv", "fire-stick", "appletv", "bravia",
                                         "webos", "tizen")),
            ("Game console", ("xbox", "playstation", "ps4", "ps5", "nintendo", "switch")),
            ("Network infrastructure", ("router", "gateway", "access-point", "accesspoint", "switch", "mesh", "nas")),
            ("Computer", ("laptop", "desktop", "workstation", "macbook", "imac", "windows", "ubuntu", "linux", "mac")),
        )
        for label, words in rules:
            if any(word in text for word in words):
                return label
        return "Unknown"

    @staticmethod
    def _band(channel):
        """Return a band only for channel 14, which is outside 6 GHz numbering.

        Channel numbers 1–13 overlap between 2.4 and 6 GHz. Windows netsh
        reports channel but not center frequency or band, so those are unknown.
        """
        return 2.4 if channel == 14 else None

    @staticmethod
    def _band_label(band):
        if band is None:
            return None
        return f"{band:g} GHz"

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    # ---------------------------------------------------------------- WLAN API
    def interfaces(self):
        """Wireless interfaces reported by the OS WLAN stack."""
        if self.os_type == "Darwin":
            return self.adapter.interfaces()[0]
        if self.os_type != "Windows":
            return []
        rc, out, _ = self._run(["netsh", "wlan", "show", "interfaces"], 5)
        if rc != 0:
            return []
        blocks = self._interface_blocks(out)
        result = []
        for block in blocks:
            name = self._val(block, "name")
            description = self._val(block, "description")
            if name or description:
                result.append({
                    "name": name,
                    "description": description,
                    "guid": self._val(block, "guid"),
                    "state": self._val(block, "state"),
                    "radio": self._val(block, "radio"),
                })
        return result

    def _parse_interfaces(self, out):
        info = {
            "connected": False, "ssid": None, "bssid": None, "signal_pct": None, "signal_dbm": None,
            "radio_type": None, "auth": None, "cipher": None, "channel": None, "frequency_ghz": None,
            "band": None, "interface": None, "interface_description": None,
        }
        info["interface"] = self._val(out, "name")
        info["interface_description"] = self._val(out, "description")
        state = self._val(out, "state")
        info["connected"] = bool(state) and str(state).lower() in ("connected", "verbunden")
        info["auth"] = self._val(out, "authentication")
        info["cipher"] = self._val(out, "cipher")
        info["radio_type"] = self._val(out, "radio")
        info["bssid"] = self._val(out, "bssid")
        ssid = self._val(out, "ssid")
        info["ssid"] = ssid or None
        match = re.search(r"^\s*(?:Signal|Signal)\s*:\s*(\d+)\s*%", out or "", re.M | re.I)
        if match:
            info["signal_pct"] = int(match.group(1))
        match = re.search(r"^\s*(?:Channel|Kanal)\s*:\s*(\d+)", out or "", re.M | re.I)
        if match:
            info["channel"] = int(match.group(1))
            info["band"] = self._band(info["channel"])
        return info

    def _parse_nearby(self, out):
        """Parse ``netsh wlan show networks mode=bssid`` into per-BSSID records."""
        aps = []
        ssid = None
        ssid_observed = False
        pending_auth = pending_cipher = None
        current = None
        for raw in (out or "").splitlines():
            line = raw.strip()
            match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.I)
            if match:
                raw_ssid = match.group(1).strip()
                ssid = raw_ssid or None
                ssid_observed = True
                pending_auth = pending_cipher = None
                current = None
                continue
            match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line, re.I)
            if match:
                current = {
                    "ssid": ssid, "ssid_observed": ssid_observed,
                    "ssid_hidden": bool(ssid_observed and not ssid),
                    "bssid": (match.group(1).strip() or None), "signal_pct": None,
                    "signal_dbm": None, "auth": pending_auth, "cipher": pending_cipher, "network_type": None,
                    "radio_type": None, "channel": None, "frequency_ghz": None, "band": None,
                    "vendor": None, "vendor_note": _VENDOR_UNAVAILABLE,
                    "client_count": None, "client_count_note": CLIENT_COUNT_NOTE,
                }
                aps.append(current)
                continue
            if current is None:
                low = line.lower()
                if low.startswith(("authentication", "authentifizierung")) and ":" in line:
                    pending_auth = line.split(":", 1)[1].strip() or None
                elif low.startswith(("cipher", "chiffre")) and ":" in line:
                    pending_cipher = line.split(":", 1)[1].strip() or None
                continue
            low = line.lower()
            if low.startswith(("authentication", "authentifizierung")) and ":" in line:
                current["auth"] = line.split(":", 1)[1].strip() or None
            elif low.startswith(("cipher", "chiffre")) and ":" in line:
                current["cipher"] = line.split(":", 1)[1].strip() or None
            elif low.startswith(("network type", "netzwerktyp")) and ":" in line:
                current["network_type"] = line.split(":", 1)[1].strip() or None
            elif low.startswith(("radio type", "funktyp")) and ":" in line:
                current["radio_type"] = line.split(":", 1)[1].strip() or None
            elif low.startswith("signal") and ":" in line:
                match = re.search(r"(\d+)\s*%", line)
                if match:
                    current["signal_pct"] = int(match.group(1))
            elif low.startswith(("channel", "kanal")) and ":" in line:
                match = re.search(r"(\d+)", line.split(":", 1)[1])
                if match:
                    current["channel"] = int(match.group(1))
                    current["band"] = self._band(current["channel"])
        # Deduplicate BSSIDs; netsh can repeat an entry across interface blocks.
        unique = {}
        for ap in aps:
            key = (ap.get("bssid"), ap.get("ssid"))
            if key[0] and key not in unique:
                unique[key] = ap
        return sorted(unique.values(), key=lambda a: (a.get("signal_pct") is None, -(a.get("signal_pct") or 0),
                                                       a.get("ssid") or ""))

    def wifi_info(self):
        """Collect the current association and the nearby BSSID list."""
        if self.os_type == "Darwin":
            return self.adapter.wifi_info()
        info = {
            "capability": "windows_netsh", "observed_at": self._timestamp(), "connected": False, "ssid": None,
            "bssid": None, "signal_pct": None, "signal_dbm": None, "radio_type": None, "auth": None,
            "cipher": None, "channel": None, "frequency_ghz": None, "band": None, "interface": None,
            "interface_description": None, "nearby_aps": [], "state": "unknown", "scan_outcome": "unavailable", "error": None,
            "unavailable_fields": [],
        }
        if self.os_type != "Windows":
            info["capability"] = "unsupported_on_this_os"
            info["state"] = "unsupported_platform"
            info["scan_outcome"] = "unavailable"
            info["error"] = (
                f"Live WLAN telemetry requires the Windows WLAN stack; this host reports {self.os_type}. "
                "No wireless values can be observed here."
            )
            info["unavailable_fields"] = ["ssid", "bssid", "channel", "band", "signal_pct", "auth", "cipher", "radio_type"]
            return info

        # This method itself runs in the shared discovery pool during a refresh.
        # Do not submit nested jobs to that same pool and wait for them: with the
        # bounded worker count, the collector can occupy every worker and deadlock.
        native_interfaces, native_aps, native_error = None, None, None
        if self.os_type == "Windows" and not self.windows_adapter:
            native_error = "Native WLAN API wrapper is unavailable; using the system-command fallback."
        if self.windows_adapter:
            try:
                native_interfaces, native_aps, native_error = self.windows_adapter.scan()
            except Exception as exc:
                native_error = f"Windows Native WLAN API scan failed: {type(exc).__name__}: {exc}"
        rc_if, out_if, err_if = self._run(["netsh", "wlan", "show", "interfaces"], 6)
        if native_error:
            rc_scan, out_scan, err_scan = self._run(["netsh", "wlan", "show", "networks", "mode=bssid"], 12)
        else:
            rc_scan, out_scan, err_scan = 0, "", ""

        if rc_if != 0 and not native_interfaces:
            info["state"] = "wlan_unavailable"
            info["scan_outcome"] = "unavailable"
            info["error"] = native_error or _describe_failure(rc_if, err_if, "Windows WLAN interface query failed")
            info["unavailable_fields"] = ["ssid", "bssid", "channel", "band", "signal_pct", "auth", "cipher"]
            return info
        interface_blocks = self._interface_blocks(out_if) if rc_if == 0 else []
        info["interfaces"] = ([self._parse_interfaces(block) for block in interface_blocks]
                               if interface_blocks else (native_interfaces or []))
        connected_block = next((block for block in interface_blocks
                                if self._parse_interfaces(block).get("connected")), None)
        if interface_blocks:
            info.update(self._parse_interfaces(connected_block or interface_blocks[0]))
        elif native_interfaces:
            connected_interface = next((row for row in native_interfaces if row.get("state") == "connected"), None)
            if connected_interface:
                info.update(connected=True, interface=connected_interface.get("name"))
        if native_error is None:
            info["nearby_aps"] = native_aps or []
            info["capability"] = "windows_native_wlan"
            info["state"] = "ok"
            info["scan_outcome"] = "success" if info["nearby_aps"] else "empty"
            scan_source = "Windows Native WLAN API"
        elif rc_scan == 0:
            info["nearby_aps"] = self._parse_nearby(out_scan)
            info["state"] = "ok" if info["nearby_aps"] or info["connected"] else "partial"
            info["scan_outcome"] = "success" if info["nearby_aps"] else "empty"
            info["fallback_scan_succeeded"] = True
            info["error"] = native_error
            scan_source = "Windows WLAN netsh fallback"
        else:
            info["error"] = native_error or _describe_failure(rc_scan, err_scan, "Windows WLAN network scan failed")
            permission = bool(re.search(r"permission|access is denied|not permitted", info["error"], re.I))
            info["state"] = "permission_required" if permission else "partial"
            info["scan_outcome"] = "permission_required" if permission else "error"
            scan_source = "Windows WLAN unavailable"
        if info["signal_pct"] is None:
            info["unavailable_fields"] = info["unavailable_fields"] + ["signal_pct"]
        info["unavailable_fields"] = info["unavailable_fields"] + ["signal_dbm"]
        for ap in info["nearby_aps"]:
            ap.setdefault("interface", info.get("interface"))
            ap.setdefault("source", scan_source)
            ap.setdefault("scan_method", scan_source)
            ap.setdefault("observed_at", info["observed_at"])
        log.info(
            "wifi_discovery",
            extra={"context": {"connected": info["connected"], "channel": info["channel"],
                               "nearby_bssids": len(info["nearby_aps"]), "state": info["state"]}},
        )
        return info

    def nearby_aps(self):
        return self.wifi_info().get("nearby_aps", [])

    # ------------------------------------------------------------ IP / devices
    def _network_context_raw(self, interface=None):
        if self.os_type == "Darwin":
            return self.adapter.network_context(interface)
        blank = {"local_ip": None, "gateway": None, "subnet_mask": None, "network": None, "interface": None}
        if self.os_type != "Windows":
            return blank
        rc, out, _ = self._run(["ipconfig"], 5)
        if rc != 0:
            return blank
        blocks = re.split(r"\n\s*\n", out)
        active = next((b for b in blocks if interface and re.search(rf"\b{re.escape(str(interface))}\b", b, re.I)), None)
        if active is None:
            active = next((b for b in blocks if re.search(r"Wi-?Fi|Wireless LAN adapter|WLAN", b, re.I)), out)
        local_ip = self._ipconfig_ipv4(active, "ipv4")
        subnet = self._ipconfig_ipv4(active, "subnet")
        gateway = self._ipconfig_ipv4(active, "gateway")
        network = None
        if local_ip and subnet:
            try:
                network = str(ipaddress.ip_network(f"{local_ip}/{subnet}", strict=False))
            except ValueError:
                network = None
        return {"local_ip": local_ip, "gateway": gateway,
                "subnet_mask": subnet, "network": network, "interface": None}

    @classmethod
    def _ipconfig_ipv4(cls, text, field):
        """Read an IPv4 value from localized ipconfig labels, including dotted labels."""
        labels = cls._label_pattern(field)
        pattern = rf"^\s*(?:{labels})[^:\r\n]*:\s*(?:\r?\n\s*)?((?:\d{{1,3}}\.){{3}}\d{{1,3}})\b"
        match = re.search(pattern, text or "", re.M | re.I)
        return match.group(1) if match else None

    def local_ip(self):
        return self._network_context_raw().get("local_ip")

    def gateway(self):
        return self._network_context_raw().get("gateway")

    def network_context(self, interface=None):
        ctx = self._network_context_raw(interface)
        ctx["interface"] = interface
        return ctx

    def _powershell_neighbors(self):
        if self.os_type != "Windows":
            return []
        script = (
            "Get-NetNeighbor -AddressFamily IPv4 | "
            "Where-Object {$_.IPAddress -and $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^00-00-00-00-00-00$'} | "
            "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Json -Compress"
        )
        rc, out, _ = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=8)
        if rc != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return [{
                "ip": x.get("IPAddress"),
                "mac": (x.get("LinkLayerAddress") or "").replace("-", ":").upper(),
                "state": x.get("State"),
                "interface": x.get("InterfaceAlias"),
            } for x in data]
        except (ValueError, AttributeError):
            return []

    def _arp_devices(self):
        if self.os_type == "Darwin":
            neighbors, error = self.adapter.neighbors()
            return neighbors, "arp -an" if not error else "arp -an (unavailable)"
        neighbors = self._powershell_neighbors()
        source = "Get-NetNeighbor"
        if not neighbors:
            rc, out, _ = self._run(["arp", "-a"], 5)
            source = "arp -a"
            if rc != 0:
                return [], None
            neighbors = []
            for line in out.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+(\w+)", line)
                if match:
                    ip, mac, status = match.groups()
                    neighbors.append({"ip": ip, "mac": mac.replace("-", ":").upper(), "state": status,
                                      "interface": None})
        return neighbors, source

    def arp_devices(self):
        """Devices the local neighbor cache knows about. No passive guessing."""
        ctx = self._network_context_raw()
        local_ip, gateway = ctx.get("local_ip"), ctx.get("gateway")
        neighbors, source = self._arp_devices()
        devices = []
        for entry in neighbors:
            ip, mac = entry.get("ip"), entry.get("mac")
            if not ip or not mac:
                continue
            devices.append({
                "ip": ip, "mac": mac, "hostname": None,
                "vendor": None, "vendor_note": _VENDOR_UNAVAILABLE, "os": None,
                "type": "Unknown", "type_inferred": False,
                "status": str(entry.get("state") or "observed").lower(),
                "is_gateway": bool(gateway) and ip == gateway,
                "is_self": bool(local_ip) and ip == local_ip,
                "interface": entry.get("interface"),
                "source": source,
                "observed_at": self._timestamp(),
            })
        seen = set()
        unique = []
        for device in devices:
            if device["ip"] in seen:
                continue
            seen.add(device["ip"])
            unique.append(device)
        log.info("device_discovery", extra={"context": {"count": len(unique), "source": source}})
        return unique

    def resolve_names(self, devices, max_seconds=1.2):
        """Reverse-DNS the neighbors that are not already cached, under a time budget."""
        deadline = time.monotonic()
        pending = []
        for device in devices:
            ip = device.get("ip")
            if not ip:
                continue
            with self._host_lock:
                cached = self._host_cache.get(ip)
            if cached and deadline - cached[0] < DNS_CACHE_TTL_SECONDS:
                device["hostname"] = cached[1]
            else:
                pending.append(device)

        def lookup(device):
            ip = device.get("ip")
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = None
            with self._host_lock:
                self._host_cache[ip] = (time.monotonic(), name)
            device["hostname"] = name

        if pending:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(pending)))
            try:
                futures = [pool.submit(lookup, device) for device in pending]
                concurrent.futures.wait(futures, timeout=max_seconds)
            finally:
                pool.shutdown(wait=False)

        for device in devices:
            inferred = self._type_from_identity(device.get("hostname"), device.get("vendor"))
            device["type"] = inferred
            device["type_inferred"] = bool(device.get("hostname")) and inferred != "Unknown"
            if device.get("is_gateway") and inferred == "Unknown":
                device["type"] = "Network gateway"
                device["type_inferred"] = True
            if device.get("is_self"):
                device["type"] = "This host"
                device["type_inferred"] = True
        return devices

    # ------------------------------------------------------------- networking
    def ping(self, host, timeout_ms=1200):
        timeout_ms = max(250, min(int(timeout_ms), 2000))
        if self.os_type == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        elif self.os_type == "Darwin":
            # macOS/BSD ping's -W takes milliseconds. Passing `1` here (as
            # older code did) can expire before an ordinary LAN reply arrives.
            cmd = ["ping", "-n", "-c", "1", "-W", str(timeout_ms), host]
        else:
            wait_seconds = max(1, (timeout_ms + 999) // 1000)
            cmd = ["ping", "-c", "1", "-W", str(wait_seconds), host]
        rc, out, err = self._run(cmd, timeout=max(2, timeout_ms / 1000 + 1))
        return {"host": host, "reachable": rc == 0, "output": (out or err)[-1200:]}

    def start_local_discovery(self, authorized=False):
        """Start an opt-in ICMP probe of only the directly connected private /24-or-smaller subnet."""
        if authorized is not True:
            raise ValueError("Confirm authorization before probing the local network.")
        context = self._network_context_raw()
        local_ip = context.get("local_ip")
        subnet = context.get("network")
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            local_address = ipaddress.ip_address(local_ip)
        except ValueError:
            raise ValueError("The operating system did not expose a valid local IPv4 address and subnet.") from None
        if (network.version != 4 or local_address not in network or not network.is_private
                or network.num_addresses > 256):
            raise ValueError("Active discovery is limited to the currently connected private IPv4 subnet, up to 256 addresses.")
        hosts = [address for address in network.hosts() if address != local_address]
        if not hosts:
            raise ValueError("The connected subnet has no other usable host addresses to probe.")
        with self._active_scan_lock:
            for job in self._active_device_scans.values():
                if job["status"] == "running":
                    raise ValueError("A local device discovery is already running.")
            job_id = uuid.uuid4().hex
            job = {"id": job_id, "status": "running", "scope": str(network), "total": len(hosts),
                   "checked": 0, "results": [], "started_at": self._timestamp(), "finished_at": None,
                   "interface": context.get("interface"),
                   "limitations": ["Only ICMP echo responders are listed. Firewalls may block replies; non-response does not mean the host is absent."],
                   "cancel": threading.Event()}
            self._active_device_scans[job_id] = job
            thread = threading.Thread(target=self._run_local_discovery, args=(job_id, hosts, context.get("interface")),
                                      name="ws-local-device-discovery", daemon=True)
            job["thread"] = thread
            thread.start()
            self._notify_device_discovery(job_id)
            return self._public_scan_job(job)

    def set_device_discovery_callback(self, callback):
        """Set an optional persistence observer for user-started local discovery jobs."""
        self._device_discovery_callback = callback if callable(callback) else None

    def _notify_device_discovery(self, job_id):
        callback = self._device_discovery_callback
        if not callback:
            return
        with self._active_scan_lock:
            job = self._active_device_scans.get(job_id)
            public = self._public_scan_job(job) if job else None
        if public:
            try:
                callback(public)
            except Exception as exc:
                log.warning("device_discovery_persist_failed", extra={"context": {"error": str(exc)}})

    def _run_local_discovery(self, job_id, hosts, interface):
        with self._active_scan_lock:
            job = self._active_device_scans.get(job_id)
        if not job:
            return
        cancel = job["cancel"]
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="ws-icmp-probe")
        futures = {}
        try:
            for address in hosts:
                if cancel.is_set():
                    break
                future = pool.submit(self.ping, str(address), 750)
                futures[future] = str(address)
            for future in concurrent.futures.as_completed(futures):
                if cancel.is_set():
                    break
                try:
                    response = future.result()
                except Exception:
                    response = {"host": futures[future], "reachable": False}
                with self._active_scan_lock:
                    job["checked"] += 1
                    if response.get("reachable"):
                        observed_at = self._timestamp()
                        job["results"].append({
                            "ip": response["host"], "mac": None, "hostname": None, "vendor": None,
                            "vendor_note": _VENDOR_UNAVAILABLE, "type": "Unknown", "type_inferred": False,
                            "status": "responded", "is_gateway": False, "is_self": False,
                            "interface": interface,
                            "source": "ICMP echo response", "observed_at": observed_at,
                        })
                    checkpoint = job["checked"] % 8 == 0
                if checkpoint:
                    self._notify_device_discovery(job_id)
            if job["results"]:
                try:
                    neighbors = {device.get("ip"): device for device in self.arp_devices()}
                    with self._active_scan_lock:
                        for result in job["results"]:
                            neighbor = neighbors.get(result["ip"])
                            if not neighbor:
                                continue
                            for field in ("mac", "hostname", "vendor", "interface"):
                                if neighbor.get(field):
                                    result[field] = neighbor[field]
                            result["source"] += f" + {neighbor.get('source', 'OS neighbor cache')}"
                except Exception:
                    # ICMP response remains valid evidence if the neighbor
                    # cache cannot be read; optional identifiers stay unknown.
                    pass
            cancelled = cancel.is_set()
            with self._active_scan_lock:
                job["status"] = "cancelled" if cancelled else "completed"
                job["finished_at"] = self._timestamp()
            self._notify_device_discovery(job_id)
        except Exception as exc:
            with self._active_scan_lock:
                job["status"] = "failed"
                job["error"] = f"{type(exc).__name__}: {exc}"
                job["finished_at"] = self._timestamp()
            self._notify_device_discovery(job_id)
        finally:
            for future in futures:
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _public_scan_job(job):
        return {key: list(value) if key == "results" else value for key, value in job.items()
                if key not in {"cancel", "thread"}}

    def local_discovery_status(self, job_id):
        with self._active_scan_lock:
            job = self._active_device_scans.get(job_id)
            return self._public_scan_job(job) if job else None

    def cancel_local_discovery(self, job_id):
        with self._active_scan_lock:
            job = self._active_device_scans.get(job_id)
            if not job or job["status"] != "running":
                return False
            job["cancel"].set()
            return True

    def tcp_ports(self, host, ports, timeout=0.5):
        """TCP connect scan. Only ever called against a host inside declared scope."""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return [{"error": f"{host} is not an IP address", "port": None, "state": "invalid_target"}]
        results = []
        for port in ports:
            started = time.perf_counter()
            sock = socket.socket()
            sock.settimeout(timeout)
            try:
                code = sock.connect_ex((host, int(port)))
                results.append({
                    "port": int(port),
                    "state": "open" if code == 0 else "closed",
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                })
            except Exception as exc:
                results.append({"port": int(port), "state": "error", "error": f"{type(exc).__name__}: {exc}"})
            finally:
                sock.close()
        return results

    def traceroute(self, host, max_hops=12):
        cmd = (["tracert", "-d", "-h", str(max_hops), host] if self.os_type == "Windows"
               else ["traceroute", "-n", "-m", str(max_hops), host])
        rc, out, err = self._run(cmd, timeout=30)
        return {"host": host, "success": rc == 0, "output": out or err, "returncode": rc,
                "engine": "tracert" if self.os_type == "Windows" else "traceroute"}

    # -------------------------------------------------------------- snapshots
    def _collect_live_snapshot(self):
        started = time.monotonic()
        futures = {
            "wifi": self._executor.submit(self.wifi_info),
            "devices": self._executor.submit(self.arp_devices),
        }
        info = futures["wifi"].result()
        devices = futures["devices"].result()
        ctx = self.network_context(info.get("interface"))
        self.resolve_names(devices, max_seconds=1.0)

        # The host WLAN scan does not expose associated-client counts. Keep
        # these fields unavailable instead of substituting neighbor-cache size.
        known_local = len([d for d in devices if not d.get("is_self")])
        snapshot = {
            "ready": True,
            "refreshing": False,
            "observed_at": self._timestamp(),
            "collection_ms": round((time.monotonic() - started) * 1000),
            "wifi": info,
            "devices": devices,
            "network": ctx,
            "known_local_devices": known_local,
            "capabilities": {
                "nearby_ap_client_counts": False,
                "client_count_note": CLIENT_COUNT_NOTE,
                "device_type": "inferred_from_hostname_when_available",
                "vendor": "unavailable_offline",
                "ip_address": "local_neighbor_cache",
                "hostname": "reverse_dns_when_available",
                "signal_dbm": "reported_by_macos_airport_when_available" if self.os_type == "Darwin" else "not_exposed_by_windows_wlan_scan",
                "band": "only_inferred_for_unambiguous_2.4GHz_channels",
            },
            "status_message": _status_message(info, devices),
        }
        log.info(
            "live_snapshot",
            extra={"context": {"collection_ms": snapshot["collection_ms"], "devices": len(devices),
                               "nearby_bssids": len(info.get("nearby_aps", []))}},
        )
        return snapshot

    def _start_refresh(self):
        with self._lock:
            if self._future and not self._future.done():
                return False
            self._generation += 1
            started_at = self._timestamp()
            self._scan_attempt = {"id": self._generation, "status": "scanning",
                                  "started_at": started_at, "finished_at": None,
                                  "successful_at": self._last_success_at,
                                  "source": None, "error": None}
            self._future_generation = self._generation
            self._future = self._executor.submit(self._snapshot_collector)
            return True

    def refresh_now(self):
        """Kick off a refresh if one is not already running. Returns immediately."""
        started = self._start_refresh()
        if started:
            log.debug("refresh_requested")
        return started

    def live_snapshot(self):
        """Return the cached snapshot immediately, never blocking on the OS."""
        with self._lock:
            age = time.monotonic() - self._cache_at if self._cache else float("inf")
            if age > SNAPSHOT_TTL_SECONDS and time.monotonic() >= self._retry_after:
                self._start_refresh()
            if self._cache:
                out = dict(self._cache)
                out["refreshing"] = bool(self._future and not self._future.done())
                out["cache_age_ms"] = round(age * 1000) if age != float("inf") else None
                out["scan_attempt"] = dict(self._scan_attempt)
                out["wifi"] = dict(out.get("wifi") or {})
                if out["refreshing"] and self._last_success_at:
                    out["wifi"]["freshness"] = "cached"
                return out
            out = _empty_snapshot(self.os_type)
            out["scan_attempt"] = dict(self._scan_attempt)
            return out

    def poll_refresh(self):
        """Publish a finished refresh, then return the current snapshot."""
        with self._lock:
            future = self._future
            generation = self._future_generation
        if future is not None and future.done():
            try:
                result = future.result()
            except Exception as exc:
                result = None
                error = str(exc)
                stack = [f"{frame.filename.rsplit('/', 1)[-1]}:{frame.lineno}:{frame.name}"
                         for frame in traceback.extract_tb(exc.__traceback__)]
                log.error("live_snapshot_exception", extra={"context": {
                    "error_type": type(exc).__name__, "stack": stack}})
            else:
                error = None
            with self._lock:
                if self._future is future and generation != self._generation:
                    self._future = None
                    self._future_generation = None
                elif self._future is future:
                    outcome, source, scan_error = _scan_outcome(result, error)
                    finished_at = self._timestamp()
                    self._scan_attempt = {"id": generation, "status": outcome,
                                          "started_at": self._scan_attempt.get("started_at"),
                                          "finished_at": finished_at,
                                          "successful_at": (finished_at if outcome in {"success", "empty"}
                                                            else self._last_success_at),
                                          "source": source, "error": scan_error}
                    if outcome in {"success", "empty"}:
                        self._track_ap_seen(result)
                        result["refreshing"] = False
                        result["scan_attempt"] = dict(self._scan_attempt)
                        result["wifi"] = dict(result.get("wifi") or {})
                        result["wifi"]["freshness"] = "live"
                        result["wifi"]["scan_outcome"] = outcome
                        self._cache = result
                        self._last_success_at = finished_at
                        self._scan_attempt["successful_at"] = finished_at
                        self._cache["scan_attempt"] = dict(self._scan_attempt)
                        self._cache_at = time.monotonic()
                        self._retry_after = 0.0
                    else:
                        ap_count = len((result or {}).get("wifi", {}).get("nearby_aps") or [])
                        log.error("live_snapshot_failed", extra={"context": {
                            "category": outcome, "source": source, "nearby_bssids": ap_count}})
                        self._retry_after = time.monotonic() + 5.0
                        if self._cache:
                            self._cache = dict(self._cache)
                            self._cache["wifi"] = dict(self._cache.get("wifi") or {})
                            self._cache["wifi"]["freshness"] = "cached"
                            self._cache.update({"refreshing": False, "collection_error": scan_error,
                                                "status_message": "Refresh failed; displaying the last successful observation."})
                        else:
                            self._cache = result if result is not None else _failed_snapshot(scan_error, self.os_type)
                            self._cache["refreshing"] = False
                            self._cache["wifi"] = dict(self._cache.get("wifi") or {})
                            self._cache["wifi"]["freshness"] = "unavailable"
                            self._cache_at = time.monotonic()
                        self._cache["scan_attempt"] = dict(self._scan_attempt)
                    self._future = None
                    self._future_generation = None
        return self.live_snapshot()

    def _track_ap_seen(self, snapshot):
        """Annotate genuine scan results with first/last times observed in this process."""
        wifi = (snapshot or {}).get("wifi") or {}
        for ap in wifi.get("nearby_aps") or []:
            identity = ((str(ap.get("bssid") or "").strip().lower() + "|" +
                         str(ap.get("source") or "").strip().lower()) if ap.get("bssid") else
                        "|".join(str(ap.get(key) or "") for key in
                        ("ssid", "channel", "frequency_ghz", "band", "interface", "source"))).strip().lower()
            if not identity:
                continue
            observed = ap.get("observed_at") or wifi.get("observed_at") or self._timestamp()
            first = self._ap_first_seen.setdefault(identity, observed)
            ap["first_seen"] = first
            ap["last_seen"] = observed

    # --------------------------------------------------------------- lifecycle
    def start_background_refresh(self):
        """Start the periodic collector. Safe to call more than once."""
        with self._lock:
            if self._worker and self._worker.is_alive():
                return False
            self._stop.clear()

            def loop():
                while not self._stop.is_set():
                    self.poll_refresh()
                    self._stop.wait(self.refresh_interval)

            self._worker = threading.Thread(target=loop, name="ws-live-refresh", daemon=True)
            self._worker.start()
            log.info("background_refresh_started", extra={"context": {"interval_s": self.refresh_interval}})
            return True

    def stop(self):
        self._stop.set()
        with self._active_scan_lock:
            for job in self._active_device_scans.values():
                if job["status"] == "running":
                    job["cancel"].set()
        with self._lock:
            worker = self._worker
        if worker:
            worker.join(timeout=2)
        self._executor.shutdown(wait=False)
        log.info("background_refresh_stopped")

    def preflight(self):
        """Real capability checks used by the assessment preflight panel."""
        if self.os_type == "Darwin":
            interfaces = self.interfaces()
            info = self.wifi_info()
            devices = self.arp_devices()
            return [
                {"id": "os", "label": "macOS networking", "status": "pass", "detail": platform.platform()},
                {"id": "adapter", "label": "Wi-Fi interface",
                 "status": "pass" if interfaces else ("warn" if info.get("state") == "permission_required" else "fail"),
                 "detail": ", ".join(i.get("name", "Unknown") for i in interfaces) if interfaces else info.get("error", "No Wi-Fi interface exposed.")},
                {"id": "scan", "label": "Nearby BSSID scan",
                 "status": "pass" if info.get("nearby_aps") else "warn",
                 "detail": f"{len(info.get('nearby_aps', []))} BSSID observations" + (f" · {info['error']}" if info.get("error") else "")},
                {"id": "connection", "label": "Current Wi-Fi connection",
                 "status": "pass" if info.get("connected") else "warn",
                 "detail": info.get("ssid") or "Not associated or not exposed by macOS."},
                {"id": "neighbors", "label": "Local neighbor cache",
                 "status": "pass" if devices else "warn", "detail": f"{len(devices)} neighbor observations"},
            ]
        checks = [
            {"id": "os", "label": "Windows networking stack",
             "status": "pass" if self.os_type == "Windows" else "fail",
             "detail": f"{self.os_type} detected"},
        ]
        netsh_ok = bool(self._run(["netsh", "-?"], 4)[1]) if self.os_type == "Windows" else False
        checks.append({"id": "netsh", "label": "netsh WLAN command set",
                       "status": "pass" if netsh_ok else "fail",
                       "detail": "Available" if netsh_ok else "Not available on this host"})
        interfaces = self.interfaces() if netsh_ok else []
        checks.append({"id": "adapter", "label": "Wireless adapter",
                       "status": "pass" if interfaces else "fail",
                       "detail": ", ".join(i.get("name") or i.get("description") or "unnamed" for i in interfaces)
                                 if interfaces else "No Wi-Fi adapter exposed to netsh"})
        info = self.wifi_info() if netsh_ok else {"connected": False, "ssid": None, "nearby_aps": [], "state": "unavailable"}
        checks.append({"id": "connection", "label": "Wi-Fi connection",
                       "status": "pass" if info.get("connected") else "warn",
                       "detail": info.get("ssid") or "Not associated"})
        aps = info.get("nearby_aps", [])
        checks.append({"id": "scan", "label": "Nearby BSSID scan",
                       "status": "pass" if aps else "warn",
                       "detail": f"{len(aps)} BSSID observations"})
        devices = self.arp_devices()
        checks.append({"id": "neighbors", "label": "Neighbor cache discovery",
                       "status": "pass" if devices else "warn",
                       "detail": f"{len(devices)} neighbor observations"})
        return checks


def _describe_failure(returncode, stderr, fallback):
    text = (stderr or "").strip()
    if returncode == -2:
        return "netsh is not available on this host."
    if returncode == -3:
        return "The WLAN service did not answer within the timeout."
    if returncode != 0 and re.search(r"access is denied|requires elevation|denied", text, re.I):
        return "Access denied by the operating system. Run the application with permission to query the WLAN service."
    if returncode != 0 and re.search(r"wireless|wlan", text, re.I) and re.search(r"not|disabled|stopped", text, re.I):
        return "The Windows WLAN AutoConfig service is not available. Wireless interfaces are disabled or the service is stopped."
    return text or fallback


def _status_message(info, devices):
    if info.get("state") == "unsupported_platform":
        return info.get("error") or "Live WLAN telemetry is unavailable on this operating system."
    if info.get("state") == "no_wireless_interface":
        return info.get("error") or "No wireless interface was exposed by the operating system."
    if info.get("state") == "permission_required":
        return info.get("error") or "macOS requires permission to inspect Wi-Fi interfaces."
    if info.get("state") == "scan_unavailable":
        return info.get("error") or "The operating system could not scan nearby wireless networks."
    if info.get("state") == "wlan_unavailable":
        return info.get("error") or "The Windows WLAN stack is unavailable."
    if info.get("state") == "partial":
        return info.get("error") or "Connected network observed; the nearby-network scan did not complete."
    if not info.get("connected") and not info.get("nearby_aps"):
        return "No active Wi-Fi association and no visible BSSIDs were observed."
    if not info.get("connected"):
        return "Not associated to a WLAN; nearby BSSIDs are still being observed."
    if not devices:
        return "Associated to Wi-Fi; the local neighbor cache is currently empty."
    source = "macOS Wi-Fi" if info.get("capability") == "macos_native" else "Windows WLAN"
    return f"Live telemetry collected from {source} and the local neighbor cache."


def _capabilities(os_type=None):
    os_type = os_type or platform.system()
    return {
        "nearby_ap_client_counts": False,
        "client_count_note": CLIENT_COUNT_NOTE,
        "device_type": "inferred_from_hostname_when_available",
        "vendor": "unavailable_offline",
        "ip_address": "local_neighbor_cache",
        "hostname": "reverse_dns_when_available",
        "signal_dbm": "reported_by_macos_airport_when_available" if os_type == "Darwin" else "not_exposed_by_windows_wlan_scan",
        "band": "only_inferred_for_unambiguous_2.4GHz_channels",
    }


def _empty_snapshot(os_type=None):
    os_type = os_type or platform.system()
    capability = "macos_native" if os_type == "Darwin" else ("windows_netsh" if os_type == "Windows" else "unsupported_on_this_os")
    return {
        "ready": False, "refreshing": True, "observed_at": None, "collection_ms": None,
        "wifi": {"connected": False, "nearby_aps": [], "interface": None, "state": "collecting",
                 "capability": capability, "error": None, "freshness": "unavailable"},
        "devices": [], "network": {}, "known_local_devices": 0,
        "capabilities": _capabilities(os_type),
        "status_message": "Collecting live operating-system Wi-Fi and local-network data…",
    }


def _failed_snapshot(error, os_type=None):
    snapshot = _empty_snapshot(os_type)
    snapshot.update({"ready": False, "refreshing": False, "observed_at": RealWiFiEngine._timestamp()})
    snapshot["wifi"]["state"] = "error"
    snapshot["status_message"] = "Live collection failed; showing the last known good state."
    snapshot["error"] = error
    return snapshot


def _scan_outcome(snapshot, exception=None):
    """Classify a completed collector result without confusing failure for empty success."""
    if exception:
        return "error", None, exception
    if not isinstance(snapshot, dict):
        return "error", None, "Live collector returned no snapshot."
    wifi = snapshot.get("wifi") if isinstance(snapshot.get("wifi"), dict) else {}
    source = wifi.get("scan_source") or wifi.get("source") or wifi.get("capability")
    error = snapshot.get("collection_error") or wifi.get("error")
    native_error = wifi.get("native_error")
    if native_error and str(native_error) not in str(error or ""):
        error = f"{error}; Native reason: {native_error}" if error else str(native_error)
    explicit = wifi.get("scan_outcome")
    if explicit in {"success", "empty", "permission_required", "unavailable", "timeout", "error"}:
        outcome = explicit
        if outcome in {"success", "empty"} and error and not wifi.get("fallback_scan_succeeded"):
            outcome = "error"
    else:
        state = str(wifi.get("state") or "").casefold()
        if state in {"permission_required", "permission_denied"}:
            outcome = "permission_required"
        elif state in {"timeout", "timed_out"}:
            outcome = "timeout"
        elif state in {"scan_unavailable", "wlan_unavailable", "no_wireless_interface", "unsupported_platform", "error"}:
            outcome = "unavailable" if state != "error" else "error"
        elif isinstance(wifi.get("nearby_aps"), list) and wifi["nearby_aps"]:
            outcome = "success"
        elif state in {"ok", "empty", "disconnected"} and not error:
            outcome = "empty"
        elif state == "partial" and not error:
            outcome = "empty"
        elif error:
            outcome = "error"
        else:
            outcome = "unavailable"
    return outcome, source, str(error) if error else None
