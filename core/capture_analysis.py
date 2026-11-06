"""Bounded, offline inspection of user-supplied PCAP/PCAPNG files.

Container structure is checked before Scapy decodes individual frames. Only
protocol names, packet counts, network endpoints and selected 802.11 fields are
returned; application-layer payloads are never inspected or included.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import time
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path

MAX_CAPTURE_BYTES = 50 * 1024 * 1024
MAX_CAPTURE_PACKETS = 500_000
MAX_ANALYSIS_SECONDS = 15
MAX_FRAME_BYTES = 16 * 1024 * 1024
PARSER_VERSION = "2.1"
_SUPPORTED_LINKTYPES = {
    0, 1,  # NULL, Ethernet
    101, 105, 113, 119, 127, 192, 276,  # raw IP, 802.11, SLL, Prism, Radiotap, PPI, SLL2
    228, 229,  # IPv4, IPv6
}
_LINKTYPE_NAMES = {
    0: "NULL", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11",
    113: "Linux cooked capture", 119: "Prism", 127: "Radiotap",
    192: "PPI", 228: "IPv4", 229: "IPv6", 276: "Linux cooked capture v2",
}


def capture_size_limit_bytes():
    """Configurable local file limit, clamped to a bounded 1–500 MiB range."""
    try:
        megabytes = int(os.environ.get("WIFISENTINEL_MAX_CAPTURE_MB", "50").strip())
    except (TypeError, ValueError):
        megabytes = 50
    return min(500, max(1, megabytes)) * 1024 * 1024


def _check_deadline(deadline):
    if time.monotonic() > deadline:
        _container_error(f"validation exceeded the {MAX_ANALYSIS_SECONDS} second processing limit.")


def _container_error(message):
    raise ValueError(f"Capture validation failed: {message}")


def _validate_pcap(path, size, deadline):
    magic_map = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            _container_error("truncated PCAP global header.")
        endian, timestamp_base = magic_map[header[:4]]
        major, minor, _zone, _sigfigs, snaplen, raw_linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4):
            _container_error("unsupported PCAP version; version 2.4 is required.")
        if not 0 < snaplen <= MAX_FRAME_BYTES:
            _container_error("invalid PCAP snapshot length.")
        linktype = raw_linktype & 0xffff
        if linktype not in _SUPPORTED_LINKTYPES:
            _container_error(f"unsupported PCAP link type {linktype}.")
        count = 0
        first_timestamp = last_timestamp = None
        while True:
            _check_deadline(deadline)
            record = handle.read(16)
            if not record:
                break
            if len(record) != 16:
                _container_error("truncated packet record header.")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if fraction >= timestamp_base:
                _container_error("invalid packet timestamp fraction.")
            if captured > snaplen or captured > MAX_FRAME_BYTES or original < captured:
                _container_error("invalid packet captured/original length.")
            packet_data = handle.read(captured)
            if len(packet_data) != captured:
                _container_error("truncated packet data.")
            timestamp = seconds + fraction / timestamp_base
            if not math.isfinite(timestamp):
                _container_error("invalid packet timestamp.")
            first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
            last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
            count += 1
            if count > MAX_CAPTURE_PACKETS:
                _container_error(f"packet count exceeds the {MAX_CAPTURE_PACKETS:,} packet analysis limit.")
    return {"capture_format": "pcap", "linktypes": [linktype], "validated_packets": count,
            "first_timestamp": first_timestamp, "last_timestamp": last_timestamp}


def _parse_pcapng_options(data, endian):
    options = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            _container_error("truncated PCAPNG option header.")
        code, length = struct.unpack(endian + "HH", data[offset:offset + 4])
        offset += 4
        if code == 0:
            if length != 0:
                _container_error("invalid PCAPNG end-of-options marker.")
            if any(data[offset:]):
                _container_error("unexpected bytes after PCAPNG end-of-options marker.")
            return options
        padded = (length + 3) & ~3
        if offset + padded > len(data):
            _container_error("truncated PCAPNG option value.")
        options[code] = data[offset:offset + length]
        offset += padded
    return options


def _validate_pcapng(path, size, deadline):
    shb = b"\x0a\x0d\x0d\x0a"
    interfaces = []
    linktypes = set()
    count = 0
    first_timestamp = last_timestamp = None
    endian = None
    section_open = False
    offset = 0
    with path.open("rb") as handle:
        while offset < size:
            _check_deadline(deadline)
            handle.seek(offset)
            prefix = handle.read(12)
            if len(prefix) < 12:
                _container_error("truncated PCAPNG block header.")
            if prefix[:4] == shb:
                marker = prefix[8:12]
                if marker == b"\x4d\x3c\x2b\x1a":
                    new_endian = "<"
                elif marker == b"\x1a\x2b\x3c\x4d":
                    new_endian = ">"
                else:
                    _container_error("invalid PCAPNG byte-order magic.")
                block_length = struct.unpack(new_endian + "I", prefix[4:8])[0]
                block_type = 0x0A0D0D0A
                endian = new_endian
            else:
                if not section_open or endian is None:
                    _container_error("PCAPNG section header is missing.")
                block_type, block_length = struct.unpack(endian + "II", prefix[:8])
            if block_length < 12 or block_length % 4 or block_length > size - offset:
                _container_error("invalid or truncated PCAPNG block length.")
            handle.seek(offset)
            block = handle.read(block_length)
            if len(block) != block_length:
                _container_error("truncated PCAPNG block data.")
            if struct.unpack(endian + "I", block[-4:])[0] != block_length:
                _container_error("PCAPNG block length trailer does not match.")
            if block_type == 0x0A0D0D0A:
                if block_length < 28:
                    _container_error("truncated PCAPNG section header block.")
                major, minor = struct.unpack(endian + "HH", block[12:16])
                if (major, minor) != (1, 0):
                    _container_error("unsupported PCAPNG section version.")
                _parse_pcapng_options(block[24:-4], endian)
                interfaces = []
                section_open = True
            elif block_type == 1:  # Interface Description Block
                if block_length < 20:
                    _container_error("truncated PCAPNG interface description block.")
                linktype = struct.unpack(endian + "H", block[8:10])[0]
                snaplen = struct.unpack(endian + "I", block[12:16])[0]
                if linktype not in _SUPPORTED_LINKTYPES:
                    _container_error(f"unsupported PCAPNG link type {linktype}.")
                if snaplen and snaplen > MAX_FRAME_BYTES:
                    _container_error("invalid PCAPNG interface snapshot length.")
                options = _parse_pcapng_options(block[16:-4], endian)
                resolution = options.get(9, b"\x06")
                if len(resolution) != 1:
                    _container_error("invalid PCAPNG timestamp resolution.")
                value = resolution[0]
                exponent = value & 0x7f
                if (value & 0x80 and exponent > 60) or (not value & 0x80 and exponent > 18):
                    _container_error("invalid PCAPNG timestamp resolution.")
                ticks = (2 ** exponent) if value & 0x80 else (10 ** exponent)
                interfaces.append({"linktype": linktype, "snaplen": snaplen, "ticks": ticks})
                linktypes.add(linktype)
            elif block_type == 6:  # Enhanced Packet Block
                if block_length < 32:
                    _container_error("truncated PCAPNG enhanced packet block.")
                interface_id, high, low, captured, original = struct.unpack(endian + "IIIII", block[8:28])
                if interface_id >= len(interfaces):
                    _container_error("PCAPNG packet references an unknown interface.")
                interface = interfaces[interface_id]
                padded = (captured + 3) & ~3
                if captured > MAX_FRAME_BYTES or original < captured or 28 + padded + 4 > block_length:
                    _container_error("invalid PCAPNG packet captured/original length.")
                if interface["snaplen"] and captured > interface["snaplen"]:
                    _container_error("PCAPNG packet exceeds the interface snapshot length.")
                ticks = (high << 32) | low
                timestamp = ticks / interface["ticks"]
                if not math.isfinite(timestamp):
                    _container_error("invalid PCAPNG packet timestamp.")
                first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
                last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
                count += 1
                if count > MAX_CAPTURE_PACKETS:
                    _container_error(f"packet count exceeds the {MAX_CAPTURE_PACKETS:,} packet analysis limit.")
            elif block_type == 3:  # Simple Packet Block, which has no timestamp
                if block_length < 16 or not interfaces:
                    _container_error("invalid PCAPNG simple packet block.")
                original = struct.unpack(endian + "I", block[8:12])[0]
                snaplen = interfaces[0]["snaplen"]
                available = block_length - 16
                captured = min(original, snaplen or available)
                if captured > available or captured > MAX_FRAME_BYTES:
                    _container_error("invalid PCAPNG simple packet length.")
                count += 1
                if count > MAX_CAPTURE_PACKETS:
                    _container_error(f"packet count exceeds the {MAX_CAPTURE_PACKETS:,} packet analysis limit.")
            elif block_type == 2:  # Obsolete Packet Block
                if block_length < 32:
                    _container_error("truncated PCAPNG packet block.")
                interface_id, high, low, captured, original = struct.unpack(endian + "HHIIII", block[8:24])
                if interface_id >= len(interfaces):
                    _container_error("PCAPNG packet references an unknown interface.")
                interface = interfaces[interface_id]
                padded = (captured + 3) & ~3
                if captured > MAX_FRAME_BYTES or original < captured or 24 + padded + 4 > block_length:
                    _container_error("invalid PCAPNG packet captured/original length.")
                timestamp = ((high << 32) | low) / interface["ticks"]
                if not math.isfinite(timestamp):
                    _container_error("invalid PCAPNG packet timestamp.")
                first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
                last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
                count += 1
                if count > MAX_CAPTURE_PACKETS:
                    _container_error(f"packet count exceeds the {MAX_CAPTURE_PACKETS:,} packet analysis limit.")
            offset += block_length
    if not section_open:
        _container_error("PCAPNG section header is missing.")
    return {"capture_format": "pcapng", "linktypes": sorted(linktypes), "validated_packets": count,
            "first_timestamp": first_timestamp, "last_timestamp": last_timestamp}


def _validate_container(path, size, deadline):
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        info = _validate_pcap(path, size, deadline)
    elif magic == b"\x0a\x0d\x0d\x0a":
        info = _validate_pcapng(path, size, deadline)
    else:
        _container_error("file signature is not PCAP or PCAPNG.")
    if path.suffix.lower() != "." + info["capture_format"]:
        _container_error("file extension does not match the capture format.")
    return info


def _protocol_label(packet, layers):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dot11 import Dot11
    from scapy.layers.eap import EAPOL
    for layer, label in ((EAPOL, "EAPOL"), (Dot11, "802.11"), (ARP, "ARP"),
                         (IPv6, "IPv6"), (IP, "IPv4"), (TCP, "TCP"), (UDP, "UDP"), (Ether, "Ethernet")):
        if packet.haslayer(layer):
            layers[label] += 1
    return


def _packet_bssid(packet, Dot11):
    if not packet.haslayer(Dot11):
        return None
    dot11 = packet[Dot11]
    addr1, addr2, addr3 = (str(getattr(dot11, name, "") or "").upper() for name in ("addr1", "addr2", "addr3"))
    try:
        frame_type = int(dot11.type)
        flags = int(dot11.FCfield)
    except (TypeError, ValueError):
        return None
    if frame_type == 0:
        candidate = addr3
    elif frame_type == 2:
        to_ds, from_ds = bool(flags & 1), bool(flags & 2)
        candidate = addr1 if to_ds and not from_ds else addr2 if from_ds and not to_ds else addr3 if not to_ds and not from_ds else None
    else:
        candidate = None
    return candidate if candidate and candidate != "NONE" else None


def _dns_query_rows(packet, DNS, DNSQR, IP, IPv6, UDP, TCP, Dot11):
    """Extract bounded DNS question metadata without retaining packet payloads."""
    if not packet.haslayer(DNS):
        return []
    try:
        dns = packet[DNS]
        if int(dns.qr) != 0:
            return []
    except (TypeError, ValueError):
        return []
    source_ip = str(packet[IP].src) if packet.haslayer(IP) else str(packet[IPv6].src) if packet.haslayer(IPv6) else None
    resolver_ip = str(packet[IP].dst) if packet.haslayer(IP) else str(packet[IPv6].dst) if packet.haslayer(IPv6) else None
    transport = "UDP" if packet.haslayer(UDP) else "TCP" if packet.haslayer(TCP) else None
    source_port = int(packet[UDP].sport if packet.haslayer(UDP) else packet[TCP].sport) if transport else None
    resolver_port = int(packet[UDP].dport if packet.haslayer(UDP) else packet[TCP].dport) if transport else None
    try:
        timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(timespec="microseconds")
    except (TypeError, ValueError, OverflowError, OSError):
        timestamp = None
    bssid = _packet_bssid(packet, Dot11)
    rows = []
    question_field = getattr(dns, "qd", None)
    questions = list(question_field) if isinstance(question_field, (list, tuple)) else [question_field]
    for question in questions[:16]:
        if not isinstance(question, DNSQR):
            continue
        raw_name = getattr(question, "qname", b"")
        if isinstance(raw_name, bytes):
            try: name = raw_name.decode("ascii").rstrip(".")
            except UnicodeDecodeError: name = ""
        else:
            name = str(raw_name).rstrip(".")
        labels = name.split(".") if name else []
        if (len(name) <= 253 and labels and
                all(0 < len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9_-]+", label) for label in labels)):
            try: qtype = int(question.qtype)
            except (TypeError, ValueError): qtype = None
            rows.append({"query_name": name.lower(), "query_type": qtype,
                         "source_ip": source_ip, "resolver_ip": resolver_ip,
                         "source_port": source_port, "resolver_port": resolver_port,
                         "transport": transport, "timestamp": timestamp, "bssid": bssid})
    return rows


def _pmf_capabilities(rsn_payload):
    """Read RSN capabilities after the bounded suite lists; return unknown on malformed IE."""
    try:
        data = bytes(rsn_payload)
        if len(data) < 8 or int.from_bytes(data[:2], "little") != 1: return None
        offset = 2 + 4
        pairwise = int.from_bytes(data[offset:offset+2], "little"); offset += 2 + 4 * pairwise
        akm = int.from_bytes(data[offset:offset+2], "little"); offset += 2 + 4 * akm
        if offset + 2 > len(data): return None
        caps = int.from_bytes(data[offset:offset+2], "little")
        return {"advertised_capable": bool(caps & (1 << 7)), "advertised_required": bool(caps & (1 << 6)),
                "negotiated_or_enforced": "unknown"}
    except (IndexError, TypeError, ValueError, OverflowError):
        return None
def analyze_capture_file(path, progress=None):
    path = Path(path)
    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Choose a .pcap or .pcapng capture file.")
    try:
        size = path.stat().st_size
    except OSError:
        raise ValueError("Capture file could not be read.") from None
    if not size:
        raise ValueError("Capture file is empty.")
    size_limit = capture_size_limit_bytes()
    if size > size_limit:
        raise ValueError(f"Capture exceeds the {size_limit // (1024 * 1024)} MiB offline-analysis limit.")
    started = time.monotonic()
    deadline = started + MAX_ANALYSIS_SECONDS
    info = _validate_container(path, size, deadline)
    try:
        from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt
        from scapy.layers.dot11 import RadioTap
        from scapy.layers.eap import EAPOL
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.inet import TCP, UDP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.utils import PcapReader
    except ImportError:
        raise RuntimeError("Offline capture analysis requires Scapy. Reinstall the project requirements.") from None

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            _check_deadline(deadline)
            digest.update(chunk)
    packet_count = eapol_count = sae_count = wireless_frames = 0
    ssids = {}
    pairs = {}
    sae_by_bssid = {}
    protocols = Counter()
    endpoints = Counter()
    dns_query_observations = []
    dns_query_count = 0
    endpoints_by_bssid = {}
    eapol_by_bssid = Counter()
    wireless_by_bssid = {}
    management_frames = {"deauthentication": [], "disassociation": [], "protected_management_frames": 0,
                         "protected_management_by_bssid": Counter(), "deauthentication_by_bssid": Counter(),
                         "disassociation_by_bssid": Counter(), "rsn_pmf_advertisements": {},
                         "deauthentication_count": 0, "disassociation_count": 0}
    station_observations = []
    frame_min = frame_max = wire_min = wire_max = None
    try:
        with PcapReader(str(path)) as capture:
            for packet in capture:
                if time.monotonic() > deadline:
                    raise ValueError(f"Capture analysis exceeded the {MAX_ANALYSIS_SECONDS} second processing limit.")
                packet_count += 1
                if packet_count > MAX_CAPTURE_PACKETS:
                    raise ValueError(f"Capture packet count exceeds the {MAX_CAPTURE_PACKETS:,} packet analysis limit.")
                frame_size = len(packet)
                frame_min = frame_size if frame_min is None else min(frame_min, frame_size)
                frame_max = frame_size if frame_max is None else max(frame_max, frame_size)
                wire_size = int(getattr(packet, "wirelen", frame_size) or frame_size)
                wire_min = wire_size if wire_min is None else min(wire_min, wire_size)
                wire_max = wire_size if wire_max is None else max(wire_max, wire_size)
                _protocol_label(packet, protocols)
                dns_rows = _dns_query_rows(packet, DNS, DNSQR, IP, IPv6, UDP, TCP, Dot11)
                dns_query_count += len(dns_rows)
                if len(dns_query_observations) < 500:
                    dns_query_observations.extend(dns_rows[:500 - len(dns_query_observations)])
                if packet.haslayer(IP):
                    for address in (str(packet[IP].src), str(packet[IP].dst)):
                        endpoints[address] += 1
                        bssid = _packet_bssid(packet, Dot11)
                        if bssid:
                            endpoints_by_bssid.setdefault(bssid, Counter())[address] += 1
                if packet.haslayer(IPv6):
                    for address in (str(packet[IPv6].src), str(packet[IPv6].dst)):
                        endpoints[address] += 1
                        bssid = _packet_bssid(packet, Dot11)
                        if bssid:
                            endpoints_by_bssid.setdefault(bssid, Counter())[address] += 1
                if packet.haslayer(Dot11):
                    wireless_frames += 1
                    dot11 = packet[Dot11]
                    bssid = _packet_bssid(packet, Dot11)
                    try:
                        frame_type, subtype = int(dot11.type), int(dot11.subtype)
                    except (TypeError, ValueError):
                        frame_type, subtype = -1, -1
                    try: protected = bool(int(getattr(dot11, 'FCfield', 0)) & 0x40)
                    except (TypeError, ValueError): protected = False
                    if frame_type == 0 and protected:
                        management_frames['protected_management_frames'] += 1
                        if bssid: management_frames['protected_management_by_bssid'][bssid] += 1
                    if frame_type == 0 and subtype in (8, 5):
                        for element in packet.iterpayloads():
                            if isinstance(element, Dot11Elt) and getattr(element, 'ID', None) == 48:
                                pmf = _pmf_capabilities(getattr(element, 'info', b''))
                                if pmf is not None and bssid:
                                    management_frames['rsn_pmf_advertisements'][bssid] = pmf
                                break
                    station_frame_types = {
                        0: "association_request", 2: "reassociation_request",
                        4: "probe_request", 11: "authentication",
                    }
                    station_type = station_frame_types.get(subtype) if frame_type == 0 else None
                    transmitter = str(getattr(dot11, "addr2", "") or "").upper()
                    if (station_type and len(station_observations) < 10_000 and
                            re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", transmitter) and
                            transmitter != "FF:FF:FF:FF:FF:FF"):
                        try:
                            timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(timespec="microseconds")
                        except (TypeError, ValueError, OverflowError, OSError):
                            timestamp = None
                        station_observations.append({
                            "station_mac": transmitter,
                            "frame_type": station_type,
                            "timestamp": timestamp,
                            "source": "Imported PCAP/PCAPNG",
                            "source_capture": path.name,
                            "observation_method": "passive 802.11 management-frame parsing",
                            "associated_bssid": None,
                            "data_class": "imported_capture_observation",
                            "limitations": [
                                "This address was observed in this capture only; it does not establish current presence or AP association.",
                                "Randomized station addresses are not resolved to a person or tracked across sessions.",
                            ],
                        })
                    if frame_type == 0 and subtype in (10, 12):
                        is_deauth = subtype == 12
                        reason = None
                        try:
                            reason_layer = packet.getlayer(Dot11Deauth if is_deauth else Dot11Disas)
                            if reason_layer is not None: reason = int(reason_layer.reason)
                        except (TypeError, ValueError): pass
                        try: timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(timespec='microseconds')
                        except (TypeError, ValueError, OverflowError, OSError): timestamp = None
                        record = {'timestamp': timestamp,
                            'frame_subtype': 'deauthentication' if is_deauth else 'disassociation',
                            'transmitter': str(getattr(dot11, 'addr2', '') or '') or None,
                            'receiver': str(getattr(dot11, 'addr1', '') or '') or None,
                            'bssid': str(getattr(dot11, 'addr3', '') or '') or None,
                            'source_capture': path.name, 'interface': None,
                            'reason_code': reason, 'protected_frame_bit': protected}
                        key = 'deauthentication' if is_deauth else 'disassociation'
                        management_frames[key + '_count'] += 1
                        if bssid: management_frames[key + '_by_bssid'][bssid] += 1
                        if len(management_frames[key]) < 500: management_frames[key].append(record)
                    if bssid:
                        wireless = wireless_by_bssid.setdefault(bssid, {
                            "frames": 0, "frame_subtypes": Counter(), "frequencies": set(), "signals": [],
                        })
                        wireless["frames"] += 1
                        try:
                            frame_type, subtype = int(dot11.type), int(dot11.subtype)
                            type_label = {0: "management", 1: "control", 2: "data", 3: "extension"}.get(frame_type, "unknown")
                            wireless["frame_subtypes"][f"{type_label}-{subtype}"] += 1
                        except (TypeError, ValueError):
                            pass
                        if packet.haslayer(RadioTap):
                            radio = packet[RadioTap]
                            try:
                                frequency = int(radio.ChannelFrequency)
                                if frequency > 0:
                                    wireless["frequencies"].add(frequency)
                            except (TypeError, ValueError):
                                pass
                            try:
                                signal = int(radio.dBm_AntSignal)
                                wireless["signals"].append(signal)
                            except (TypeError, ValueError):
                                pass
                    if packet.haslayer(Dot11Beacon):
                        element = packet.getlayer(Dot11Elt)
                        while element:
                            if getattr(element, "ID", None) == 0:
                                bssid = str(getattr(dot11, "addr3", "") or "").upper()
                                raw_ssid = bytes(element.info).decode("utf-8", "replace")
                                ssids[bssid] = {"ssid": raw_ssid or None, "ssid_observed": True,
                                               "ssid_hidden": not bool(raw_ssid)}
                                break
                            element = element.payload.getlayer(Dot11Elt) if hasattr(element.payload, "getlayer") else None
                    if packet.haslayer(Dot11Auth):
                        try:
                            if int(packet[Dot11Auth].algo) == 3:
                                sae_count += 1
                                bssid = str(getattr(dot11, "addr3", "") or "").upper()
                                if bssid and bssid != "NONE":
                                    sae_by_bssid[bssid] = sae_by_bssid.get(bssid, 0) + 1
                        except (TypeError, ValueError):
                            pass
                    for address in (getattr(dot11, "addr1", None), getattr(dot11, "addr2", None), getattr(dot11, "addr3", None)):
                        if address and str(address).upper() != "NONE":
                            endpoints[str(address).upper()] += 1
                if packet.haslayer(EAPOL):
                    eapol_count += 1
                    bssid = _packet_bssid(packet, Dot11)
                    if bssid:
                        eapol_by_bssid[bssid] += 1
                if not packet.haslayer(EAPOL) or not packet.haslayer(Dot11):
                    if progress and packet_count % 1000 == 0:
                        progress({"stage": "parsing", "packets_examined": packet_count})
                    continue
                eapol = packet[EAPOL]
                if int(getattr(eapol, "type", -1)) != 3:
                    continue
                key = packet.getlayer("EAPOL_KEY")
                if key is None:
                    continue
                try:
                    if int(key.key_type) != 1:
                        continue
                    replay = int(key.key_replay_counter)
                    ack = bool(key.key_ack)
                    mic = bool(key.has_key_mic)
                    install = bool(key.install)
                    secure = bool(key.secure)
                except (TypeError, ValueError, AttributeError):
                    continue
                message = "M1" if ack and not mic else ("M3" if ack and mic and install else
                           ("M2" if not ack and mic and not secure else ("M4" if not ack and mic and secure else None)))
                if not message:
                    continue
                dot11 = packet[Dot11]
                addr1, addr2, addr3 = (str(getattr(dot11, key_name, "") or "").upper()
                                       for key_name in ("addr1", "addr2", "addr3"))
                ap = addr3 if addr3 and addr3 != "NONE" else None
                if ap and addr1 == ap:
                    station = addr2
                elif ap and addr2 == ap:
                    station = addr1
                else:
                    ap, station = None, " / ".join(x for x in (addr1, addr2) if x and x != "NONE") or None
                pair_key = (ap or "unknown AP", station or "unknown station")
                identity = ssids.get(ap, {})
                record = pairs.setdefault(pair_key, {"bssid": ap, "ssid": identity.get("ssid"),
                                                      "ssid_observed": identity.get("ssid_observed", False),
                                                      "ssid_hidden": identity.get("ssid_hidden", False), "peer": station,
                                                      "messages": set(), "replay_counters": {}})
                record["messages"].add(message)
                record["exchange_frames"] = record.get("exchange_frames", 0) + 1
                record["replay_counters"].setdefault(replay, set()).add(message)
                if progress and packet_count % 1000 == 0:
                    progress({"stage": "parsing", "packets_examined": packet_count})
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Capture could not be parsed after structural validation ({type(exc).__name__}).") from None

    if packet_count != info["validated_packets"]:
        raise ValueError("Capture packet count did not match the validated container records.")

    for field in ("deauthentication", "disassociation"):
        for frame in management_frames[field]:
            identity=ssids.get(str(frame.get("bssid") or "").upper(), {})
            frame["ssid"]=identity.get("ssid")
            frame["ssid_observed"]=identity.get("ssid_observed",False)
            frame["ssid_hidden"]=identity.get("ssid_hidden",False)

    for query in dns_query_observations:
        identity=ssids.get(str(query.get("bssid") or "").upper(), {})
        query["ssid"]=identity.get("ssid")
        query["ssid_observed"]=identity.get("ssid_observed",False)

    exchanges = []
    for record in pairs.values():
        observed = sorted(record["messages"])
        replay_messages = record["replay_counters"]
        candidate = any({"M1", "M2"}.issubset(replay_messages.get(counter, set())) and
                        {"M3", "M4"}.issubset(replay_messages.get(counter + 1, set()))
                        for counter in replay_messages)
        exchanges.append({"bssid": record["bssid"], "ssid": record["ssid"],
                          "ssid_observed": record["ssid_observed"], "ssid_hidden": record["ssid_hidden"],
                          "peer": record["peer"], "messages_observed": observed,
                          "exchange_frames": record.get("exchange_frames", 0),
                          "candidate_four_way_exchange": candidate})
    ssid_observations = [{"bssid": bssid, **values} for bssid, values in sorted(ssids.items())]
    result = {
        "filename": path.name, "size_bytes": size, "sha256": digest.hexdigest(),
        "capture_format": info["capture_format"], "parser_version": PARSER_VERSION,
        "linktypes": [{"value": x, "name": _LINKTYPE_NAMES[x]} for x in info["linktypes"]],
        "wireless_metadata_supported": any(x in {105, 119, 127, 192} for x in info["linktypes"]),
        "packets_examined": packet_count, "validated_packets": info["validated_packets"],
        "first_packet_timestamp": info["first_timestamp"], "last_packet_timestamp": info["last_timestamp"],
        "frame_size_min_bytes": frame_min, "frame_size_max_bytes": frame_max,
        "wire_size_min_bytes": wire_min, "wire_size_max_bytes": wire_max,
        "protocol_counts": dict(sorted(protocols.items())), "endpoints": [x for x, _n in endpoints.most_common(128)],
        "dns_query_count": dns_query_count, "dns_query_observations": dns_query_observations,
        "endpoint_count": len(endpoints), "ssid_observations": ssid_observations,
        "endpoint_observations": [{"bssid": bssid, "ssid": ssids.get(bssid, {}).get("ssid"),
                                   "endpoints": [value for value, _n in counter.most_common(128)],
                                   "endpoint_count": len(counter)}
                                  for bssid, counter in sorted(endpoints_by_bssid.items())],
        "wireless_observations": [{"bssid": bssid, "ssid": ssids.get(bssid, {}).get("ssid"),
                                    "ssid_observed": ssids.get(bssid, {}).get("ssid_observed", False),
                                    "ssid_hidden": ssids.get(bssid, {}).get("ssid_hidden", False),
                                    "frames": row["frames"],
                                    "frame_subtype_counts": dict(sorted(row["frame_subtypes"].items())),
                                    "channel_frequencies_mhz": sorted(row["frequencies"]),
                                    "signal_dbm_min": min(row["signals"]) if row["signals"] else None,
                                    "signal_dbm_max": max(row["signals"]) if row["signals"] else None}
                                   for bssid, row in sorted(wireless_by_bssid.items())],
        "eapol_observations": [{"bssid": bssid, "ssid": ssids.get(bssid, {}).get("ssid"), "frames": count}
                               for bssid, count in sorted(eapol_by_bssid.items())],
        "wireless_frames": wireless_frames, "eapol_frames": eapol_count,
        "sae_authentication_frames": sae_count,
        "sae_observations": [{"bssid": bssid, "ssid": ssids.get(bssid, {}).get("ssid"), "frames": count}
                             for bssid, count in sorted(sae_by_bssid.items())],
        "exchange_pairs": exchanges, "candidate_exchanges": sum(bool(x["candidate_four_way_exchange"]) for x in exchanges),
        "management_frame_observations": management_frames,
        "station_observations": station_observations,
        "limitations": [
            "Offline analysis only: no radio transmission, association, password recovery, or live capture was performed.",
            "Application-layer payloads and credentials are not extracted or included in this analysis result.",
            "Packet and protocol totals describe the whole capture; endpoint and wireless exchange identifiers are filtered to the declared assessment scope.",
            "DNS question names are unencrypted metadata, are limited to observed questions, and are filtered by the declared wireless BSSID/SSID scope before persistence. Encrypted DNS and encrypted application content are not decoded.",
            "Candidate WPA 4-way exchange is identified from observed EAPOL message/replay-counter patterns; it is not proof of a usable or complete key exchange.",
            "WPA3-SAE authentication frames are counted separately and are not reported as WPA2-PSK handshakes.",
            "Capture filters, channel coverage, packet loss, timestamps, and capture provenance may limit conclusions.",
            "No password is recovered or tested by this feature.",
        ],
    }
    if progress:
        progress({"stage": "complete", "packets_examined": packet_count})
    return result


def in_wireless_scope(record, scope):
    declared = {value.strip().casefold() for value in str(scope or "").replace(";", ",").split(",") if value.strip()}
    return bool(declared and {str(record.get("bssid") or "").casefold(),
                             str(record.get("ssid") or "").casefold()} & declared)


def scoped_capture_result(result, wireless_scope):
    """Return only exchange details tied to an explicitly declared SSID/BSSID."""
    output = dict(result)
    output["dns_query_observations"] = [row for row in result.get("dns_query_observations", [])
                                        if in_wireless_scope(row, wireless_scope)]
    output["dns_query_scoped_count"] = len(output["dns_query_observations"])
    output["exchange_pairs"] = [row for row in result.get("exchange_pairs", []) if in_wireless_scope(row, wireless_scope)]
    output["candidate_exchanges"] = sum(bool(row.get("candidate_four_way_exchange")) for row in output["exchange_pairs"])
    output["endpoint_observations"] = [row for row in result.get("endpoint_observations", [])
                                       if in_wireless_scope(row, wireless_scope)]
    output["wireless_observations"] = [row for row in result.get("wireless_observations", [])
                                       if in_wireless_scope(row, wireless_scope)]
    scoped_endpoints = set()
    for row in output["endpoint_observations"]:
        scoped_endpoints.update(row.get("endpoints") or [])
    output["endpoints"] = sorted(scoped_endpoints)[:128]
    output["endpoint_count"] = len(scoped_endpoints)
    output["eapol_observations"] = [row for row in result.get("eapol_observations", [])
                                    if in_wireless_scope(row, wireless_scope)]
    output["eapol_frames"] = sum(int(row.get("frames", 0)) for row in output["eapol_observations"])
    output["sae_observations"] = [row for row in result.get("sae_observations", []) if in_wireless_scope(row, wireless_scope)]
    output["sae_authentication_frames"] = sum(int(row.get("frames", 0)) for row in output["sae_observations"])
    output["ssid_observations"] = [row for row in result.get("ssid_observations", []) if in_wireless_scope(row, wireless_scope)]
    management = dict(result.get("management_frame_observations") or {})
    for field in ("deauthentication", "disassociation"):
        management[field] = [row for row in management.get(field, []) if in_wireless_scope(row, wireless_scope)]
        count_map={bssid:int(count) for bssid,count in (management.get(field + "_by_bssid") or {}).items()
                   if in_wireless_scope({"bssid":bssid,"ssid":ssids.get(bssid,{}).get("ssid")},wireless_scope)}
        management[field + "_by_bssid"] = count_map
        management[field + "_count"] = sum(count_map.values())
    management["rsn_pmf_advertisements"] = {bssid: value for bssid, value in (management.get("rsn_pmf_advertisements") or {}).items()
        if in_wireless_scope({"bssid":bssid,"ssid":ssids.get(bssid,{}).get("ssid")}, wireless_scope)}
    management["protected_management_by_bssid"]={bssid:int(count) for bssid,count in (management.get("protected_management_by_bssid") or {}).items()
        if in_wireless_scope({"bssid":bssid,"ssid":ssids.get(bssid,{}).get("ssid")},wireless_scope)}
    management["protected_management_frames"]=sum(management["protected_management_by_bssid"].values())
    output["management_frame_observations"] = management
    output["scope_filter"] = "Explicit wireless scope; off-scope/unknown-AP exchange details omitted."
    return output
