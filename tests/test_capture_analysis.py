import tempfile
import struct
import unittest
from pathlib import Path

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, EAPOL, EAPOL_KEY, LLC, RadioTap, SNAP
from scapy.utils import PcapNgWriter, wrpcap

from core.capture_analysis import analyze_capture_file, capture_size_limit_bytes, scoped_capture_result


def packet_pair(ap, station, ssid):
    packets = [RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap)
               / Dot11Beacon() / Dot11Elt(ID="SSID", info=ssid.encode())]
    messages = [
        ({"key_ack": 1, "has_key_mic": 0}, 10, True),
        ({"key_ack": 0, "has_key_mic": 1, "secure": 0}, 10, False),
        ({"key_ack": 1, "has_key_mic": 1, "install": 1}, 11, True),
        ({"key_ack": 0, "has_key_mic": 1, "secure": 1}, 11, False),
    ]
    for fields, counter, from_ap in messages:
        addr1, addr2 = (station, ap) if from_ap else (ap, station)
        packets.append(RadioTap() / Dot11(type=2, FCfield=2 if from_ap else 1,
                         addr1=addr1, addr2=addr2, addr3=ap) / LLC() / SNAP(code=0x888e)
                       / EAPOL(version=2, type=3) / EAPOL_KEY(key_type=1, key_descriptor_type_version=2,
                         key_replay_counter=counter, **fields))
    return packets


class CaptureAnalysisTests(unittest.TestCase):
    def test_dns_query_metadata_is_parsed_without_application_payload(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, Raw
        packet = (Ether() / IP(src="192.168.1.9", dst="192.168.1.1") / UDP(sport=53000, dport=53)
                  / DNS(rd=1, qd=DNSQR(qname="printer.local", qtype="A")) / Raw(load=b"must-not-be-exported"))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dns.pcap"
            wrpcap(str(path), [packet])
            result = analyze_capture_file(path)
        self.assertEqual(result["dns_query_count"], 1)
        observation = result["dns_query_observations"][0]
        self.assertEqual(observation["query_name"], "printer.local")
        self.assertEqual(observation["source_ip"], "192.168.1.9")
        self.assertEqual(observation["resolver_ip"], "192.168.1.1")
        self.assertNotIn("payload", observation)
        self.assertNotIn(b"must-not-be-exported", repr(observation).encode())

    def test_dns_names_are_exposed_only_when_access_point_matches_wireless_scope(self):
        data = {"dns_query_count": 2, "dns_query_observations": [
            {"query_name": "one.example", "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Authorized"},
            {"query_name": "two.example", "bssid": "AA:BB:CC:DD:EE:00", "ssid": "Other"},
        ]}
        scoped = scoped_capture_result(data, "aa:bb:cc:dd:ee:ff")
        self.assertEqual([x["query_name"] for x in scoped["dns_query_observations"]], ["one.example"])
        self.assertEqual(scoped["dns_query_count"], 2)
        self.assertEqual(scoped["dns_query_scoped_count"], 1)
        self.assertEqual(scoped_capture_result(data, "")["dns_query_observations"], [])

    def test_probe_request_produces_capture_scoped_station_observation(self):
        station = "02:11:22:33:44:55"
        packet = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                   addr2=station, addr3="ff:ff:ff:ff:ff:ff")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "probe.pcap"
            wrpcap(str(path), [packet])
            result = analyze_capture_file(path)
        self.assertEqual(len(result["station_observations"]), 1)
        observation = result["station_observations"][0]
        self.assertEqual(observation["station_mac"], station)
        self.assertEqual(observation["frame_type"], "probe_request")
        self.assertEqual(observation["source_capture"], "probe.pcap")
        self.assertIsNone(observation["associated_bssid"])
        self.assertEqual(observation["data_class"], "imported_capture_observation")

    def test_management_deauth_reason_and_rsn_pmf_advertisement_are_reported_conservatively(self):
        from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, Dot11Elt, RadioTap
        from scapy.packet import Raw
        ap, station = "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"
        rsn = (b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x04" +
               b"\x01\x00" + b"\x00\x0f\xac\x02" + b"\xc0\x00")
        packets = [RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap)
                   / Dot11Beacon() / Dot11Elt(ID=48, info=rsn),
                   RadioTap() / Dot11(type=0, subtype=12, addr1=station, addr2=ap, addr3=ap)
                   / Dot11Deauth(reason=7),
                   RadioTap() / Dot11(type=0, subtype=10, addr1=station, addr2=ap, addr3=ap)
                   / Dot11Disas(reason=8),
                   RadioTap() / Dot11(type=0, subtype=13, FCfield=0x40, addr1=station, addr2=ap, addr3=ap)
                   / Raw(load=b"protected-action")]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "management.pcap"
            wrpcap(str(path), packets)
            result = analyze_capture_file(path)["management_frame_observations"]
            self.assertEqual(result["deauthentication_count"], 1)
            self.assertEqual(result["deauthentication"][0]["transmitter"].upper(), ap)
            self.assertEqual(result["deauthentication"][0]["receiver"].upper(), station)
            self.assertEqual(result["deauthentication"][0]["reason_code"], 7)
            self.assertEqual(result["deauthentication"][0]["interface"], None)
            self.assertEqual(result["deauthentication"][0]["source_capture"], "management.pcap")
            self.assertEqual(result["disassociation_count"], 1)
            self.assertEqual(result["disassociation"][0]["reason_code"], 8)
            self.assertEqual(result["protected_management_frames"], 1)
            self.assertEqual(result["rsn_pmf_advertisements"][ap], {
                "advertised_capable": True, "advertised_required": True, "negotiated_or_enforced": "unknown"})

    def test_capture_size_limit_can_be_configured_and_is_bounded(self):
        from unittest.mock import patch
        with patch.dict("os.environ", {"WIFISENTINEL_MAX_CAPTURE_MB": "20"}):
            self.assertEqual(capture_size_limit_bytes(), 20 * 1024 * 1024)
        with patch.dict("os.environ", {"WIFISENTINEL_MAX_CAPTURE_MB": "9999"}):
            self.assertEqual(capture_size_limit_bytes(), 500 * 1024 * 1024)
    def test_pcap_and_pcapng_detect_candidate_message_patterns(self):
        ap, station = "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"
        packets = packet_pair(ap, station, "Authorized Lab")
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "sample.pcap"
            wrpcap(str(pcap), packets)
            result = analyze_capture_file(pcap)
            self.assertEqual(result["candidate_exchanges"], 1)
            self.assertEqual(result["exchange_pairs"][0]["messages_observed"], ["M1", "M2", "M3", "M4"])
            self.assertTrue(result["exchange_pairs"][0]["candidate_four_way_exchange"])
            self.assertEqual(result["exchange_pairs"][0]["ssid"], "Authorized Lab")
            pcapng = Path(td) / "sample.pcapng"
            writer = PcapNgWriter(str(pcapng))
            for packet in packets:
                writer.write(packet)
            writer.close()
            self.assertEqual(analyze_capture_file(pcapng)["packets_examined"], len(packets))

    def test_capture_details_are_filtered_to_exact_declared_scope(self):
        scoped = packet_pair("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "Authorized Lab")
        other = packet_pair("AA:BB:CC:DD:EE:00", "11:22:33:44:55:00", "Other AP")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mixed.pcap"
            wrpcap(str(path), scoped + other)
            result = analyze_capture_file(path)
            filtered = scoped_capture_result(result, "aa:bb:cc:dd:ee:ff")
            self.assertEqual(len(filtered["exchange_pairs"]), 1)
            self.assertEqual(filtered["exchange_pairs"][0]["ssid"], "Authorized Lab")
            self.assertEqual(filtered["eapol_frames"], 4)
            self.assertEqual(filtered["candidate_exchanges"], 1)

    def test_wrong_extension_and_empty_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.txt"
            path.write_text("not a capture")
            with self.assertRaisesRegex(ValueError, "Choose a .pcap"):
                analyze_capture_file(path)
            path = Path(td) / "empty.pcap"
            path.touch()
            with self.assertRaisesRegex(ValueError, "empty"):
                analyze_capture_file(path)

    def test_capture_size_limit_is_enforced_before_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "too-large.pcap"
            with path.open("wb") as handle:
                handle.truncate(50 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, "50 MiB"):
                analyze_capture_file(path)

    def test_valid_header_only_pcap_is_a_persistable_empty_capture(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "empty-valid.pcap"
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
            result = analyze_capture_file(path)
            self.assertEqual(result["packets_examined"], 0)
            self.assertEqual(result["capture_format"], "pcap")
            self.assertEqual(result["exchange_pairs"], [])

    def test_truncated_packet_record_is_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "truncated.pcap"
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
            record = struct.pack("<IIII", 1, 0, 20, 20) + b"short"
            path.write_bytes(header + record)
            with self.assertRaisesRegex(ValueError, "truncated"):
                analyze_capture_file(path)

    def test_unsupported_pcap_link_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "unsupported.pcap"
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 999))
            with self.assertRaisesRegex(ValueError, "unsupported.*link type"):
                analyze_capture_file(path)

    def test_invalid_pcap_timestamp_fraction_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "invalid-time.pcap"
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
            record = struct.pack("<IIII", 1, 1_000_000, 0, 0)
            path.write_bytes(header + record)
            with self.assertRaisesRegex(ValueError, "timestamp"):
                analyze_capture_file(path)

    def test_malformed_pcapng_block_trailer_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "malformed.pcapng"
            writer = PcapNgWriter(str(path))
            writer.write(RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                             addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon())
            writer.close()
            data = bytearray(path.read_bytes())
            data[-1] ^= 0x01
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "trailer"):
                analyze_capture_file(path)

    def test_valid_empty_pcapng_is_distinct_from_an_empty_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "empty-valid.pcapng"
            writer = PcapNgWriter(str(path))
            writer.close()
            result = analyze_capture_file(path)
            self.assertEqual(result["capture_format"], "pcapng")
            self.assertEqual(result["packets_examined"], 0)

    def test_ethernet_capture_does_not_claim_wireless_ap_identity(self):
        from scapy.all import Ether, IP, Raw
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ethernet.pcap"
            wrpcap(str(path), [Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x0800)
                               / IP(src="192.0.2.1", dst="192.0.2.2") / Raw(b"x")])
            result = analyze_capture_file(path)
            self.assertEqual(result["wireless_metadata_supported"], False)
            self.assertEqual(result["exchange_pairs"], [])
            self.assertEqual(result["endpoint_count"], 2)

    def test_extension_must_match_capture_header(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.pcapng"
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
            with self.assertRaisesRegex(ValueError, "extension"):
                analyze_capture_file(path)

    def test_scoped_result_omits_endpoints_for_other_access_points(self):
        from scapy.all import IP
        from scapy.layers.dot11 import Dot11
        from scapy.layers.l2 import LLC, SNAP
        ap = "AA:BB:CC:DD:EE:FF"
        other = "AA:BB:CC:DD:EE:00"
        packets = [RadioTap() / Dot11(type=2, addr1="11:22:33:44:55:66", addr2="66:55:44:33:22:11", addr3=ap)
                   / LLC() / SNAP(code=0x0800) / IP(src="192.0.2.1", dst="192.0.2.2"),
                   RadioTap() / Dot11(type=2, addr1="11:22:33:44:55:00", addr2="66:55:44:33:22:00", addr3=other)
                   / LLC() / SNAP(code=0x0800) / IP(src="198.51.100.1", dst="198.51.100.2")]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mixed-endpoints.pcap"
            wrpcap(str(path), packets)
            result = scoped_capture_result(analyze_capture_file(path), ap)
            self.assertEqual(result["endpoints"], ["192.0.2.1", "192.0.2.2"])
            self.assertEqual(result["endpoint_count"], 2)

    def test_radiotap_channel_frequency_signal_and_80211_frame_counts_are_extracted(self):
        from scapy.layers.dot11 import Dot11
        ap = "AA:BB:CC:DD:EE:FF"
        packet = RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2412, dBm_AntSignal=-47) / \
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap) / Dot11Beacon() / \
            Dot11Elt(ID="SSID", info=b"Lab")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "radiotap.pcap"
            wrpcap(str(path), [packet])
            result = scoped_capture_result(analyze_capture_file(path), ap)
            observation = result["wireless_observations"][0]
            self.assertEqual(observation["bssid"], ap)
            self.assertEqual(observation["channel_frequencies_mhz"], [2412])
            self.assertEqual(observation["signal_dbm_min"], -47)
            self.assertEqual(observation["frame_subtype_counts"], {"management-8": 1})


if __name__ == "__main__":
    unittest.main()
