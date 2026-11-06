import unittest
from unittest.mock import patch
from core.nmap_runner import validate_target_scope, parse_ports, NmapRunner


class NmapScopeTests(unittest.TestCase):
    def test_target_must_be_inside_declared_cidr(self):
        self.assertEqual(validate_target_scope("192.168.1.20", "192.168.1.0/24"), "192.168.1.20")
        with self.assertRaises(ValueError):
            validate_target_scope("192.168.2.20", "192.168.1.0/24")

    def test_rejects_hostname_and_missing_scope(self):
        with self.assertRaises(ValueError):
            validate_target_scope("example.com", "192.168.1.0/24")
        with self.assertRaises(ValueError):
            validate_target_scope("192.168.1.20", "")

    def test_port_parser_is_bounded(self):
        self.assertEqual(parse_ports("22,80,443,8000-8002"), [22,80,443,8000,8001,8002])
        with self.assertRaises(ValueError):
            parse_ports("1-300")
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("abc")

    @patch("core.nmap_runner.subprocess.run")
    def test_parses_real_nmap_xml(self, run):
        class Completed:
            returncode = 0
            stderr = ""
            stdout = """<?xml version="1.0"?><nmaprun scanner="nmap" version="7.99" startstr="start">
            <host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
            <service name="https" product="Example" version="1.0"/></port></ports></host>
            <runstats><finished timestr="finish"/></runstats></nmaprun>"""
        run.return_value = Completed()
        result = NmapRunner("/usr/bin/nmap").scan("192.168.1.20", "192.168.1.0/24", "443")
        self.assertEqual(result["host_count"], 1)
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["open_ports"][0]["service"], "https")
        self.assertIn("-oX", result["command"])

    @patch("core.nmap_runner.subprocess.run")
    def test_parses_aggregated_closed_port_states_for_conservative_retest(self, run):
        class Completed:
            returncode = 0
            stderr = ""
            stdout = """<?xml version="1.0"?><nmaprun scanner="nmap" version="7.99">
            <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
            <ports><extraports state="closed" count="2"><extrareasons reason="conn-refused" count="2"/></extraports></ports></host>
            <runstats><finished timestr="finish"/></runstats></nmaprun>"""
        run.return_value = Completed()
        result = NmapRunner("/usr/bin/nmap").scan("127.0.0.1", "127.0.0.0/8", [80, 443])
        self.assertEqual(result["hosts"][0]["extraports"][0]["state"], "closed")
        self.assertEqual(result["hosts"][0]["extraports"][0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
