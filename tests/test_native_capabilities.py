import unittest
from unittest.mock import patch

import main as app
from core.catalog import TEST_CATALOG, requirements


class NativeCapabilityTests(unittest.TestCase):
    def test_catalog_contains_no_remote_connector_tests(self):
        self.assertTrue(TEST_CATALOG)
        self.assertTrue(all(test["execution_path"] == "local" for test in TEST_CATALOG))
        self.assertNotIn("connector", requirements())

    def test_tool_matrix_reports_local_tools_without_remote_systems(self):
        with patch.object(app.shutil, "which", return_value=None):
            matrix = app.Bridge().tool_matrix()

        names = {row["name"] for row in matrix["local"]}
        self.assertTrue({"Nmap", "TShark", "tcpdump", "Aircrack-ng", "hcxtools", "Bettercap", "Wireshark"}.issubset(names))
        self.assertEqual(matrix["os"], app.platform.system())
        self.assertFalse({"connector", "kali_wireless", "kismet_observations"} & set(matrix))

    def test_tool_detection_distinguishes_installed_from_invoked(self):
        completed = type("Result", (), {"returncode": 0, "stdout": "Nmap version 7.99", "stderr": ""})()
        with patch.object(app.shutil, "which", return_value="/usr/bin/nmap"), \
             patch.object(app.subprocess, "run", return_value=completed):
            matrix = app.Bridge().tool_matrix()

        nmap = next(row for row in matrix["local"] if row["executable"] == "nmap")
        self.assertEqual(nmap["status"], "AVAILABLE · INTEGRATED")
        self.assertTrue(nmap["invoked_by_wifisentinel"])
        tshark = next(row for row in matrix["local"] if row["executable"] == "tshark")
        self.assertEqual(tshark["status"], "AVAILABLE · DETECTED")
        self.assertFalse(tshark["invoked_by_wifisentinel"])

    def test_settings_do_not_expose_retired_connector_configuration(self):
        settings = app.Bridge().settings()
        self.assertNotIn("connector_url", settings)


if __name__ == "__main__":
    unittest.main()
