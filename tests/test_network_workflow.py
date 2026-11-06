import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import main as app
from core.store import Store


class NetworkFirstWorkflowTests(unittest.TestCase):
    def test_permission_failure_remains_visible_without_inventing_networks(self):
        original_store, original_wifi = app.store, app.wifi
        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "permission-scan.db")
            class FakeWiFi:
                def poll_refresh(self):
                    return {"wifi": {"state": "permission_required", "nearby_aps": [],
                                      "error": "macOS permission required"},
                            "scan_attempt": {"status": "permission_required", "error": "macOS permission required",
                                             "started_at": "2026-10-14T10:00:00Z"},
                            "devices": [], "observed_at": "2026-10-14T10:00:00Z"}
            app.store, app.wifi = test_store, FakeWiFi()
            try:
                snapshot = app.Bridge().live_snapshot()
                self.assertEqual(snapshot["scan_attempt"]["status"], "permission_required")
                self.assertEqual(snapshot["wifi"]["state"], "permission_required")
                self.assertEqual(snapshot["wifi"]["nearby_aps"], [])
                self.assertEqual(test_store.observation_history("wireless"), [])
            finally:
                test_store.close()
                app.store, app.wifi = original_store, original_wifi

    def test_selected_real_observation_is_scoped_persisted_and_reopenable(self):
        original_store, original_wifi = app.store, app.wifi
        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "workflow.db")
            observation = {
                "ssid": "Training AP", "bssid": "AA:BB:CC:DD:EE:FF", "auth": "WPA2 Personal",
                "cipher": "CCMP", "channel": 11, "frequency_ghz": 2.4, "band": 2.4,
                "signal_dbm": -42, "interface": "en0", "source": "CoreWLAN",
                "observed_at": "2026-10-10T10:00:00Z",
            }

            class FakeWiFi:
                def poll_refresh(self):
                    return {"wifi": {"nearby_aps": [observation]}}

            app.store, app.wifi = test_store, FakeWiFi()
            try:
                bridge = app.Bridge()
                saved = bridge.analyze_network_observation(dict(observation))
                self.assertEqual(saved["review"]["bssid"], observation["bssid"])
                self.assertIn("advertises WPA2", saved["review"]["summary"])
                self.assertEqual(test_store.evidence_count(saved["assessment_id"], "network_advertisement"), 1)
                self.assertFalse(test_store.assessment(saved["assessment_id"])["authorization"])

                test_store.close()
                app.store = Store(Path(temp_dir) / "workflow.db")
                history = app.Bridge().network_observation_history(dict(observation))
                self.assertEqual(history["assessment_id"], saved["assessment_id"])
                self.assertEqual(history["review"]["source"], "CoreWLAN")
                authorized = app.Bridge().confirm_network_capture_authorization(saved["assessment_id"], True)
                self.assertTrue(authorized["authorization"])
            finally:
                app.store.close()
                app.store, app.wifi = original_store, original_wifi


if __name__ == "__main__":
    unittest.main()
