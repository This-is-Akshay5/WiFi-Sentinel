import unittest
import time
from concurrent.futures import Future

from core.wifi_engine import RealWiFiEngine


class DiscoveryStateTests(unittest.TestCase):
    @staticmethod
    def complete(engine, generation, snapshot):
        future = Future()
        future.set_result(snapshot)
        engine._generation = generation
        engine._future_generation = generation
        engine._scan_attempt = {"id": generation, "status": "scanning",
                                "started_at": "2026-10-14T10:00:12Z",
                                "finished_at": None, "successful_at": None,
                                "source": None, "error": None}
        engine._future = future

    def test_permission_failure_keeps_last_successful_networks_cached(self):
        engine = RealWiFiEngine()
        try:
            engine._cache = {
                "ready": True,
                "refreshing": True,
                "observed_at": "2026-10-14T10:00:00Z",
                "wifi": {
                    "state": "ok",
                    "freshness": "live",
                    "observed_at": "2026-10-14T10:00:00Z",
                    "nearby_aps": [{
                        "ssid": "Evidence-backed network",
                        "bssid": "02:00:00:00:00:01",
                        "source": "Test adapter",
                        "observed_at": "2026-10-14T10:00:00Z",
                    }],
                },
            }
            future = Future()
            future.set_result({
                "ready": True,
                "refreshing": False,
                "observed_at": "2026-10-14T10:00:12Z",
                "wifi": {
                    "state": "permission_required",
                    "error": "OS scan permission required",
                    "nearby_aps": [],
                },
                "devices": [],
                "network": {},
            })
            engine._generation = 1
            engine._future_generation = 1
            engine._scan_attempt = {"id": 1, "status": "scanning",
                                    "started_at": "2026-10-14T10:00:12Z",
                                    "finished_at": None, "successful_at": "2026-10-14T10:00:00Z",
                                    "source": None, "error": None}
            engine._future = future

            snapshot = engine.poll_refresh()

            self.assertEqual(
                [ap["ssid"] for ap in snapshot["wifi"]["nearby_aps"]],
                ["Evidence-backed network"],
                "a permission failure must retain the last successful observation",
            )
            self.assertEqual(snapshot["wifi"]["freshness"], "cached")
            self.assertEqual(snapshot["wifi"]["observed_at"], "2026-10-14T10:00:00Z")
            self.assertEqual(snapshot["scan_attempt"]["status"], "permission_required")
        finally:
            engine.stop()

    def test_successful_empty_scan_is_live_empty_and_keeps_history_timestamp(self):
        engine = RealWiFiEngine()
        try:
            engine._cache = {
                "ready": True,
                "wifi": {"state": "ok", "freshness": "live", "observed_at": "old",
                         "nearby_aps": [{"ssid": "Previously observed"}]},
            }
            engine._cache_at = time.monotonic()
            self.complete(engine, 2, {
                "ready": True,
                "observed_at": "2026-10-14T10:00:24Z",
                "wifi": {"state": "empty", "scan_outcome": "empty", "nearby_aps": [],
                         "observed_at": "2026-10-14T10:00:24Z", "source": "Test adapter"},
                "devices": [],
                "network": {},
            })

            snapshot = engine.poll_refresh()

            self.assertEqual(snapshot["wifi"]["nearby_aps"], [])
            self.assertEqual(snapshot["wifi"]["freshness"], "live")
            self.assertEqual(snapshot["scan_attempt"]["status"], "empty")
            self.assertTrue(snapshot["scan_attempt"]["successful_at"])
        finally:
            engine.stop()

    def test_scan_timeout_is_a_distinct_failed_attempt_and_keeps_last_success(self):
        engine = RealWiFiEngine()
        try:
            engine._cache = {"ready": True, "wifi": {"state": "ok", "freshness": "live",
                "observed_at": "2026-10-14T10:00:00Z", "nearby_aps": [{"bssid": "02:00:00:00:00:01"}]}}
            engine._cache_at = time.monotonic()
            self.complete(engine, 3, {"ready": True, "wifi": {"state": "timeout", "scan_outcome": "timeout",
                "error": "Native wireless scan exceeded its time limit.", "nearby_aps": []}, "devices": [], "network": {}})
            snapshot = engine.poll_refresh()
            self.assertEqual(snapshot["scan_attempt"]["status"], "timeout")
            self.assertEqual(snapshot["wifi"]["freshness"], "cached")
            self.assertEqual(snapshot["wifi"]["observed_at"], "2026-10-14T10:00:00Z")
        finally:
            engine.stop()

    def test_multiple_native_ap_observations_publish_as_live_with_identifiers_intact(self):
        engine = RealWiFiEngine()
        try:
            aps = [
                {"ssid": f"Network {index}", "bssid": f"02:00:00:00:00:0{index}",
                 "ssid_observed": True, "source": "macOS CoreWLAN"}
                for index in range(1, 4)
            ]
            self.complete(engine, 4, {"ready": True, "observed_at": "2026-10-15T00:00:00Z",
                "wifi": {"state": "ok", "scan_outcome": "success", "nearby_aps": aps,
                         "observed_at": "2026-10-15T00:00:00Z", "scan_source": "CoreWLAN"},
                "devices": [], "network": {}})
            snapshot = engine.poll_refresh()
            self.assertEqual(snapshot["scan_attempt"]["status"], "success")
            self.assertEqual([(row["ssid"], row["bssid"]) for row in snapshot["wifi"]["nearby_aps"]],
                             [(row["ssid"], row["bssid"]) for row in aps])
            self.assertEqual(snapshot["wifi"]["freshness"], "live")
        finally:
            engine.stop()

    def test_scan_attempt_preserves_native_error_beside_friendly_permission_message(self):
        from core.wifi_engine import _scan_outcome
        outcome, source, error = _scan_outcome({"wifi": {
            "state": "permission_required", "scan_outcome": "permission_required",
            "error": "Allow Location Services", "native_error": "AuthorizationCreate() failed: -60008",
            "scan_source": "CoreWLAN"}})
        self.assertEqual(outcome, "permission_required")
        self.assertEqual(source, "CoreWLAN")
        self.assertIn("Allow Location Services", error)
        self.assertIn("AuthorizationCreate() failed: -60008", error)

    def test_stale_generation_is_discarded_without_replacing_newer_snapshot(self):
        engine = RealWiFiEngine()
        try:
            engine._cache = {"ready": True, "wifi": {"state": "ok", "freshness": "live",
                                                        "nearby_aps": [{"ssid": "Newer observation"}]}}
            engine._cache_at = time.monotonic()
            engine._generation = 2
            engine._future_generation = 1
            engine._scan_attempt = {"id": 2, "status": "success", "started_at": "now",
                                    "finished_at": "now", "successful_at": "now",
                                    "source": "newer source", "error": None}
            old = Future()
            old.set_result({"ready": True, "wifi": {"state": "ok", "nearby_aps": [{"ssid": "Old result"}]}})
            engine._future = old

            snapshot = engine.poll_refresh()

            self.assertEqual(snapshot["wifi"]["nearby_aps"][0]["ssid"], "Newer observation")
            self.assertEqual(snapshot["scan_attempt"]["id"], 2)
            self.assertIsNone(engine._future)
        finally:
            engine.stop()


if __name__ == "__main__":
    unittest.main()
