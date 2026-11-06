import unittest

from core.rogue_ap import compare_access_points, in_wireless_scope, normalize_bssid


class AccessPointInventoryTests(unittest.TestCase):
    def test_normalizes_bssid_without_accepting_multicast_or_invalid_values(self):
        self.assertEqual(normalize_bssid("AA-BB-CC-DD-EE-01"), "aa:bb:cc:dd:ee:01")
        for value in ("not-a-mac", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:00:00:00:01"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_bssid(value)

    def test_exact_bssid_inventory_matching_preserves_observations(self):
        rows = compare_access_points(
            [
                {"ssid": "Office", "bssid": "AA:BB:CC:DD:EE:01", "channel": 36, "source": "OS WLAN"},
                {"ssid": "Office", "bssid": "aa:bb:cc:dd:ee:02", "channel": 40, "source": "OS WLAN"},
                {"ssid": "Hidden", "bssid": None, "ssid_observed": False, "source": "OS WLAN"},
            ],
            [{"ssid": "Office", "bssid": "aa:bb:cc:dd:ee:01"}],
        )
        self.assertEqual([row["status"] for row in rows], ["approved", "unlisted", "identity_unavailable"])
        self.assertEqual(rows[1]["bssid"], "aa:bb:cc:dd:ee:02")
        self.assertEqual(rows[1]["conclusion"], "Unlisted observation; requires investigation.")
        self.assertIsNone(rows[2]["ssid"])
        self.assertFalse(rows[2]["ssid_observed"])

    def test_duplicate_ssid_does_not_become_a_security_finding(self):
        rows = compare_access_points(
            [
                {"ssid": "Guest", "bssid": "02:00:00:00:00:01"},
                {"ssid": "Guest", "bssid": "02:00:00:00:00:02"},
            ],
            [],
        )
        self.assertTrue(all(row["status"] == "unlisted" for row in rows))
        self.assertTrue(all("rogue" not in row["conclusion"].lower() for row in rows))

    def test_invalid_inventory_rows_are_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            compare_access_points([], [{"bssid": "invalid"}])

    def test_scope_uses_only_observed_ssid_or_valid_bssid(self):
        self.assertFalse(in_wireless_scope(
            {"ssid": "placeholder", "ssid_observed": False, "bssid": None}, "placeholder"))
        self.assertTrue(in_wireless_scope(
            {"ssid": "placeholder", "ssid_observed": False, "bssid": "02:00:00:00:00:01"},
            "02:00:00:00:00:01"))
        self.assertTrue(in_wireless_scope({"ssid": "Office"}, "office"))


class AccessPointBridgePersistenceTests(unittest.TestCase):
    def test_review_requires_authorization_and_persists_scoped_evidence(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "ap-review.db")
            original_store = app.store
            try:
                app.store = test_store
                assessment = test_store.create_assessment({
                    "name": "Authorized wireless review", "authorization": True,
                    "wireless_scope": "02:00:00:00:00:01,02:00:00:00:00:02",
                })
                bridge = app.Bridge()
                bridge.live_snapshot = lambda: {
                    "refreshing": False,
                    "scan_attempt": {"status": "success", "successful_at": "2026-10-31T12:00:00Z"},
                    "wifi": {"scan_source": "OS WLAN", "observed_at": "2026-10-31T12:00:00Z",
                             "nearby_aps": [
                                 {"ssid": "Office", "ssid_observed": True,
                                  "bssid": "02:00:00:00:00:01", "source": "OS WLAN"},
                                 {"ssid": "Outside", "ssid_observed": True,
                                  "bssid": "02:00:00:00:00:02", "source": "OS WLAN"},
                             ]},
                }
                with self.assertRaisesRegex(ValueError, "Confirm authorization"):
                    bridge.run_rogue_ap_review(assessment["id"], False)
                bridge.save_approved_ap("02:00:00:00:00:01", "Office", authorized=True)
                result = bridge.run_rogue_ap_review(assessment["id"], True)
                self.assertEqual([row["status"] for row in result["observations"]], ["approved", "unlisted"])
                self.assertEqual(len(result["finding_ids"]), 1)
                state = test_store.state(assessment["id"])
                self.assertEqual(len(state["evidence"]), 1)
                self.assertEqual(state["evidence"][0]["data_class"], "live")
                self.assertEqual(state["executions"][0]["status"], "completed")
                self.assertEqual(state["findings"][0]["validation"],
                                 "Unverified observation; not a confirmed rogue access point.")
            finally:
                app.store = original_store
                test_store.close()


if __name__ == "__main__":
    unittest.main()
