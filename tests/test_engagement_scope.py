import unittest
from datetime import datetime, timezone

from core.engagement_scope import authorize_execution


class EngagementScopeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
        self.assessment = {"authorization": 1, "network_scope": "192.168.5.0/24"}
        self.policy = {
            "active": True,
            "testing_start": "2026-10-31T11:00:00Z",
            "testing_end": "2026-10-31T13:00:00Z",
            "permitted_activities": ["nmap_scan"],
            "excluded_hosts": [],
            "excluded_ip_ranges": [],
            "testing_windows": [],
        }

    def test_valid_in_scope_permitted_activity_is_allowed(self):
        result = authorize_execution(self.assessment, self.policy, "nmap_scan", "192.168.5.8", self.now)
        self.assertTrue(result["allowed"])

    def test_missing_authorization_or_inactive_scope_is_blocked(self):
        self.assertFalse(authorize_execution({**self.assessment, "authorization": 0}, self.policy,
                                             "nmap_scan", "192.168.5.8", self.now)["allowed"])
        self.assertFalse(authorize_execution(self.assessment, {**self.policy, "active": False},
                                             "nmap_scan", "192.168.5.8", self.now)["allowed"])

    def test_expired_or_malformed_time_window_is_blocked(self):
        expired = {**self.policy, "testing_end": "2026-10-31T11:59:59Z"}
        malformed = {**self.policy, "testing_start": "not-a-time"}
        self.assertFalse(authorize_execution(self.assessment, expired, "nmap_scan", "192.168.5.8", self.now)["allowed"])
        self.assertFalse(authorize_execution(self.assessment, malformed, "nmap_scan", "192.168.5.8", self.now)["allowed"])

    def test_activity_allow_list_and_schedule_window_are_enforced(self):
        disallowed = authorize_execution(self.assessment, self.policy, "port_assessment", "192.168.5.8", self.now)
        outside = authorize_execution(self.assessment, {**self.policy, "testing_windows": [
            {"start": "2026-10-31T14:00:00Z", "end": "2026-10-31T15:00:00Z"}
        ]}, "nmap_scan", "192.168.5.8", self.now)
        self.assertFalse(disallowed["allowed"])
        self.assertFalse(outside["allowed"])

    def test_excluded_ip_and_host_are_blocked(self):
        policy = {**self.policy, "excluded_hosts": ["192.168.5.8"],
                  "excluded_ip_ranges": ["192.168.5.16/28"]}
        self.assertFalse(authorize_execution(self.assessment, policy, "nmap_scan", "192.168.5.8", self.now)["allowed"])
        self.assertFalse(authorize_execution(self.assessment, policy, "nmap_scan", "192.168.5.20", self.now)["allowed"])


class EngagementPersistenceTests(unittest.TestCase):
    def test_scope_manifest_is_versioned_and_changes_are_audited(self):
        import tempfile
        from pathlib import Path
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            store = Store(Path(temp_dir) / "scope.db")
            try:
                record = store.create_assessment({"name": "Scoped engagement", "scope_policy": {
                    "active": True, "testing_start": "2026-10-31T11:00:00Z",
                    "testing_end": "2026-10-31T13:00:00Z", "permitted_activities": ["nmap_scan"]}})
                self.assertTrue(store.scope_policy(record["id"])["active"])
                store.set_scope_policy(record["id"], {"active": False, "permitted_activities": []})
                history = store.scope_history(record["id"])
                self.assertEqual(len(history), 2)
                self.assertFalse(history[0]["policy"]["active"])
            finally:
                store.close()

    def test_v11_upgrade_creates_scope_tables_and_preserves_records(self):
        import sqlite3
        import tempfile
        from pathlib import Path
        from core.store import Store, SCHEMA_VERSION

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "legacy-v11.db"
            store = Store(path)
            assessment = store.create_assessment({"name": "Existing data"})
            store.add_evidence(assessment["id"], None, "test", "fixture", {"marker": "preserved"})
            store.db.execute("DROP TABLE scope_change_history")
            store.db.execute("DROP TABLE engagement_scopes")
            store.db.execute("PRAGMA user_version=11")
            store.close()
            upgraded = Store(path)
            try:
                self.assertEqual(upgraded.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                self.assertEqual(upgraded.state(assessment["id"])["assessment"]["name"], "Existing data")
                self.assertEqual(len(upgraded.evidence(assessment["id"])), 1)
                self.assertFalse(upgraded.scope_policy(assessment["id"])["active"])
            finally:
                upgraded.close()


if __name__ == "__main__":
    unittest.main()
