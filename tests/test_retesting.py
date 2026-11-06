import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from core.retesting import classify_finding_retest
from core.store import SCHEMA_VERSION, Store


class FindingRetestTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "id": "FND-1", "title": "Gateway exposes management services", "asset": "192.168.1.1",
            "source_test": "Gateway TCP exposure", "category": "Network Security",
        }
        self.completed = {"status": "completed", "evidence_id": "EVD-NEW", "execution_id": "EXE-NEW"}

    def test_same_title_and_asset_is_unresolved(self):
        fresh = [{**self.finding, "id": "FND-2"}]
        result = classify_finding_retest(self.finding, self.completed, fresh)
        self.assertEqual(result["status"], "unresolved")
        self.assertEqual(result["evidence_id"], "EVD-NEW")

    def test_different_title_on_same_asset_and_check_is_partial(self):
        fresh = [{**self.finding, "id": "FND-2", "title": "One management service remains"}]
        self.assertEqual(classify_finding_retest(self.finding, self.completed, fresh)["status"], "partial")

    def test_absent_finding_without_rule_comparable_payload_is_unable_to_verify(self):
        self.assertEqual(classify_finding_retest(self.finding, self.completed, [])["status"], "unable_to_verify")
        incomplete = {**self.completed, "evidence_id": None}
        self.assertEqual(classify_finding_retest(self.finding, incomplete, [])["status"], "unable_to_verify")

    def test_nmap_retest_marks_fixed_only_when_same_live_host_shows_old_port_closed(self):
        prior = {"target": "192.168.1.1", "open_ports": [{"port": 80, "protocol": "tcp"}]}
        fresh = {"target": "192.168.1.1", "host_count": 1,
                 "hosts": [{"status": "up", "addresses": [{"address": "192.168.1.1"}],
                           "ports": [{"port": 80, "protocol": "tcp", "state": "closed"}]}],
                 "open_ports": []}
        finding = {**self.finding, "title": "Open TCP services observed by Nmap", "source_test": "Nmap host and service assessment"}
        result = {**self.completed, "test_id": "nmap_scan"}
        self.assertEqual(classify_finding_retest(finding, result, [], prior, fresh)["status"], "fixed")

    def test_nmap_absent_target_is_unable_to_verify_not_fixed(self):
        prior = {"target": "192.168.1.1", "open_ports": [{"port": 80, "protocol": "tcp"}]}
        fresh = {"target": "192.168.1.1", "host_count": 0, "hosts": [], "open_ports": []}
        finding = {**self.finding, "title": "Open TCP services observed by Nmap", "source_test": "Nmap host and service assessment"}
        result = {**self.completed, "test_id": "nmap_scan"}
        self.assertEqual(classify_finding_retest(finding, result, [], prior, fresh)["status"], "unable_to_verify")

    def test_nmap_closed_summary_must_cover_all_original_ports(self):
        prior = {"target": "192.168.1.1", "open_ports": [{"port": 80}, {"port": 443}]}
        host = {"status": "up", "addresses": [{"address": "192.168.1.1"}], "ports": [],
                "extraports": [{"state": "closed", "count": 2}]}
        finding = {**self.finding, "title": "Open TCP services observed by Nmap", "source_test": "Nmap host and service assessment"}
        result = {**self.completed, "test_id": "nmap_scan"}
        fresh = {"target": "192.168.1.1", "hosts": [host], "open_ports": []}
        self.assertEqual(classify_finding_retest(finding, result, [], prior, fresh)["status"], "fixed")
        partial = {**fresh, "hosts": [{**host, "extraports": [{"state": "closed", "count": 1}]}]}
        self.assertEqual(classify_finding_retest(finding, result, [], prior, partial)["status"], "unable_to_verify")

    def test_connected_profile_fix_requires_same_bssid_and_observed_protected_mode(self):
        finding = {**self.finding, "title": "Connected network is not protected"}
        result = {**self.completed, "test_id": "connected_profile_audit"}
        previous = {"connected": True, "bssid": "AA:BB:CC:DD:EE:01", "auth": "Open", "cipher": "None"}
        fixed = {"connected": True, "bssid": "AA:BB:CC:DD:EE:01", "auth": "WPA2 Personal", "cipher": "AES"}
        self.assertEqual(classify_finding_retest(finding, result, [], previous, fixed)["status"], "fixed")
        changed_bssid = {**fixed, "bssid": "AA:BB:CC:DD:EE:02"}
        self.assertEqual(classify_finding_retest(finding, result, [], previous, changed_bssid)["status"], "unable_to_verify")

    def test_different_asset_is_not_used_as_fix_evidence(self):
        fresh = [{**self.finding, "id": "FND-2", "asset": "192.168.1.20"}]
        self.assertEqual(classify_finding_retest(self.finding, self.completed, fresh)["status"], "unable_to_verify")

    def test_schema_upgrade_adds_retest_history_without_rewriting_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            store = Store(path)
            aid = store.create_assessment({"name": "Retest history", "target": "lab", "authorization": True})["id"]
            execution = store.start_execution(aid, "test", "gateway_exposure")
            evidence_id = store.add_evidence(aid, execution, "test_result", "test source", {"host": "192.168.1.1"})
            finding_id = store.add_finding(aid, execution, self.finding["title"], "Medium", "description", "impact",
                                           self.finding["source_test"], "logic", "fix", evidence_id,
                                           asset="192.168.1.1", category="Network Security")
            original = store.finding(aid, finding_id)
            store.db.execute("DROP TABLE finding_retests")
            store.db.execute("PRAGMA user_version=14")
            store.close()
            upgraded = Store(path)
            self.assertEqual(upgraded.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(upgraded.finding(aid, finding_id)["title"], original["title"])
            new_execution = upgraded.start_execution(aid, "same test", "gateway_exposure")
            new_evidence = upgraded.add_evidence(aid, new_execution, "test_result", "test source", {"host": "192.168.1.1"})
            retest = upgraded.record_finding_retest(aid, finding_id, "fixed", new_execution, new_evidence, "New evidence")
            self.assertEqual(retest["status"], "fixed")
            self.assertEqual(upgraded.finding_retests(aid, finding_id)[0]["evidence_id"], new_evidence)
            from core.reporting import build_report
            report = build_report(upgraded.state(aid, include_all=True))
            self.assertEqual(report["finding_retests"][0]["id"], retest["id"])
            upgraded.close()

    def test_bridge_reruns_original_supported_check_and_records_new_evidence(self):
        import main as app
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "bridge.db")
            aid = store.create_assessment({"name": "Bridge retest", "target": "lab", "authorization": True,
                                           "network_scope": "192.168.1.0/24"})["id"]
            old_execution = store.start_execution(aid, "Gateway exposure", "gateway_exposure")
            old_evidence = store.add_evidence(aid, old_execution, "test_result", "test source",
                                              {"host": "192.168.1.1", "ports_requested": [80],
                                               "results": [{"port": 80, "protocol": "tcp", "state": "open"}]},
                                              {"scope": "declared network scope: 192.168.1.0/24", "test": "gateway_exposure"})
            finding_id = store.add_finding(aid, old_execution, self.finding["title"], "Medium", "description", "impact",
                                           self.finding["source_test"], "logic", "fix", old_evidence,
                                           asset="192.168.1.1", category="Network Security")

            class FakeEngine:
                def run_test(self, assessment_id, test_id, config):
                    self.config = config
                    execution = store.start_execution(assessment_id, "Gateway exposure retest", test_id)
                    evidence = store.add_evidence(assessment_id, execution, "test_result", "retest",
                                                  {"host": "192.168.1.1", "ports_requested": [80],
                                                   "results": [{"port": 80, "protocol": "tcp", "state": "closed"}]})
                    store.update_execution(execution, "completed", 100, "completed")
                    return {"status": "completed", "execution_id": execution, "evidence_id": evidence}

            fake = FakeEngine()
            bridge = app.Bridge()
            with patch("main.store", store), patch("main.engine", fake):
                result = bridge.retest_finding(aid, finding_id)
                self.assertEqual(result["retest"]["status"], "fixed")
                self.assertEqual(fake.config, {})
                self.assertEqual(bridge.finding_retests(aid, finding_id)[0]["evidence_id"], result["execution"]["evidence_id"])
            store.close()

    def test_bridge_refuses_to_compare_after_assessment_scope_changes(self):
        import main as app
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "scope-change.db")
            aid = store.create_assessment({"name": "Changed scope", "target": "lab", "authorization": True,
                                           "network_scope": "192.168.1.0/24"})["id"]
            old_execution = store.start_execution(aid, "Gateway exposure", "gateway_exposure")
            old_evidence = store.add_evidence(aid, old_execution, "test_result", "test source",
                                              {"host": "192.168.1.1"},
                                              {"scope": "declared network scope: 192.168.1.0/24"})
            finding_id = store.add_finding(aid, old_execution, self.finding["title"], "Medium", "description", "impact",
                                           self.finding["source_test"], "logic", "fix", old_evidence,
                                           asset="192.168.1.1", category="Network Security")
            store.update_assessment(aid, network_scope="192.168.2.0/24")

            class ForbiddenEngine:
                def run_test(self, *_args, **_kwargs):
                    raise AssertionError("A changed-scope retest must not run.")

            with patch("main.store", store), patch("main.engine", ForbiddenEngine()):
                result = app.Bridge().retest_finding(aid, finding_id)
            self.assertEqual(result["retest"]["status"], "unable_to_verify")
            self.assertEqual(result["execution"]["status"], "blocked")
            store.close()

    def test_bridge_blocks_duplicate_retest_for_same_finding(self):
        import main as app
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "concurrent.db")
            aid = store.create_assessment({"name": "Concurrent retest", "target": "lab", "authorization": True,
                                           "network_scope": "192.168.1.0/24"})["id"]
            old_execution = store.start_execution(aid, "Gateway exposure", "gateway_exposure")
            old_evidence = store.add_evidence(aid, old_execution, "test_result", "test source",
                                              {"host": "192.168.1.1", "results": [{"port": 80, "state": "open"}]},
                                              {"scope": "declared network scope: 192.168.1.0/24"})
            finding_id = store.add_finding(aid, old_execution, self.finding["title"], "Medium", "description", "impact",
                                           self.finding["source_test"], "logic", "fix", old_evidence,
                                           asset="192.168.1.1", category="Network Security")
            started, release = threading.Event(), threading.Event()

            class SlowEngine:
                def run_test(self, assessment_id, test_id, config):
                    started.set()
                    release.wait(timeout=2)
                    execution = store.start_execution(assessment_id, "Gateway exposure retest", test_id)
                    evidence = store.add_evidence(assessment_id, execution, "test_result", "retest",
                                                  {"host": "192.168.1.1", "results": [{"port": 80, "state": "closed"}]})
                    store.update_execution(execution, "completed", 100, "completed")
                    return {"status": "completed", "execution_id": execution, "evidence_id": evidence}

            bridge = app.Bridge()
            result_holder = []
            with patch("main.store", store), patch("main.engine", SlowEngine()):
                worker = threading.Thread(target=lambda: result_holder.append(bridge.retest_finding(aid, finding_id)))
                worker.start()
                self.assertTrue(started.wait(timeout=2))
                duplicate = bridge.retest_finding(aid, finding_id)
                self.assertIn("already has a retest", duplicate["error"])
                release.set()
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(result_holder[0]["retest"]["status"], "fixed")
            store.close()


if __name__ == "__main__":
    unittest.main()
