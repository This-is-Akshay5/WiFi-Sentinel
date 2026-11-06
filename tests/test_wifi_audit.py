import tempfile
import unittest
from pathlib import Path

from core.wifi_audit import evaluate, score_findings, compare_prior_findings
from core.store import Store, SCHEMA_VERSION


def sample_context(auth="WPA3 Personal", bssid="AA:BB:CC:DD:EE:01", pmf=None):
    return {
        "observed_at": "2026-10-15T12:00:00+00:00",
        "source": "macOS CoreWLAN",
        "wifi": {
            "connected": True, "state": "ok", "ssid": "Lab Network", "bssid": bssid,
            "interface": "en0", "auth": auth, "cipher": "AES", "band": 5.0,
            "channel": 36, "signal_dbm": -48,
            "nearby_aps": [
                {"ssid": "Lab Network", "bssid": "AA:BB:CC:DD:EE:99",
                 "pmf_advertisement": {"advertised_capable": True, "advertised_required": False}},
                {"ssid": "Lab Network", "bssid": bssid, "pmf_advertisement": pmf},
            ],
        },
        "network": {"local_ip": "192.168.4.25", "network": "192.168.4.0/24",
                    "gateway": "192.168.4.1", "interface": "en0"},
    }


class WiFiAuditEvaluatorTests(unittest.TestCase):
    def test_audit_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "authorization"):
            evaluate(sample_context(), False, None)

    def test_same_ssid_different_bssid_does_not_supply_pmf_evidence(self):
        result = evaluate(sample_context(pmf=None), True, {"status": "unavailable"})
        pmf = next(check for check in result["checks"] if check["id"] == "pmf")
        self.assertEqual(pmf["status"], "unavailable")
        self.assertIsNone(pmf.get("evidence"))

    def test_open_network_finding_uses_observed_authentication(self):
        result = evaluate(sample_context(auth="Open"), True,
                          {"status": "reachable", "source": "system ping", "observed_at": "2026-10-15T12:00:01Z"})
        finding = next(f for f in result["findings"] if f["check_id"] == "security_mode")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["evidence"]["authentication"], "Open")
        self.assertEqual(result["score"]["status"], "scored")

    def test_unknown_security_and_unavailable_gateway_do_not_create_low_score(self):
        context = sample_context(auth=None)
        context["wifi"]["auth"] = None
        context["wifi"]["saved_password"] = "DO-NOT-EXPORT-SECRET"
        result = evaluate(context, True, {"status": "unavailable"})
        security = next(check for check in result["checks"] if check["id"] == "security_mode")
        self.assertEqual(security["status"], "unavailable")
        self.assertEqual(result["score"]["status"], "insufficient_evidence")
        self.assertIsNone(result["score"]["value"])
        self.assertNotIn("DO-NOT-EXPORT-SECRET", str(result))

    def test_pmf_requires_exact_connected_bssid_and_marks_optional(self):
        context = sample_context(pmf={"advertised_capable": True, "advertised_required": False})
        result = evaluate(context, True, {"status": "reachable", "source": "system ping"})
        pmf = next(check for check in result["checks"] if check["id"] == "pmf")
        self.assertEqual(pmf["status"], "finding")
        self.assertEqual(pmf["evidence"]["bssid"], context["wifi"]["bssid"])

    def test_contradictory_pmf_flags_remain_unknown_and_explicit_hidden_ssid_stays_distinct(self):
        context = sample_context(pmf={"advertised_capable": False, "advertised_required": True})
        context["wifi"]["ssid"] = None
        context["wifi"]["ssid_hidden"] = True
        result = evaluate(context, True, {"status": "unavailable"})
        pmf = next(check for check in result["checks"] if check["id"] == "pmf")
        self.assertEqual(pmf["status"], "unavailable")
        self.assertIsNone(pmf["evidence"])
        self.assertTrue(result["network"]["ssid_hidden"])
        self.assertIsNone(result["network"]["ssid"])

    def test_score_formula_is_bounded_deterministic_and_deduplicates_related_findings(self):
        finding = {"check_id": "one", "correlation_group": "radio", "severity": "High",
                   "status": "new", "risk_factors": {"exploitability": 0.8, "exposure": 0.5,
                                                            "impact": 0.75, "evidence_quality": 1.0}}
        duplicate = {**finding, "check_id": "two"}
        result = score_findings([finding, duplicate], {"core_checks_observed": 2})
        self.assertEqual(result["status"], "scored")
        self.assertEqual(result["value"], 23)
        self.assertEqual(result, score_findings([duplicate, finding], {"core_checks_observed": 2}))
        self.assertIn("noisy-or", result["formula"])
        resolved = score_findings([{**finding, "status": "resolved"}], {"core_checks_observed": 2})
        self.assertEqual(resolved["value"], 0)

    def test_score_bands_match_product_boundaries(self):
        cases = [(0.19, "Low"), (0.2, "Moderate"), (0.39, "Moderate"),
                 (0.4, "High"), (0.69, "High"), (0.7, "Critical")]
        for contribution, expected_band in cases:
            with self.subTest(contribution=contribution):
                finding = {"check_id": "test", "severity": "Critical", "status": "new",
                           "correlation_group": "test", "risk_factors": {"exploitability": contribution,
                            "exposure": 1, "impact": 1, "evidence_quality": 1}}
                result = score_findings([finding], {"core_checks_observed": 2})
                self.assertEqual(result["band"], expected_band)

    def test_risk_factors_outside_unit_interval_are_rejected(self):
        finding = {"check_id": "invalid", "severity": "High", "risk_factors": {
            "exploitability": 1.1, "exposure": 1, "impact": 1, "evidence_quality": 1}}
        with self.assertRaisesRegex(ValueError, "0 to 1"):
            score_findings([finding], {"core_checks_observed": 2})

    def test_gateway_timeout_is_inconclusive_and_hotspot_type_stays_manual(self):
        result = evaluate(sample_context(), True, {"status": "unreachable"})
        gateway = next(check for check in result["checks"] if check["id"] == "gateway_reachability")
        hotspot = next(check for check in result["checks"] if check["id"] == "network_context_type")
        self.assertEqual(gateway["status"], "inconclusive")
        self.assertEqual(hotspot["status"], "manual_verification")
        self.assertNotIn("hotspot", result["network"].get("device_type", ""))

    def test_applied_remediation_requires_same_asset_and_new_evidence_to_verify(self):
        prior = {"id": "WFA-OLD", "remediations": [{"finding_id": "WIFI-SECURITY_MODE", "status": "applied"}],
                 "payload": {"network": {"bssid": "AA:BB:CC:DD:EE:01"},
                             "findings": [{"id": "WIFI-SECURITY_MODE", "check_id": "security_mode"}]}}
        current = {"network": {"bssid": "AA:BB:CC:DD:EE:01"}, "checks": [
            {"id": "security_mode", "status": "pass", "evidence": {"authentication": "WPA3 Personal"}}]}
        verified = compare_prior_findings(prior, current)
        self.assertEqual(verified[0]["status"], "verified_resolved")
        self.assertEqual(verified[0]["evidence"]["authentication"], "WPA3 Personal")
        changed_ap = {**current, "network": {"bssid": "AA:BB:CC:DD:EE:02"}}
        self.assertEqual(compare_prior_findings(prior, changed_ap), [])
        still_present = {**current, "checks": [{"id": "security_mode", "status": "finding", "evidence": {"authentication": "WEP"}}]}
        self.assertEqual(compare_prior_findings(prior, still_present)[0]["status"], "still_present")
        unknown = {**current, "checks": [{"id": "security_mode", "status": "unavailable"}]}
        self.assertEqual(compare_prior_findings(prior, unknown)[0]["status"], "unable_to_verify")
        prior_without_action = {**prior, "remediations": []}
        self.assertEqual(compare_prior_findings(prior_without_action, still_present)[0]["status"], "recurring")


class WiFiAuditStoreTests(unittest.TestCase):
    def test_audit_persists_with_integrity_and_v10_data_survives_additive_migration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "audit.db"
            store = Store(path)
            assessment = store.create_assessment({"name": "Existing history"})
            store.db.execute("DROP TABLE wifi_audit_remediations")
            store.db.execute("PRAGMA user_version=10")
            store.close()

            upgraded = Store(path)
            self.assertEqual(upgraded.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(upgraded.assessment(assessment["id"])["name"], "Existing history")
            saved = upgraded.save_wifi_audit({"score": {"status": "insufficient_evidence", "value": None},
                                                "model_version": "wifi-audit-v1",
                                                "findings": [{"id": "WIFI-SECURITY_MODE"}]})
            loaded = upgraded.wifi_audit(saved["id"])
            self.assertTrue(loaded["integrity_valid"])
            self.assertEqual(loaded["payload"]["model_version"], "wifi-audit-v1")
            self.assertEqual(upgraded.wifi_audits()[0]["id"], saved["id"])
            action = upgraded.set_wifi_audit_remediation(saved["id"], "WIFI-SECURITY_MODE", True)
            self.assertEqual(action["status"], "applied")
            self.assertEqual(upgraded.wifi_audit(saved["id"])["remediations"][0]["status"], "applied")
            upgraded.db.execute("UPDATE wifi_audits SET payload_json='{}' WHERE id=?", (saved["id"],))
            self.assertFalse(upgraded.wifi_audit(saved["id"])["integrity_valid"])
            upgraded.close()


class WiFiAuditReportTests(unittest.TestCase):
    def test_pdf_uses_a_persisted_audit_and_keeps_credentials_out(self):
        from core.reporting import write_wifi_audit_pdf
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wifi-audit.pdf"
            audit = {"id": "WFA-TEST", "created_at": "2026-10-15T12:00:00Z", "integrity_valid": True,
                     "payload": {"model_version": "wifi-audit-v1", "status": "partial",
                                 "scope": "Currently connected Wi-Fi interface only",
                     "network": {"ssid": "Café 東京", "bssid": "AA:BB:CC:DD:EE:01",
                                             "authentication": "WPA3 Personal", "gateway": None,
                                             "saved_password": "DO-NOT-EXPORT-SECRET",
                                             "source": "macOS CoreWLAN"},
                                 "score": {"status": "insufficient_evidence", "value": None,
                                           "reason": "PMF evidence unavailable"},
                                 "checks": [{"label": f"Check {i}", "status": "unavailable",
                                             "detail": "No direct evidence"} for i in range(80)],
                                 "coverage": {"checks_observed": 0, "checks_total": 7},
                                 "findings": [], "recommendations": [],
                                 "limitations": ["DNS unavailable", "Saved credential not accessed"],
                                 "methodology": "OS observations"}}
            write_wifi_audit_pdf(path, audit)
            data = path.read_bytes()
            self.assertTrue(data.startswith(b"%PDF-"))
            self.assertGreaterEqual(len(__import__("re").findall(rb"/Type\s*/Page\b", data)), 2)
            self.assertIn(b"STSong-Light", data)
            self.assertNotIn(b"secret", data.lower())


class WiFiAuditBridgeTests(unittest.TestCase):
    def test_bridge_requires_authorization_before_os_collection(self):
        import main as app
        class NeverCalledWiFi:
            def wifi_info(self):
                raise AssertionError("authorization must be checked first")
        original = app.wifi
        app.wifi = NeverCalledWiFi()
        try:
            with self.assertRaisesRegex(ValueError, "authorization"):
                app.Bridge().run_wifi_audit(False)
        finally:
            app.wifi = original

    def test_bridge_rejects_concurrent_audit_before_querying_adapter(self):
        import main as app
        class NeverCalledWiFi:
            os_type = "Darwin"
            def wifi_info(self):
                raise AssertionError("a concurrent audit must be rejected before collection")
        original = app.wifi
        app.wifi = NeverCalledWiFi()
        self.assertTrue(app.wifi_audit_lock.acquire(blocking=False))
        try:
            with self.assertRaisesRegex(RuntimeError, "already running"):
                app.Bridge().run_wifi_audit(True)
        finally:
            app.wifi_audit_lock.release()
            app.wifi = original

    def test_bridge_credential_reveal_requires_explicit_action(self):
        import main as app
        class NeverCalledWiFi:
            def wifi_info(self):
                raise AssertionError("credential access must require explicit UI action")
        original = app.wifi
        app.wifi = NeverCalledWiFi()
        try:
            with self.assertRaisesRegex(ValueError, "explicit action"):
                app.Bridge().get_current_wifi_credential(False)
        finally:
            app.wifi = original

    def test_bridge_returns_transient_credential_without_persisting_it(self):
        import main as app
        class FakeWiFi:
            os_type = "Darwin"
            def wifi_info(self):
                return {"connected": True, "ssid": "Current Network"}
        original_wifi, original_reader = app.wifi, app.retrieve_current_wifi_credential
        app.wifi = FakeWiFi()
        app.retrieve_current_wifi_credential = lambda os_type, info: "transient-test-secret"
        try:
            result = app.Bridge().get_current_wifi_credential(True)
            self.assertEqual(result, {"ok": True, "password": "transient-test-secret"})
        finally:
            app.wifi, app.retrieve_current_wifi_credential = original_wifi, original_reader

    def test_bridge_collects_connected_context_and_persists_without_ping_output(self):
        import main as app
        class FakeWiFi:
            os_type = "Darwin"
            def wifi_info(self):
                return {"connected": True, "state": "ok", "ssid": "Lab", "bssid": "AA:BB:CC:DD:EE:01",
                        "auth": "WPA3 Personal", "interface": "en0", "nearby_aps": []}
            def network_context(self, interface):
                return {"local_ip": "192.168.4.25", "network": "192.168.4.0/24",
                        "gateway": "192.168.4.1", "interface": interface}
            def ping(self, host, timeout_ms):
                self.ping_args = (host, timeout_ms)
                return {"reachable": True, "output": "must not persist"}
        class FakeStore:
            saved = None
            def wifi_audits(self, limit=100):
                return []
            def save_wifi_audit(self, payload):
                self.saved = dict(payload)
                return {"id": "WFA-1", "payload": payload, "integrity_valid": True}
        original_wifi, original_store = app.wifi, app.store
        fake_wifi, fake_store = FakeWiFi(), FakeStore()
        app.wifi, app.store = fake_wifi, fake_store
        try:
            result = app.Bridge().run_wifi_audit(True)
            self.assertEqual(result["id"], "WFA-1")
            self.assertEqual(fake_wifi.ping_args, ("192.168.4.1", 1200))
            self.assertEqual(fake_store.saved["network"]["bssid"], "AA:BB:CC:DD:EE:01")
            self.assertNotIn("must not persist", str(fake_store.saved))
        finally:
            app.wifi, app.store = original_wifi, original_store

    def test_bridge_exports_only_integrity_verified_persisted_audit(self):
        import main as app
        audit = {"id": "WFA-1", "created_at": "2026-10-15T12:00:00Z", "integrity_valid": True,
                 "remediations": [], "payload": {"model_version": "wifi-audit-v1", "status": "partial",
                 "scope": "Connected interface", "network": {}, "score": {"status": "insufficient_evidence"},
                 "coverage": {}, "checks": [], "findings": [], "recommendations": [], "limitations": []}}
        class FakeStore:
            def wifi_audit(self, audit_id):
                return audit if audit_id == "WFA-1" else None
        original_store, original_reports = app.store, app.REPORTS
        with tempfile.TemporaryDirectory() as temp_dir:
            app.store, app.REPORTS = FakeStore(), Path(temp_dir)
            try:
                exported = app.Bridge().export_wifi_audit_pdf("WFA-1")
                self.assertTrue(Path(exported).is_file())
                self.assertTrue(Path(exported).read_bytes().startswith(b"%PDF-"))
                audit["integrity_valid"] = False
                blocked = app.Bridge().export_wifi_audit_pdf("WFA-1")
                self.assertIn("integrity check failed", blocked["error"])
            finally:
                app.store, app.REPORTS = original_store, original_reports


if __name__ == "__main__":
    unittest.main()
