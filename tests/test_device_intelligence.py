import unittest

from core.device_intelligence import build_profiles


class DeviceIntelligenceTests(unittest.TestCase):
    def test_profiles_preserve_each_source_observation_without_identity_merging(self):
        profiles = build_profiles([
            {"observation_id": "OBS-1", "source": "OS neighbor cache", "observed_at": "t1",
             "data_class": "live", "fields": {"ip": "192.168.1.8", "mac": "02:00:00:00:00:01"}},
            {"observation_id": "ICMP-2", "source": "Authorized ICMP", "observed_at": "t2",
             "data_class": "live", "fields": {"ip": "192.168.1.8", "mac": "02:00:00:00:00:02"}},
        ])
        self.assertEqual(len(profiles), 2)
        self.assertEqual([item["source"] for item in profiles], ["OS neighbor cache", "Authorized ICMP"])
        self.assertEqual(profiles[0]["identity_claim"], "observation_only")
        self.assertEqual(profiles[0]["fields"]["mac"]["value"], "02:00:00:00:00:01")
        self.assertEqual(profiles[1]["fields"]["mac"]["value"], "02:00:00:00:00:02")

    def test_estimated_type_and_open_services_keep_basis_and_confidence(self):
        profiles = build_profiles([{
            "observation_id": "NMAP-1", "source": "Nmap scan", "method": "TCP connect scan",
            "data_class": "live", "observed_at": "t3",
            "fields": {"ip": "192.168.1.10", "type": "Printer", "type_inferred": True,
                       "open_ports": [
                           {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                           {"port": 53, "protocol": "udp", "state": "closed", "service": "domain"},
                       ]},
        }])
        profile = profiles[0]
        self.assertEqual(profile["classification"], {
            "value": "Printer", "status": "estimated", "confidence": "Low",
            "basis": "Source marked device type as inferred.",
        })
        self.assertEqual(len(profile["services"]), 1)
        self.assertEqual(profile["services"][0]["source"], "Nmap scan")
        self.assertEqual(profile["services"][0]["confidence"], "Nmap service fingerprint estimate")

    def test_missing_and_unknown_fields_are_not_filled_in(self):
        profile = build_profiles([{"source": "OS neighbor cache", "fields": {"ip": "192.168.1.2"}}])[0]
        self.assertIsNone(profile["fields"]["mac"]["value"])
        self.assertEqual(profile["fields"]["mac"]["status"], "unavailable")
        self.assertEqual(profile["classification"]["status"], "unavailable")
        self.assertEqual(profile["services"], [])

    def test_bridge_reads_snapshots_discovery_and_nmap_evidence_as_separate_profiles(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            store = Store(Path(temp_dir) / "devices.db")
            original_store = app.store
            try:
                app.store = store
                store.save_observation_snapshot({
                    "kind": "device", "source": "OS neighbor cache", "method": "arp cache",
                    "observed_at": "2026-10-31T12:00:00Z", "results": [{"ip": "192.168.1.2", "mac": "02:00:00:00:00:01"}],
                })
                store.save_device_discovery({
                    "id": "ICMP-1", "scope": "192.168.1.0/24", "status": "completed",
                    "started_at": "2026-10-31T12:01:00Z", "finished_at": "2026-10-31T12:01:02Z",
                    "checked": 256, "total": 256, "results": [{"ip": "192.168.1.2", "status": "responded"}],
                })
                assessment = store.create_assessment({"name": "Nmap observation"})
                execution = store.start_execution(assessment["id"], "Nmap scan", "nmap_scan")
                store.add_evidence(assessment["id"], execution, "nmap_scan", "Local Nmap",
                                  {"target": "192.168.1.3", "open_ports": [{"port": 443, "protocol": "tcp",
                                   "state": "open", "service": "https"}]}, {"test": "nmap_scan"},
                                  label="Nmap scan", test_id="nmap_scan")
                result = app.Bridge().device_intelligence()
                self.assertEqual({row["source"] for row in result["profiles"]},
                                 {"OS neighbor cache", "Authorized ICMP discovery", "Local Nmap"})
                self.assertEqual(result["observation_count"], 3)
                self.assertEqual(result["limitations"][0], "Profiles are individual observations and are not merged into permanent device identities.")
                nmap_profile = next(row for row in result["profiles"] if row["source"] == "Local Nmap")
                self.assertEqual(nmap_profile["services"][0]["port"], 443)
            finally:
                app.store = original_store
                store.close()


if __name__ == "__main__":
    unittest.main()
