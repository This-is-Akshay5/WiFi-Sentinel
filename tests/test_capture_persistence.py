import tempfile
import unittest
from pathlib import Path
import sqlite3

from core.store import Store


class CapturePersistenceTests(unittest.TestCase):
    def test_database_failure_rolls_back_execution_evidence_finding_and_capture_rows(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "assessment.db")
            assessment = store.create_assessment({"name": "Offline capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            result = {"filename": "capture.pcap", "size_bytes": 128, "sha256": "d" * 64,
                      "capture_format": "pcap", "parser_version": "2.0", "packets_examined": 5,
                      "candidate_exchanges": 1, "exchange_pairs": [], "limitations": []}
            store.db.execute("CREATE TRIGGER fail_capture BEFORE INSERT ON capture_imports "
                             "BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                store.save_capture_analysis(assessment["id"], result, "captures/" + "d" * 64 + ".pcap")
            self.assertEqual(store.capture_imports(assessment["id"]), [])
            self.assertEqual(store.executions(assessment["id"]), [])
            self.assertEqual(store.evidence(assessment["id"]), [])
            self.assertEqual(store.findings(assessment["id"]), [])
            store.close()

    def test_capture_import_is_atomic_and_deduplicated_by_assessment_and_hash(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "assessment.db")
            assessment = store.create_assessment({"name": "Offline capture", "authorization": True,
                                                  "wireless_scope": "02:00:00:00:00:01"})
            aid = assessment["id"]
            result = {"filename": "capture.pcap", "size_bytes": 128, "sha256": "a" * 64,
                      "capture_format": "pcap", "parser_version": "2.0", "packets_examined": 0,
                      "candidate_exchanges": 0, "exchange_pairs": [], "limitations": ["Offline only"]}
            first = store.save_capture_analysis(aid, result, "captures/" + "a" * 64 + ".pcap")
            second = store.save_capture_analysis(aid, result, "captures/" + "a" * 64 + ".pcap")
            self.assertFalse(first["duplicate"])
            self.assertTrue(second["duplicate"])
            self.assertEqual(first["evidence_id"], second["evidence_id"])
            self.assertEqual(len(store.capture_imports(aid)), 1)
            self.assertEqual(len(store.executions(aid)), 1)
            self.assertEqual(len(store.evidence(aid)), 1)
            self.assertEqual(store.evidence(aid)[0]["data_class"], "capture")
            self.assertEqual(len(store.findings(aid)), 0)
            store.close()

    def test_candidate_finding_references_persisted_capture_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "assessment.db")
            assessment = store.create_assessment({"name": "Offline capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            aid = assessment["id"]
            result = {"filename": "capture.pcapng", "size_bytes": 256, "sha256": "b" * 64,
                      "capture_format": "pcapng", "parser_version": "2.0", "packets_examined": 5,
                      "candidate_exchanges": 1,
                      "exchange_pairs": [{"ssid": "LabNet", "candidate_four_way_exchange": True}],
                      "limitations": ["Offline only"]}
            saved = store.save_capture_analysis(aid, result, "captures/" + "b" * 64 + ".pcapng")
            finding = store.findings(aid)[0]
            self.assertEqual(finding["evidence_id"], saved["evidence_id"])
            self.assertEqual(finding["severity"], "Informational")
            self.assertIn("pattern", finding["detection_logic"].lower())
            self.assertEqual(store.capture_imports(aid)[0]["source_sha256"], "b" * 64)
            store.close()


if __name__ == "__main__":
    unittest.main()
