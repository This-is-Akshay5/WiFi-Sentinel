import csv
import json
import re
import tempfile
import unittest
from pathlib import Path

from core.dataset_engine import DatasetEngine
from core.reporting import build_report, write_findings_csv, write_json, write_pdf
from core.store import Store


class ReportingTests(unittest.TestCase):
    def test_csv_formula_injection_is_neutralized_for_capture_rows(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "assessment.csv"
            write_findings_csv(path, [], [{"id": "CAP-1", "filename": "=HYPERLINK(\"bad\")",
                                            "source_sha256": "e" * 64, "evidence_id": "EVD-1"}])
            with path.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["record_type"], "capture_import")
            self.assertEqual(row["title"], "'=HYPERLINK(\"bad\")")

    def test_pdf_capture_import_table_paginates_large_import_history(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "many-captures.pdf"
            captures = [{"id": f"CAP-{index}", "filename": f"capture-{index}.pcap", "capture_format": "pcap",
                         "size_bytes": 1024, "source_sha256": f"{index:064x}", "parser_version": "2.0",
                         "imported_at": "2026-10-14T00:00:00Z", "evidence_id": f"EVD-{index}", "analysis": {}}
                        for index in range(100)]
            write_pdf(path, build_report({"assessment": {"id": "ASM-1", "name": "Capture report"},
                                         "capture_imports": captures}))
            pages = re.findall(rb"/Type\s*/Page\b", path.read_bytes())
            self.assertGreaterEqual(len(pages), 2)

    def test_capture_provenance_is_in_json_csv_and_pdf_exports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Capture provenance", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            result = {"filename": "training.pcap", "size_bytes": 24, "sha256": "c" * 64,
                      "capture_format": "pcap", "parser_version": "2.0", "packets_examined": 0,
                      "candidate_exchanges": 0, "exchange_pairs": [],
                      "limitations": ["No packets were present in this valid capture."]}
            store.save_capture_analysis(assessment["id"], result, "captures/" + "c" * 64 + ".pcap")
            store.save_wireless_defense_run(assessment["id"], "simulation", "simulated", "SIMULATION ONLY",
                ["LAB-TARGET-SYNTHETIC"], {"packet_transmission":"none"},
                {"mode":"simulation","data_class":"simulation","scope":"SIMULATION ONLY"})
            state=store.state(assessment["id"],include_all=True)
            state['authorization_documents']=[{'id':'DOC-1','filename':'authorization.pdf','document_format':'PDF',
                'size_bytes':128,'sha256':'d'*64,'uploaded_at':'2026-10-14T00:00:00Z','uploaded_by':'operator'}]
            state['authorization_document_history']=[{'id':'DCH-1','document_id':'DOC-1','action':'attached',
                'sha256':'d'*64,'changed_by':'operator','created_at':'2026-10-14T00:00:00Z'}]
            state['observation_snapshots']=[{'id':'OBS-1','kind':'wireless','source':'macOS CoreWLAN','method':'CoreWLAN scan',
                'interface':'en0','data_class':'live','status':'success','first_seen':'2026-10-14T00:00:00Z',
                'last_seen':'2026-10-14T00:01:00Z','results':[{'bssid':'02:00:00:00:00:01'}],'limitations':[]}]
            report = build_report(state, generated_at="2026-10-14T00:00:00Z")
            json_path, csv_path, pdf_path = root / "report.json", root / "assessment.csv", root / "report.pdf"
            write_json(json_path, report)
            write_findings_csv(csv_path, report["findings"], report["capture_imports"], report["report"],
                report["wireless_defense_runs"],report['observation_snapshots'])
            write_pdf(pdf_path, report)
            self.assertEqual(json.loads(json_path.read_text())["capture_imports"][0]["source_sha256"], "c" * 64)
            self.assertEqual(json.loads(json_path.read_text())["wireless_defense_runs"][0]["mode"], "simulation")
            self.assertEqual(json.loads(json_path.read_text())["observation_snapshots"][0]["source"],"macOS CoreWLAN")
            self.assertEqual(json.loads(json_path.read_text())["authorization_documents"][0]["sha256"],"d"*64)
            self.assertEqual(json.loads(json_path.read_text())["authorization_document_history"][0]["action"],"attached")
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            metadata = next(row for row in rows if row["record_type"] == "report_metadata")
            captures = [row for row in rows if row["record_type"] == "capture_import"]
            defenses = [row for row in rows if row["record_type"] == "wireless_defense_run"]
            observations = [row for row in rows if row["record_type"] == "observation_snapshot"]
            self.assertIn("Evidence-led assessment", metadata["report_methodology"])
            self.assertEqual(metadata["generated_at"], report["report"]["generated_at"])
            self.assertEqual(captures[0]["source_sha256"], "c" * 64)
            self.assertEqual(captures[0]["evidence_id"], report["capture_imports"][0]["evidence_id"])
            self.assertEqual(defenses[0]["data_class"], "simulation")
            self.assertEqual(observations[0]["source"],"macOS CoreWLAN")
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-"))
            store.close()

    def test_json_csv_and_pdf_exports_contain_persisted_assessment_data(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({
                "name": "Quarterly wireless review", "target": "Lab AP",
                "wireless_scope": "Lab AP,AA:BB:CC:DD:EE:FF", "network_scope": "192.0.2.0/24",
                "authorization": True, "authorized_by": "Test operator", "authorization_note": "Ticket 123",
            })
            execution = store.start_execution(assessment["id"], "Observed Wi-Fi scan", "wifi_posture")
            evidence = store.add_evidence(assessment["id"], execution, "wifi_scan", "unit test",
                                          {"ssid": "Lab AP", "data_class": "live"})
            store.add_network(assessment["id"], {"ssid": "Lab AP", "bssid": "AA:BB:CC:DD:EE:FF",
                                                 "channel": 36, "auth": "WPA2", "observed_at": "2026-10-10T00:00:00Z"})
            store.add_finding(assessment["id"], execution, "Observed weak configuration", "High",
                              "Observed from persisted test data", "Potential exposure", "Wi-Fi posture",
                              "Observed security fields", "Review AP security configuration", evidence_id=evidence,
                              confidence="High")
            store.update_execution(execution, stage="complete", progress=100, status="completed")
            state = store.state(assessment["id"], include_all=True)
            report = build_report(state, {"operating_system": "Test OS"}, generated_at="2026-10-10T00:00:00Z")
            json_path, csv_path, pdf_path = root / "report.json", root / "findings.csv", root / "report.pdf"
            write_json(json_path, report)
            write_findings_csv(csv_path, report["findings"])
            write_pdf(pdf_path, report)

            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["assessment"]["id"], assessment["id"])
            self.assertEqual(parsed["networks"][0]["ssid"], "Lab AP")
            self.assertEqual(parsed["report"]["execution_counts"]["completed"], 1)
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["title"], "Observed weak configuration")
            pdf = pdf_path.read_bytes()
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
            store.close()

    def test_csv_neutralizes_spreadsheet_formula_prefixes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.csv"
            write_findings_csv(path, [{"id": "F1", "title": "=HYPERLINK(\"bad\")"}])
            with path.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["title"], "'=HYPERLINK(\"bad\")")


class DatasetProvenanceTests(unittest.TestCase):
    def test_file_created_after_missing_cache_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "appears.csv"
            engine = DatasetEngine(path)
            self.assertFalse(engine.summary()["available"])
            path.write_text('@timestamp,mac_address,association,dataType\n"Sep 25, 2025 @ 14:16:37.019",id1,associated,normal\n', encoding="utf-8")
            summary = engine.summary()
            self.assertTrue(summary["available"])
            self.assertEqual(summary["records"], 1)

    def test_dataset_cache_invalidates_after_file_changes(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "changes.csv"
            row = '"Sep 25, 2025 @ 14:16:37.019",id1,associated,normal\n'
            path.write_text('@timestamp,mac_address,association,dataType\n' + row, encoding="utf-8")
            engine = DatasetEngine(path)
            self.assertEqual(engine.summary()["records"], 1)
            path.write_text('@timestamp,mac_address,association,dataType\n' + row + row.replace('id1','id2'), encoding="utf-8")
            self.assertEqual(engine.summary()["records"], 2)

    def test_summary_reports_schema_discarded_rows_and_processing_time(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "research.csv"
            path.write_text(
                "@timestamp,mac_address,association,dataType\n"
                '"Sep 25, 2025 @ 14:16:37.019",00:11:22:33:44:55,associated,normal\n'
                "not-a-time,00:11:22:33:44:55,associated,attack\n"
                '"Sep 25, 2025 @ 14:16:38.019",00:11:22:33:44:55,unknown,attack\n',
                encoding="utf-8",
            )
            summary = DatasetEngine(path).summary()
            self.assertEqual(summary["records"], 1)
            self.assertEqual(summary["rows_seen"], 3)
            self.assertEqual(summary["discarded_rows"], 2)
            self.assertEqual(summary["parsing_status"], "partial")
            self.assertTrue(summary["last_processed_at"])

    def test_missing_required_columns_are_reported_as_invalid_schema(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.csv"
            path.write_text("timestamp,device\nvalue,host\n", encoding="utf-8")
            summary = DatasetEngine(path).summary()
            self.assertEqual(summary["parsing_status"], "invalid_schema")
            self.assertEqual(summary["schema_errors"], ["@timestamp", "association", "dataType", "mac_address"])


if __name__ == "__main__":
    unittest.main()
