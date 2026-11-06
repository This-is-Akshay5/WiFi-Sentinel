import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from unittest.mock import patch

from core.capture_storage import import_capture
from core.store import Store


class CaptureStorageTests(unittest.TestCase):
    @staticmethod
    def empty_pcap():
        return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)

    def test_import_stores_verified_bytes_content_addressed_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pcap"
            source.write_bytes(self.empty_pcap())
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Authorized capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            first = import_capture(source, root / "data" / "captures", store, assessment["id"], "LabNet")
            second = import_capture(source, root / "data" / "captures", store, assessment["id"], "LabNet")
            self.assertEqual(first["result"]["filename"], "source.pcap")
            self.assertTrue(first["result"]["sha256"] in first["stored_path"])
            self.assertEqual(Path(root / "data" / "captures" / first["stored_path"].split("/", 1)[1]).read_bytes(),
                             self.empty_pcap())
            self.assertTrue(second["duplicate"])
            self.assertEqual(first["evidence_id"], second["evidence_id"])
            store.close()

    def test_invalid_capture_is_not_retained_or_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "invalid.pcap"
            source.write_bytes(b"not a capture")
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Authorized capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            with self.assertRaises(ValueError):
                import_capture(source, root / "data" / "captures", store, assessment["id"], "LabNet")
            self.assertEqual(store.capture_imports(assessment["id"]), [])
            retained = [item for item in (root / "data" / "captures").glob("**/*") if item.is_file()]
            self.assertEqual(retained, [])
            store.close()

    def test_database_failure_removes_new_content_addressed_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pcap"
            source.write_bytes(self.empty_pcap())
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Authorized capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            with patch.object(store, "save_capture_analysis", side_effect=RuntimeError("injected database failure")):
                with self.assertRaisesRegex(RuntimeError, "injected database failure"):
                    import_capture(source, root / "data" / "captures", store, assessment["id"], "LabNet")
            retained = [item for item in (root / "data" / "captures").glob("**/*") if item.is_file()]
            self.assertEqual(retained, [])
            store.close()

    def test_symbolic_link_capture_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pcap"
            source.write_bytes(self.empty_pcap())
            outside = root / "outside"
            outside.mkdir()
            captures = root / "captures"
            captures.symlink_to(outside, target_is_directory=True)
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Authorized capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                import_capture(source, captures, store, assessment["id"], "LabNet")
            self.assertEqual(list(outside.iterdir()), [])
            store.close()

    def test_bridge_native_picker_preview_analyze_and_cancel_flow(self):
        import main as app
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pcap"
            source.write_bytes(self.empty_pcap())
            store = Store(root / "assessment.db")
            assessment = store.create_assessment({"name": "Authorized capture", "authorization": True,
                                                  "wireless_scope": "LabNet"})
            dialog = SimpleNamespace(OPEN_DIALOG="open", windows=[SimpleNamespace(
                create_file_dialog=lambda *_a, **_k: [str(source)])])
            with patch.object(app, "store", store), patch.object(app, "CAPTURES", root / "data" / "captures"), \
                    patch.object(app, "webview", dialog):
                bridge = app.Bridge()
                preview = bridge.select_capture()
                self.assertTrue(preview["ok"])
                self.assertEqual(preview["filename"], "source.pcap")
                self.assertEqual(preview["size_bytes"], len(self.empty_pcap()))
                self.assertNotIn("path", preview)
                unauthorized=bridge.analyze_capture_selection(preview["selection_id"],False,"LabNet")
                self.assertFalse(unauthorized["ok"])
                self.assertIn("authorization",unauthorized["error"].lower())
                first = bridge.analyze_capture_selection(preview["selection_id"], True, "LabNet")
                self.assertTrue(first["ok"])
                self.assertEqual(first["result"]["packets_examined"], 0)
                preview = bridge.select_capture()
                second = bridge.analyze_capture_selection(preview["selection_id"], True, "LabNet")
                self.assertTrue(second["duplicate"])
                self.assertEqual(first["evidence_id"], second["evidence_id"])
                history=bridge.capture_history()
                self.assertEqual(len(history),1)
                self.assertNotIn('stored_path',history[0])
                reopened=bridge.capture_analysis(history[0]['id'])
                self.assertEqual(reopened['analysis']['packets_examined'],0)
                preview = bridge.select_capture()
                self.assertTrue(bridge.cancel_capture_selection(preview["selection_id"])["cancelled"])
                offline_aid=store.setting('offline_capture_assessment_id','')
                self.assertEqual(len(store.capture_imports(offline_aid)), 1)
            store.close()


if __name__ == "__main__":
    unittest.main()
