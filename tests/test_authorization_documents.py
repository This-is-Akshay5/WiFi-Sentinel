import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from core.authorization_documents import copy_authorization_document, delete_authorization_document


class AuthorizationDocumentStorageTests(unittest.TestCase):
    def test_copies_approved_document_with_hash_and_no_content_return(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "private"
            source = Path(temp_dir) / "letter.txt"
            source.write_bytes(b"authorization text")
            record = copy_authorization_document(source, root, "ASM-123", max_bytes=1024)
            stored = root / record["stored_path"]
            self.assertTrue(stored.is_file())
            self.assertEqual(record["sha256"], hashlib.sha256(b"authorization text").hexdigest())
            self.assertEqual(record["size_bytes"], len(b"authorization text"))
            self.assertNotIn("content", record)
            if os.name != "nt":
                self.assertEqual(stored.stat().st_mode & 0o777, 0o600)

    def test_rejects_unsupported_extension_symlinks_and_oversized_documents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "private"
            unsupported = Path(temp_dir) / "payload.exe"
            unsupported.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "supported authorization-document"):
                copy_authorization_document(unsupported, root, "ASM-1", max_bytes=1024)
            large = Path(temp_dir) / "large.txt"
            large.write_bytes(b"12345")
            with self.assertRaisesRegex(ValueError, "size limit"):
                copy_authorization_document(large, root, "ASM-1", max_bytes=4)
            link = Path(temp_dir) / "link.txt"
            link.symlink_to(large)
            with self.assertRaisesRegex(ValueError, "Symbolic links"):
                copy_authorization_document(link, root, "ASM-1", max_bytes=1024)

    def test_storage_deletion_is_confined_to_document_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "private"
            source = Path(temp_dir) / "letter.pdf"
            source.write_bytes(b"pdf content placeholder")
            record = copy_authorization_document(source, root, "ASM-2", max_bytes=1024)
            self.assertTrue(delete_authorization_document(root, record["stored_path"]))
            self.assertFalse((root / record["stored_path"]).exists())
            with self.assertRaisesRegex(ValueError, "outside the document storage"):
                delete_authorization_document(root, "../letter.pdf")

    def test_document_records_and_removal_history_are_persisted_without_contents(self):
        from core.store import Store
        with tempfile.TemporaryDirectory() as temp_dir:
            store = Store(Path(temp_dir) / "authorization.db")
            try:
                assessment = store.create_assessment({"name": "Document test"})
                record = store.add_authorization_document(assessment["id"], {
                    "filename": "authorization.pdf", "stored_path": "ASM/DOC.pdf",
                    "sha256": hashlib.sha256(b"document").hexdigest(), "size_bytes": 8,
                    "document_format": "PDF",
                })
                self.assertNotIn("content", record)
                self.assertEqual(len(store.authorization_documents(assessment["id"])), 1)
                self.assertTrue(store.remove_authorization_document(assessment["id"], record["id"]))
                self.assertEqual(store.authorization_documents(assessment["id"]), [])
                self.assertEqual([row["action"] for row in store.authorization_document_history(assessment["id"])],
                                 ["removed", "attached"])
            finally:
                store.close()

    def test_v12_migration_adds_document_tables_and_preserves_assessment_evidence(self):
        import sqlite3
        from core.store import SCHEMA_VERSION, Store
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "v12.db"
            store = Store(path)
            assessment = store.create_assessment({"name": "Preserved"})
            store.add_evidence(assessment["id"], None, "marker", "fixture", {"kept": True})
            store.db.execute("DROP TABLE authorization_document_history")
            store.db.execute("DROP TABLE authorization_documents")
            store.db.execute("PRAGMA user_version=12")
            store.close()
            migrated = Store(path)
            try:
                self.assertEqual(migrated.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                self.assertEqual(migrated.state(assessment["id"])["assessment"]["name"], "Preserved")
                self.assertEqual(len(migrated.evidence(assessment["id"])), 1)
                self.assertEqual(migrated.authorization_documents(assessment["id"]), [])
            finally:
                migrated.close()

    def test_bridge_import_and_removal_are_authorized_and_audited(self):
        import main as app
        from core.store import Store
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "private-documents"
            source = Path(temp_dir) / "authorization.txt"
            source.write_text("authorization marker", encoding="utf-8")
            test_store = Store(Path(temp_dir) / "bridge.db")
            original_store, original_root = app.store, app.AUTHORIZATION_DOCS
            try:
                app.store, app.AUTHORIZATION_DOCS = test_store, root
                assessment = test_store.create_assessment({"name": "Bridge document workflow"})
                bridge = app.Bridge()
                info = source.stat()
                bridge._authorization_document_selections["fixture"] = {
                    "assessment_id": assessment["id"], "path": source, "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns,
                }
                with self.assertRaisesRegex(ValueError, "Confirm"):
                    bridge.import_authorization_document("fixture", False)
                imported = bridge.import_authorization_document("fixture", True)
                self.assertNotIn("stored_path", imported)
                self.assertNotIn("content", imported)
                self.assertEqual(len(list((root / assessment["id"]).glob("*.txt"))), 1)
                listed = bridge.authorization_documents(assessment["id"])
                self.assertEqual(len(listed["documents"]), 1)
                self.assertNotIn("stored_path", listed["documents"][0])
                deleted = bridge.remove_authorization_document(assessment["id"], imported["id"], True)
                self.assertTrue(deleted["file_removed"])
                self.assertEqual(bridge.authorization_documents(assessment["id"])["documents"], [])
                self.assertEqual([row["action"] for row in bridge.authorization_documents(assessment["id"])["history"]],
                                 ["removed", "attached"])
            finally:
                app.store, app.AUTHORIZATION_DOCS = original_store, original_root
                test_store.close()


if __name__ == "__main__":
    unittest.main()
