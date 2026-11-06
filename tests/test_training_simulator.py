import hashlib
import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from core.training_simulator import TrainingSessionManager, validate_event


class TrainingSimulatorTests(unittest.TestCase):
    def test_accepts_only_fixed_synthetic_event_values(self):
        self.assertEqual(validate_event({"event": "click"}), {"event": "click", "choice": None})
        self.assertEqual(validate_event({"event": "synthetic_response", "choice": "yes"}),
                         {"event": "synthetic_response", "choice": "yes"})
        for payload in ({"event": "submit", "password": "secret"},
                        {"event": "synthetic_response", "choice": "secret"},
                        {"event": "click", "extra": "value"}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_event(payload)

    def test_session_is_loopback_only_and_tracks_aggregated_synthetic_events(self):
        events = []
        manager = TrainingSessionManager(on_event=lambda session_id, event, choice: events.append(
            (session_id, event, choice)))
        with patch("core.training_simulator._make_server") as make_server:
            server = type("Server", (), {"server_address": ("127.0.0.1", 43123), "serve_forever": lambda self: None,
                                         "shutdown": lambda self: None, "server_close": lambda self: None})()
            make_server.return_value = server
            with patch("core.training_simulator.Thread", autospec=True) as thread_type:
                session = manager.start_session(10)
                thread_type.return_value.start.assert_called_once()

        session_id = session["session_id"]
        token = session["url"].rsplit("/", 1)[-1]
        self.assertEqual(session["host"], "127.0.0.1")
        self.assertEqual(hashlib.sha256(token.encode()).hexdigest(), session["token_sha256"])
        self.assertNotEqual(token, session["token_sha256"])
        with self.assertRaisesRegex(ValueError, "already active"):
            manager.start_session(30)
        with self.assertRaisesRegex(ValueError, "invalid"):
            manager.record("different-token", {"event": "visit"})
        manager.record(token, {"event": "visit"})
        manager.record(token, {"event": "click"})
        manager.record(token, {"event": "synthetic_response", "choice": "no"})
        summary = manager.summary()
        self.assertEqual(summary["events"], {"visit": 1, "click": 1, "synthetic_yes": 0, "synthetic_no": 1})
        self.assertEqual(events, [(session_id, "visit", None), (session_id, "click", None),
                                 (session_id, "synthetic_response", "no")])
        self.assertNotIn(token, json.dumps(summary))
        manager.stop_session()

    def test_session_expires_and_stops_accepting_events(self):
        manager = TrainingSessionManager()
        with patch("core.training_simulator._make_server") as make_server:
            server = type("Server", (), {"server_address": ("127.0.0.1", 43124), "serve_forever": lambda self: None,
                                         "shutdown": lambda self: None, "server_close": lambda self: None})()
            make_server.return_value = server
            with patch("core.training_simulator.Thread"):
                session = manager.start_session(1)
        token = session["url"].rsplit("/", 1)[-1]
        manager._session["expires_monotonic"] = 0
        with self.assertRaises(ValueError):
            manager.record(token, {"event": "visit"})
        self.assertEqual(manager.summary()["status"], "expired")

    def test_http_page_accepts_only_allowlisted_events_and_shutdown_closes_listener(self):
        manager = TrainingSessionManager()
        session = manager.start_session(30)
        try:
            with urlopen(session["url"], timeout=2) as response:
                page = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
            self.assertIn("Security awareness exercise", page)
            self.assertNotIn('type="password"', page)
            event_url = session["url"].replace("/session/", "/event/")
            for payload in ({"event": "click"}, {"event": "synthetic_response", "choice": "yes"}):
                request = Request(event_url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
            bad_request = Request(event_url, data=b'{"event":"synthetic_response","choice":"yes","password":"private"}',
                                  headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as rejected:
                urlopen(bad_request, timeout=2)
            self.assertEqual(rejected.exception.code, 400)
            summary = manager.summary()
            self.assertEqual(summary["events"]["visit"], 1)
            self.assertEqual(summary["events"]["click"], 1)
            self.assertEqual(summary["events"]["synthetic_yes"], 1)
            self.assertNotIn("private", json.dumps(summary))
        finally:
            manager.stop_session()
        with self.assertRaises((OSError, HTTPError)):
            urlopen(session["url"], timeout=1)

    def test_store_migration_preserves_existing_records_and_persists_only_aggregatable_events(self):
        import tempfile
        from pathlib import Path
        from core.store import SCHEMA_VERSION, Store

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "training.db"
            store = Store(path)
            assessment = store.create_assessment({"name": "Existing assessment"})
            store.add_evidence(assessment["id"], None, "marker", "fixture", {"keep": True})
            store.create_training_session("TRN-TEST123456", "a" * 64, "127.0.0.1", 43125,
                                          "2026-10-31T10:00:00+00:00", "2026-10-31T10:15:00+00:00")
            store.add_training_event("TRN-TEST123456", "visit")
            store.add_training_event("TRN-TEST123456", "synthetic_response", "yes")
            store.db.execute("DROP TABLE training_events")
            store.db.execute("DROP TABLE training_sessions")
            store.db.execute("PRAGMA user_version=13")
            store.close()

            upgraded = Store(path)
            try:
                self.assertEqual(upgraded.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                self.assertEqual(upgraded.assessment(assessment["id"])["name"], "Existing assessment")
                self.assertEqual(len(upgraded.evidence(assessment["id"])), 1)
                session = upgraded.create_training_session("TRN-NEW123456", "b" * 64, "127.0.0.1", 43126,
                                                            "2026-10-31T10:00:00+00:00", "2026-10-31T10:15:00+00:00")
                upgraded.add_training_event(session["id"], "click")
                upgraded.add_training_event(session["id"], "synthetic_response", "no")
                record = upgraded.training_session(session["id"])
                self.assertEqual(record["events"], {"visit": 0, "click": 1, "synthetic_yes": 0, "synthetic_no": 1})
                self.assertNotIn("secret-session-url-token", str(record))
                self.assertEqual(upgraded.recover_interrupted_training_sessions("2026-10-31T10:02:00+00:00"), 1)
                self.assertEqual(upgraded.training_session(session["id"])["status"], "stopped")
                with self.assertRaises(ValueError):
                    upgraded.create_training_session("TRN-REMOTE", "c" * 64, "0.0.0.0", 43127,
                                                      "now", "later")
                old = upgraded.create_training_session("TRN-OLD123456", "e" * 64, "127.0.0.1", 43129,
                    "2020-01-01T00:00:00+00:00", "2020-01-01T00:15:00+00:00")
                upgraded.finish_training_session(old["id"], "expired", "2020-01-01T00:15:00+00:00")
                self.assertEqual(upgraded.purge_training_sessions_before("2021-01-01T00:00:00+00:00"), 1)
                self.assertIsNone(upgraded.training_session(old["id"]))
                with self.assertRaisesRegex(ValueError, "timezone"):
                    upgraded.purge_training_sessions_before("2021-01-01T00:00:00")
            finally:
                upgraded.close()

    def test_bridge_start_stop_persists_session_metadata_and_synthetic_counts(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        class FakeManager:
            def __init__(self, on_event=None, on_status=None):
                self.on_event, self.on_status = on_event, on_status
                self.current = {"session_id": "TRN-BRIDGE1234", "status": "active", "host": "127.0.0.1",
                                "port": 43128, "created_at": "2026-10-31T10:00:00+00:00",
                                "expires_at": "2026-10-31T10:15:00+00:00", "ended_at": None,
                                "token_sha256": "d" * 64,
                                "events": {"visit": 0, "click": 0, "synthetic_yes": 0, "synthetic_no": 0},
                                "event_history": []}
            def start_session(self, duration):
                self.duration = duration
                return {"session_id": "TRN-BRIDGE1234", "url": "http://127.0.0.1:43128/session/secret-token",
                        "host": "127.0.0.1", "port": 43128, "created_at": self.current["created_at"],
                        "expires_at": self.current["expires_at"], "duration_seconds": duration,
                        "token_sha256": "d" * 64}
            def summary(self):
                return self.current
            def stop_session(self, status="stopped"):
                self.current["status"] = status
                self.current["ended_at"] = "2026-10-31T10:01:00+00:00"
                if self.on_status:
                    self.on_status(self.current["session_id"], status, self.current["ended_at"])
                return self.current

        with tempfile.TemporaryDirectory() as temp_dir:
            store = Store(Path(temp_dir) / "bridge-training.db")
            original = app.store
            try:
                app.store = store
                with patch.object(app, "TrainingSessionManager", FakeManager):
                    bridge = app.Bridge()
                    result = bridge.start_awareness_training(60)
                    self.assertEqual(result["host"], "127.0.0.1")
                    self.assertIn("secret-token", result["url"])
                    bridge._training_simulator.on_event(result["session_id"], "synthetic_response", "no")
                    stopped = bridge.stop_awareness_training()
                record = store.training_session(result["session_id"])
                self.assertEqual(stopped["status"], "stopped")
                self.assertEqual(record["status"], "stopped")
                self.assertEqual(record["events"]["synthetic_no"], 1)
                self.assertNotIn("secret-token", str(store.training_sessions()))
            finally:
                store.close()
                app.store = original


if __name__ == "__main__":
    unittest.main()
