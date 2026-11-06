"""Loopback-only synthetic security-awareness exercise.

The simulator has one fixed original page and accepts only visit, click, and
yes/no synthetic-choice events. It never accepts names, passwords, or free-form
form values and never sends messages to real recipients.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from threading import Thread
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

MAX_EVENT_BYTES = 256
MAX_SESSION_SECONDS = 30 * 60

_PAGE = b"""<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Security awareness exercise</title><style>body{font:16px system-ui;max-width:680px;margin:10vh auto;padding:24px;color:#182230}main{border:1px solid #d0d7de;border-radius:12px;padding:28px}button{padding:10px 16px;margin:8px 8px 0 0}aside{margin-top:24px;padding:16px;background:#f3f6f9}</style><main><h1>Security awareness exercise</h1><p>This locally hosted training message asks you to review a fictional Wi-Fi security notice. It is not connected to a real account or service.</p><p><button id=\"review\" type=\"button\">Review notice</button></p><section id=\"question\" hidden><p>For this synthetic exercise, did the message create urgency or ask you to bypass a normal process?</p><button data-choice=\"yes\" type=\"button\">Yes</button><button data-choice=\"no\" type=\"button\">No</button></section><aside id=\"lesson\" hidden><b>Training note</b><p>Check the sender and destination through a known channel. Avoid acting on urgency or unexpected links. This exercise stored only visit, click, and a synthetic yes/no choice.</p></aside></main><script>(()=>{const token=location.pathname.split('/').pop();const send=(event,choice)=>fetch('/event/'+encodeURIComponent(token),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(choice?{event,choice}:{event})});document.querySelector('#review').addEventListener('click',async()=>{await send('click');document.querySelector('#question').hidden=false});document.querySelectorAll('[data-choice]').forEach(button=>button.addEventListener('click',async()=>{await send('synthetic_response',button.dataset.choice);document.querySelector('#lesson').hidden=false;document.querySelector('#question').hidden=true}))})();</script></html>"""


def validate_event(payload):
    if not isinstance(payload, dict):
        raise ValueError("Event must be a JSON object.")
    event = payload.get("event")
    if event == "visit" and set(payload) == {"event"}:
        return {"event": "visit", "choice": None}
    if event == "click" and set(payload) == {"event"}:
        return {"event": "click", "choice": None}
    if event == "synthetic_response" and set(payload) == {"event", "choice"} and payload.get("choice") in {"yes", "no"}:
        return {"event": "synthetic_response", "choice": payload["choice"]}
    raise ValueError("Only visit, click, or synthetic yes/no events are accepted.")


def _make_server(manager):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urlsplit(self.path).path.split("/")
            if len(parts) != 3 or parts[1] != "session" or not manager.valid_token(parts[2]):
                self.send_error(404)
                return
            try:
                manager.record(parts[2], {"event": "visit"})
            except ValueError:
                self.send_error(410)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(_PAGE)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(_PAGE)

        def do_POST(self):
            parts = urlsplit(self.path).path.split("/")
            if len(parts) != 3 or parts[1] != "event" or not manager.valid_token(parts[2]):
                self.send_error(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                size = -1
            if size < 0 or size > MAX_EVENT_BYTES:
                self.send_error(413)
                return
            try:
                payload = json.loads(self.rfile.read(size).decode("utf-8"))
                result = manager.record(parts[2], payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self.send_error(400)
                return
            response = json.dumps({"ok": True, "event": result["event"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 0.5
    return server


class TrainingSessionManager:
    def __init__(self, on_event=None, on_status=None):
        self._lock = threading.RLock()
        self._on_event = on_event
        self._on_status = on_status
        self._session = None
        self._server = None
        self._thread = None
        self._timer = None

    def start_session(self, duration_seconds=15 * 60):
        if isinstance(duration_seconds, bool):
            raise ValueError("Session duration must be between 1 and 1800 seconds.")
        try:
            duration = int(duration_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("Session duration must be between 1 and 1800 seconds.") from exc
        if duration < 1 or duration > MAX_SESSION_SECONDS:
            raise ValueError("Session duration must be between 1 and 1800 seconds.")
        with self._lock:
            if self._session and self._session["status"] == "active" and time.monotonic() < self._session["expires_monotonic"]:
                raise ValueError("A training session is already active. Stop it before starting another.")
            if self._session and self._session["status"] == "active":
                self._expire_locked()
            token = secrets.token_urlsafe(32)
            session_id = "TRN-" + secrets.token_hex(6).upper()
            created = datetime.now(timezone.utc)
            expires = created + timedelta(seconds=duration)
            self._server = _make_server(self)
            host, port = self._server.server_address
            self._session = {"session_id": session_id, "token": token,
                             "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                             "host": host, "port": port, "created_at": created.isoformat(timespec="seconds"),
                             "expires_at": expires.isoformat(timespec="seconds"),
                             "expires_monotonic": time.monotonic() + duration,
                             "status": "active", "events": []}
            self._thread = Thread(target=self._server.serve_forever, name="wifisentinel-training", daemon=True)
            self._thread.start()
            self._timer = threading.Timer(duration, self.stop_session, kwargs={"status": "expired"})
            self._timer.daemon = True
            self._timer.start()
            return {"session_id": session_id, "url": f"http://{host}:{port}/session/{token}",
                    "host": host, "port": port, "created_at": self._session["created_at"],
                    "expires_at": self._session["expires_at"], "duration_seconds": duration,
                    "token_sha256": self._session["token_sha256"], "status": "active"}

    def valid_token(self, token):
        with self._lock:
            current = self._session
            return bool(current and current["status"] == "active" and
                        time.monotonic() < current["expires_monotonic"] and
                        hmac.compare_digest(str(current["token"]), str(token)))

    def record(self, token, payload):
        normalized = validate_event(payload)
        with self._lock:
            current = self._session
            if not current or current["status"] != "active" or time.monotonic() >= current["expires_monotonic"]:
                if current and current["status"] == "active":
                    self._expire_locked()
                raise ValueError("Training session is no longer active.")
            if not hmac.compare_digest(current["token"], str(token)):
                raise ValueError("Training session token is invalid.")
            entry = {"event": normalized["event"], "choice": normalized["choice"],
                     "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            current["events"].append(entry)
            if self._on_event:
                try:
                    self._on_event(current["session_id"], entry["event"], entry["choice"])
                except Exception as exc:
                    current["events"].pop()
                    raise ValueError("Training event could not be persisted.") from exc
            return entry

    def summary(self):
        with self._lock:
            if not self._session:
                return {"status": "unavailable", "events": {"visit": 0, "click": 0, "synthetic_yes": 0, "synthetic_no": 0}}
            if self._session["status"] == "active" and time.monotonic() >= self._session["expires_monotonic"]:
                self._expire_locked()
            events = self._session["events"]
            return {"session_id": self._session["session_id"], "status": self._session["status"],
                    "host": self._session["host"], "port": self._session["port"],
                    "created_at": self._session["created_at"], "expires_at": self._session["expires_at"],
                    "ended_at": self._session.get("ended_at"),
                    "token_sha256": self._session["token_sha256"],
                    "events": {"visit": sum(x["event"] == "visit" for x in events),
                               "click": sum(x["event"] == "click" for x in events),
                               "synthetic_yes": sum(x["choice"] == "yes" for x in events),
                               "synthetic_no": sum(x["choice"] == "no" for x in events)},
                    "event_history": [{"event": x["event"], "choice": x["choice"], "observed_at": x["observed_at"]}
                                      for x in events]}

    def stop_session(self, status="stopped"):
        if status not in {"stopped", "expired"}:
            raise ValueError("Invalid training session status.")
        with self._lock:
            if not self._session or self._session["status"] != "active":
                return self.summary()
            self._session["status"] = status
            self._session["ended_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            session_id, ended_at = self._session["session_id"], self._session["ended_at"]
            server, timer = self._server, self._timer
            self._server = None
            self._timer = None
            if timer and timer is not threading.current_thread():
                timer.cancel()
        if server:
            server.shutdown()
            server.server_close()
        if self._on_status:
            self._on_status(session_id, status, ended_at)
        return self.summary()

    def _expire_locked(self):
        if not self._session or self._session["status"] != "active":
            return
        self._session["status"] = "expired"
        self._session["ended_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        session_id, ended_at = self._session["session_id"], self._session["ended_at"]
        server, timer = self._server, self._timer
        self._server = None
        self._timer = None
        if timer and timer is not threading.current_thread():
            timer.cancel()
        if server:
            Thread(target=server.shutdown, daemon=True).start()
            server.server_close()
        if self._on_status:
            try:
                self._on_status(session_id, "expired", ended_at)
            except Exception:
                pass
