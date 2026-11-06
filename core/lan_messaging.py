"""Explicitly enrolled receiver messaging with pinned TLS and signed acknowledgements.

Delivery means a compatible receiver accepted the announcement. It does not
claim an OS notification was displayed or read by a person.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import ssl
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_MESSAGE_BYTES = 2048
MAX_TITLE_CHARS = 80
MAX_BODY_CHARS = 1000
_RECEIVER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class DeliveryError(RuntimeError):
    """An announcement was not verifiably acknowledged by the enrolled receiver."""


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def validate_receiver(name, endpoint, token, certificate_sha256, receiver_id, allow_loopback_http=False):
    name = str(name or "").strip()
    endpoint = str(endpoint or "").strip()
    token = str(token or "")
    receiver_id = str(receiver_id or "").strip()
    fingerprint = str(certificate_sha256 or "").replace(":", "").strip().lower()
    if not name or len(name) > 100 or any(ord(char) < 32 for char in name):
        raise ValueError("Receiver name must be 1–100 printable characters.")
    if len(token.encode("utf-8")) < 32:
        raise ValueError("Receiver enrollment token must contain at least 32 bytes.")
    if not _RECEIVER_ID.fullmatch(receiver_id):
        raise ValueError("Receiver ID must use 1–64 letters, digits, dots, underscores, or hyphens.")
    if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
        raise ValueError("Enter the receiver certificate's 64-character SHA-256 fingerprint.")
    parsed = urlsplit(endpoint)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("Receiver endpoint cannot contain credentials, query parameters, or fragments.")
    if not parsed.hostname or not parsed.port:
        raise ValueError("Receiver endpoint must include a hostname and explicit port.")
    try:
        endpoint_address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("Receiver endpoint must use a literal private or loopback IP address.") from exc
    if endpoint_address.is_unspecified or endpoint_address.is_multicast or endpoint_address.is_link_local or endpoint_address.is_reserved:
        raise ValueError("Receiver endpoint address is not a supported private or loopback address.")
    if not (endpoint_address.is_private or endpoint_address.is_loopback):
        raise ValueError("Receiver endpoint must be inside a private LAN or loopback interface.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Receiver endpoint must be an origin only; paths are fixed by the protocol.")
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and allow_loopback_http and endpoint_address.is_loopback:
        pass
    else:
        raise ValueError("Remote receivers require HTTPS with a pinned certificate; HTTP is allowed only for loopback tests.")
    return {"name": name, "endpoint": f"{parsed.scheme}://{parsed.netloc}", "token": token,
            "certificate_sha256": fingerprint, "receiver_id": receiver_id,
            "allow_loopback_http": bool(allow_loopback_http and parsed.scheme == "http" and endpoint_address.is_loopback)}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signature(token, payload):
    return hmac.new(str(token).encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()


def _message_text(value, label, limit):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text.")
    value = value.strip()
    if not value or len(value) > limit or any(ord(char) < 32 and char not in "\n\t\r" for char in value):
        raise ValueError(f"{label} must be 1–{limit} printable characters.")
    return value


def create_envelope(token, receiver_id, title, body, now=None, lifetime_seconds=300):
    if not _RECEIVER_ID.fullmatch(str(receiver_id or "")):
        raise ValueError("Receiver ID is invalid.")
    if len(str(token or "").encode("utf-8")) < 32:
        raise ValueError("Receiver enrollment token must contain at least 32 bytes.")
    if isinstance(lifetime_seconds, bool) or not 1 <= int(lifetime_seconds) <= 300:
        raise ValueError("Announcement expiry must be between 1 and 300 seconds.")
    issued = int(now if now is not None else time.time())
    payload = {"message_id": "MSG-" + secrets.token_hex(12).upper(),
               "receiver_id": str(receiver_id), "nonce": secrets.token_urlsafe(18),
               "issued_at": issued, "expires_at": issued + int(lifetime_seconds),
               "title": _message_text(title, "Title", MAX_TITLE_CHARS),
               "body": _message_text(body, "Message", MAX_BODY_CHARS)}
    return {"payload": payload, "signature": _signature(token, payload)}


def verify_acknowledgement(token, acknowledgement, message_id):
    if not isinstance(acknowledgement, dict) or set(acknowledgement) != {"payload", "signature"}:
        return False
    payload = acknowledgement.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"message_id", "receiver_id", "status", "received_at", "nonce"}:
        return False
    signature = acknowledgement.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, _signature(token, payload)):
        return False
    return payload.get("message_id") == message_id and payload.get("status") == "accepted" and bool(payload.get("receiver_id"))


class ReceiverServerManager:
    """Compatible receiver service; non-loopback binding requires HTTPS certificate files."""
    def __init__(self, token, receiver_id, on_message=None):
        if len(str(token or "").encode("utf-8")) < 32 or not _RECEIVER_ID.fullmatch(str(receiver_id or "")):
            raise ValueError("A 32-byte token and valid receiver ID are required.")
        self._token = str(token)
        self.receiver_id = str(receiver_id)
        self._on_message = on_message
        self._seen = {}
        self._lock = threading.RLock()
        self._server = None
        self._thread = None
        self.inbox = []

    def verify(self, envelope, now=None):
        current_time = int(now if now is not None else time.time())
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("Malformed announcement envelope.")
        payload, signature = envelope.get("payload"), envelope.get("signature")
        required = {"message_id", "receiver_id", "nonce", "issued_at", "expires_at", "title", "body"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise ValueError("Malformed announcement payload.")
        if not isinstance(signature, str) or not hmac.compare_digest(signature, _signature(self._token, payload)):
            raise ValueError("Announcement signature is invalid.")
        if payload["receiver_id"] != self.receiver_id:
            raise ValueError("Announcement names a different receiver.")
        if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
            raise ValueError("Announcement timestamps are invalid.")
        if payload["issued_at"] > current_time + 60 or current_time - payload["issued_at"] > 60:
            raise ValueError("Announcement timestamp is outside the accepted window.")
        if payload["expires_at"] <= current_time or payload["expires_at"] - payload["issued_at"] > 300:
            raise ValueError("Announcement is expired or exceeds the five-minute lifetime.")
        if not re.fullmatch(r"MSG-[A-F0-9]{24}", str(payload["message_id"])):
            raise ValueError("Announcement ID is invalid.")
        if not isinstance(payload["nonce"], str) or not 16 <= len(payload["nonce"]) <= 100:
            raise ValueError("Announcement nonce is invalid.")
        payload = {**payload, "title": _message_text(payload["title"], "Title", MAX_TITLE_CHARS),
                   "body": _message_text(payload["body"], "Message", MAX_BODY_CHARS)}
        with self._lock:
            for nonce, expiry in list(self._seen.items()):
                if expiry <= current_time:
                    self._seen.pop(nonce, None)
            if payload["nonce"] in self._seen:
                raise ValueError("Announcement nonce replay was rejected.")
            if len(self._seen) >= 5000:
                raise ValueError("Receiver replay cache is full; restart after reviewing receiver health.")
            self._seen[payload["nonce"]] = payload["expires_at"]
            accepted = {"message_id": payload["message_id"], "receiver_id": self.receiver_id,
                        "title": payload["title"], "body": payload["body"],
                        "received_at": datetime.fromtimestamp(current_time, timezone.utc).isoformat(timespec="seconds")}
            self.inbox.append(accepted)
            self.inbox = self.inbox[-500:]
        if self._on_message:
            self._on_message(dict(accepted))
        return accepted

    def acknowledge(self, accepted, now=None):
        payload = {"message_id": accepted["message_id"], "receiver_id": self.receiver_id,
                   "status": "accepted", "received_at": accepted["received_at"],
                   "nonce": secrets.token_urlsafe(18)}
        return {"payload": payload, "signature": _signature(self._token, payload)}

    def start(self, bind="127.0.0.1", port=8765, certfile=None, keyfile=None):
        try:
            address = ipaddress.ip_address(bind)
        except ValueError as exc:
            raise ValueError("Receiver bind address must be a literal IP address.") from exc
        if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved or not (address.is_private or address.is_loopback):
            raise ValueError("Receiver may bind only to a loopback or private interface address.")
        if not address.is_loopback and not (certfile and keyfile):
            raise ValueError("A TLS certificate and private key are required for LAN binding.")
        manager = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/v1/announcement":
                    self.send_error(404)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    size = -1
                if size < 0 or size > MAX_MESSAGE_BYTES:
                    self.send_error(413)
                    return
                try:
                    envelope = json.loads(self.rfile.read(size).decode("utf-8"))
                    accepted = manager.verify(envelope)
                    response = manager.acknowledge(accepted)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    self.send_error(400)
                    return
                body = _canonical(response)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = HTTPServer((str(address), int(port)), Handler)
        server.timeout = 0.5
        if certfile or keyfile:
            if not (certfile and keyfile):
                server.server_close()
                raise ValueError("Both TLS certificate and private key paths are required.")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certfile), str(keyfile))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="wifisentinel-receiver", daemon=True)
        self._thread.start()
        scheme = "https" if certfile else "http"
        fingerprint = None
        if certfile:
            pem = Path(certfile).read_text(encoding="ascii")
            der = ssl.PEM_cert_to_DER_cert(pem)
            fingerprint = hashlib.sha256(der).hexdigest()
        display_host = f"[{address}]" if address.version == 6 else str(address)
        return {"receiver_id": self.receiver_id, "host": str(address), "port": server.server_address[1],
                "endpoint": f"{scheme}://{display_host}:{server.server_address[1]}", "certificate_sha256": fingerprint}

    def stop(self):
        server, self._server = self._server, None
        if server:
            server.shutdown()
            server.server_close()


def send_announcement(receiver, title, body, now=None):
    receiver = dict(receiver or {})
    checked = validate_receiver(receiver.get("name"), receiver.get("endpoint"), receiver.get("token"),
                                receiver.get("certificate_sha256"), receiver.get("receiver_id"),
                                allow_loopback_http=receiver.get("allow_loopback_http") is True)
    parsed = urlsplit(checked["endpoint"])
    port = parsed.port
    envelope = create_envelope(checked["token"], checked["receiver_id"], title, body, now=now)
    raw = _canonical(envelope)
    connection = None
    try:
        if parsed.scheme == "https":
            context = ssl._create_unverified_context()
            connection = http.client.HTTPSConnection(parsed.hostname, port, timeout=3, context=context)
            connection.connect()
            cert = connection.sock.getpeercert(binary_form=True)
            actual_pin = hashlib.sha256(cert).hexdigest()
            if not hmac.compare_digest(actual_pin, checked["certificate_sha256"]):
                raise DeliveryError("Receiver TLS certificate fingerprint did not match the enrolled pin.")
        else:
            if not _loopback(parsed.hostname) or receiver.get("allow_loopback_http") is not True:
                raise DeliveryError("Cleartext HTTP is restricted to explicitly enabled loopback tests.")
            connection = http.client.HTTPConnection(parsed.hostname, port, timeout=3)
        connection.request("POST", "/v1/announcement", body=raw,
                           headers={"Content-Type": "application/json", "Content-Length": str(len(raw)),
                                    "Connection": "close"})
        response = connection.getresponse()
        data = response.read(MAX_MESSAGE_BYTES + 1)
        if len(data) > MAX_MESSAGE_BYTES or response.status != 200:
            raise DeliveryError(f"Receiver did not accept the announcement (HTTP {response.status}).")
        try:
            acknowledgement = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeliveryError("Receiver returned an invalid acknowledgement.") from exc
        message_id = envelope["payload"]["message_id"]
        if not verify_acknowledgement(checked["token"], acknowledgement, message_id):
            raise DeliveryError("Receiver acknowledgement signature or message ID did not verify.")
        ack = acknowledgement["payload"]
        return {"status": "acknowledged", "message_id": message_id, "receiver_id": ack["receiver_id"],
                "received_at": ack["received_at"], "certificate_sha256": checked["certificate_sha256"],
                "delivery_claim": "Accepted by the enrolled receiver; human display/read status is not reported."}
    except DeliveryError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise DeliveryError(f"No verified receiver acknowledgement was obtained ({type(exc).__name__}).") from exc
    finally:
        if connection:
            connection.close()
