"""WiFiSentinel compatible enrolled receiver.

Run on a computer you administer. LAN binding requires an HTTPS certificate
and private key; the enrollment token is read from the environment and never
printed. See README.md for a launch example.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading

from core.lan_messaging import ReceiverServerManager


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a WiFiSentinel announcement receiver")
    parser.add_argument("--receiver-id", required=True, help="Stable operator-assigned ID, e.g. lab-laptop")
    parser.add_argument("--bind", default="127.0.0.1", help="Loopback or private interface IP; defaults to loopback")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--cert", help="TLS certificate PEM; required for LAN binding")
    parser.add_argument("--key", help="TLS private key PEM; required for LAN binding")
    args = parser.parse_args(argv)
    token = os.environ.get("WIFISENTINEL_RECEIVER_TOKEN", "")
    if len(token.encode("utf-8")) < 32:
        parser.error("Set WIFISENTINEL_RECEIVER_TOKEN to a random value of at least 32 bytes.")

    def display_message(message):
        print("\nAnnouncement accepted by this receiver")
        print(f"Title: {message['title']}")
        print(message["body"])
        print(f"Message ID: {message['message_id']}\n")

    manager = ReceiverServerManager(token, args.receiver_id, on_message=display_message)
    try:
        info = manager.start(args.bind, args.port, args.cert, args.key)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"WiFiSentinel receiver {info['receiver_id']} listening at {info['endpoint']}")
    if info["certificate_sha256"]:
        print(f"TLS certificate SHA-256: {info['certificate_sha256']}")
    else:
        print("Loopback-only mode. No remote receiver enrollment is possible.")
    print("Press Ctrl+C to stop. An ACK means the receiver accepted the message; it does not prove human display/read.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("Stopping receiver.")
    finally:
        manager.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
