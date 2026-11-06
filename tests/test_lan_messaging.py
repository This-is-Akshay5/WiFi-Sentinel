import unittest
import hashlib
import json
from unittest.mock import patch

from core.lan_messaging import (ReceiverServerManager, create_envelope, send_announcement, validate_receiver,
                                verify_acknowledgement)


TOKEN = "0123456789abcdef0123456789abcdef"


class LanMessagingTests(unittest.TestCase):
    def test_receiver_enrollment_requires_safe_endpoint_token_and_certificate_pin(self):
        receiver = validate_receiver("Lab receiver", "https://192.168.1.20:8765", TOKEN, "a" * 64, "lab-01")
        self.assertEqual(receiver["endpoint"], "https://192.168.1.20:8765")
        self.assertEqual(receiver["token"], TOKEN)
        for endpoint in ("http://192.168.1.20:8765", "https://user:pass@example.test/", "https://example.test/?token=x",
                         "https://example.test:443"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_receiver("Lab receiver", endpoint, TOKEN, "a" * 64, "lab-01")
        with self.assertRaisesRegex(ValueError, "32"):
            validate_receiver("Lab receiver", "https://192.168.1.20:8765", "short", "a" * 64, "lab-01")

    def test_message_envelope_is_signed_and_bound_to_receiver_and_expiry(self):
        envelope = create_envelope(TOKEN, "lab-01", "Maintenance notice", "A scheduled update starts at 18:00.", now=1_800_000_000)
        receiver = ReceiverServerManager(TOKEN, "lab-01")
        accepted = receiver.verify(envelope, now=1_800_000_001)
        self.assertEqual(accepted["title"], "Maintenance notice")
        with self.assertRaisesRegex(ValueError, "replay"):
            receiver.verify(envelope, now=1_800_000_001)
        other = ReceiverServerManager(TOKEN, "different-receiver")
        with self.assertRaisesRegex(ValueError, "receiver"):
            other.verify(envelope, now=1_800_000_001)
        tampered = {"payload": {**envelope["payload"], "body": "changed"}, "signature": envelope["signature"]}
        with self.assertRaisesRegex(ValueError, "signature"):
            receiver.verify(tampered, now=1_800_000_001)
        expired = create_envelope(TOKEN, "lab-01", "Expired", "Too late", now=1_800_000_000, lifetime_seconds=1)
        with self.assertRaisesRegex(ValueError, "expired"):
            ReceiverServerManager(TOKEN, "lab-01").verify(expired, now=1_800_000_002)

    def test_real_loopback_receiver_acceptance_requires_signed_acknowledgement(self):
        manager = ReceiverServerManager(TOKEN, "local-test-receiver")
        receiver = manager.start("127.0.0.1", 0)
        try:
            enrollment = validate_receiver("Loopback fixture", receiver["endpoint"], TOKEN,
                                           "0" * 64, "local-test-receiver", allow_loopback_http=True)
            result = send_announcement(enrollment, "Exercise", "Synthetic announcement only.")
            self.assertEqual(result["status"], "acknowledged")
            self.assertEqual(result["receiver_id"], "local-test-receiver")
            self.assertEqual(manager.inbox[0]["body"], "Synthetic announcement only.")
            self.assertEqual(result["certificate_sha256"], "0" * 64)
        finally:
            manager.stop()

    def test_acknowledgement_tampering_is_rejected(self):
        envelope = create_envelope(TOKEN, "lab", "Title", "Body", now=1_800_000_000)
        manager = ReceiverServerManager(TOKEN, "lab")
        accepted = manager.verify(envelope, now=1_800_000_001)
        ack = manager.acknowledge(accepted, now=1_800_000_002)
        self.assertTrue(verify_acknowledgement(TOKEN, ack, envelope["payload"]["message_id"]))
        ack["payload"]["status"] = "displayed"
        self.assertFalse(verify_acknowledgement(TOKEN, ack, envelope["payload"]["message_id"]))

    def test_bridge_requires_authorized_enrollment_and_send_and_never_returns_shared_token(self):
        import main as app
        bridge = app.Bridge()
        with self.assertRaisesRegex(ValueError, "Confirm"):
            bridge.enroll_lan_receiver("Lab receiver", "https://192.168.1.20:8765", TOKEN,
                                       "a" * 64, "lab-01", authorized=False)
        enrollment = bridge.enroll_lan_receiver("Lab receiver", "https://192.168.1.20:8765", TOKEN,
                                                "a" * 64, "lab-01", authorized=True)
        self.assertNotIn(TOKEN, str(enrollment))
        self.assertNotIn(TOKEN, str(bridge.enrolled_lan_receivers()))
        with self.assertRaisesRegex(ValueError, "Confirm"):
            bridge.send_lan_announcement(enrollment["enrollment_id"], "Title", "Body", authorized=False)
        with patch.object(app, "send_announcement", return_value={
            "status": "acknowledged", "message_id": "MSG-0123456789ABCDEF01234567",
            "receiver_id": "lab-01", "received_at": "2026-10-31T10:00:00+00:00",
            "certificate_sha256": "a" * 64,
            "delivery_claim": "Accepted by the enrolled receiver; human display/read status is not reported."}) as sender:
            result = bridge.send_lan_announcement(enrollment["enrollment_id"], "Sensitive title", "Sensitive body", authorized=True)
        self.assertTrue(result["ok"])
        self.assertNotIn("Sensitive body", str(result))
        self.assertNotIn(TOKEN, str(bridge.lan_message_history()))
        self.assertNotIn("Sensitive body", str(bridge.lan_message_history()))
        sender.assert_called_once()

    def test_bridge_records_unacknowledged_attempt_as_failure(self):
        import main as app
        from core.lan_messaging import DeliveryError
        bridge = app.Bridge()
        receiver = bridge.enroll_lan_receiver("Lab receiver", "https://192.168.1.20:8765", TOKEN,
                                              "a" * 64, "lab-01", authorized=True)
        with patch.object(app, "send_announcement", side_effect=DeliveryError("No verified receiver acknowledgement.")):
            result = bridge.send_lan_announcement(receiver["enrollment_id"], "Title", "Body", authorized=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "not_acknowledged")
        self.assertIsNone(result.get("message_id"))

    def test_https_delivery_checks_the_pinned_certificate_before_sending(self):
        from core.lan_messaging import DeliveryError

        class FakeSocket:
            def getpeercert(self, binary_form=False):
                return b"receiver-certificate"

        class FakeConnection:
            def __init__(self, *_args, **_kwargs):
                self.sock = FakeSocket()
                self.requested = False
            def connect(self):
                return None
            def request(self, *_args, **_kwargs):
                self.requested = True
            def close(self):
                return None

        receiver = validate_receiver("Lab", "https://192.168.1.20:8765", TOKEN, "f" * 64, "lab-01")
        with patch("core.lan_messaging.http.client.HTTPSConnection", FakeConnection):
            with self.assertRaisesRegex(DeliveryError, "fingerprint"):
                send_announcement(receiver, "Title", "Body")

    def test_https_delivery_requires_a_verified_receiver_ack(self):
        from core.lan_messaging import ReceiverServerManager

        cert = b"receiver-certificate"
        receiver = validate_receiver("Lab", "https://192.168.1.20:8765", TOKEN,
                                     hashlib.sha256(cert).hexdigest(), "lab-01")
        manager = ReceiverServerManager(TOKEN, "lab-01")

        class FakeSocket:
            def getpeercert(self, binary_form=False):
                return cert

        class FakeResponse:
            status = 200
            def __init__(self, body): self.body = body
            def read(self, _limit): return self.body

        class FakeConnection:
            def __init__(self, *_args, **_kwargs): self.sock=FakeSocket(); self.response=None
            def connect(self): return None
            def request(self, _method, _path, body=None, **_kwargs):
                accepted=manager.verify(json.loads(body))
                ack=manager.acknowledge(accepted)
                self.response=FakeResponse(json.dumps(ack).encode())
            def getresponse(self): return self.response
            def close(self): return None

        with patch("core.lan_messaging.http.client.HTTPSConnection", FakeConnection):
            result=send_announcement(receiver,"Title","Body")
        self.assertEqual(result["status"],"acknowledged")


if __name__ == "__main__":
    unittest.main()
