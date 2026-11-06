import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from core.segmentation import evaluate_probe, normalize_plan, probe_tcp


class SegmentationPlanTests(unittest.TestCase):
    def test_plan_requires_literal_in_scope_targets_and_bounded_tcp_ports(self):
        result = normalize_plan(["192.168.10.8", "192.168.10.9"], "22,443", "192.168.10.0/24",
                               "blocked", "Corporate")
        self.assertEqual(result["targets"], ["192.168.10.8", "192.168.10.9"])
        self.assertEqual(result["ports"], [22, 443])
        self.assertEqual(result["expected"], "blocked")
        with self.assertRaisesRegex(ValueError, "outside"):
            normalize_plan(["192.168.11.8"], "443", "192.168.10.0/24", "blocked", "Corporate")
        with self.assertRaisesRegex(ValueError, "literal IP"):
            normalize_plan(["host.example"], "443", "192.168.10.0/24", "blocked", "Corporate")

    def test_plan_limits_targets_ports_and_policy_values(self):
        with self.assertRaisesRegex(ValueError, "8 targets"):
            normalize_plan([f"192.168.10.{i}" for i in range(1, 10)], "443", "192.168.10.0/24", "blocked", "Corp")
        with self.assertRaisesRegex(ValueError, "4 TCP ports"):
            normalize_plan(["192.168.10.8"], "22,80,443,445,3389", "192.168.10.0/24", "blocked", "Corp")
        with self.assertRaisesRegex(ValueError, "expected policy"):
            normalize_plan(["192.168.10.8"], "443", "192.168.10.0/24", "maybe", "Corp")


class TcpProbeTests(unittest.TestCase):
    def test_open_connection_is_closed_and_reports_reachable(self):
        connection = Mock()
        result = probe_tcp("192.168.10.8", 443, connector=lambda *_args, **_kwargs: connection)
        self.assertEqual(result["status"], "reachable")
        connection.close.assert_called_once_with()

    def test_refused_timeout_and_other_errors_remain_distinct(self):
        cases = [(ConnectionRefusedError(), "closed"), (socket.timeout(), "timeout"), (OSError(), "unreachable_or_error")]
        for error, expected in cases:
            with self.subTest(expected=expected):
                result = probe_tcp("192.168.10.8", 443,
                                   connector=lambda *_args, _error=error, **_kwargs: (_ for _ in ()).throw(_error))
                self.assertEqual(result["status"], expected)

    def test_only_direct_policy_mismatches_are_marked(self):
        self.assertTrue(evaluate_probe({"status": "reachable"}, "blocked")["mismatch"])
        self.assertTrue(evaluate_probe({"status": "closed"}, "allowed")["mismatch"])
        self.assertFalse(evaluate_probe({"status": "timeout"}, "blocked")["mismatch"])
        self.assertFalse(evaluate_probe({"status": "unreachable_or_error"}, "allowed")["mismatch"])

    def test_bridge_checks_scope_before_probe_and_persists_results(self):
        from unittest.mock import patch
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "segmentation.db")
            original_store = app.store
            try:
                app.store = test_store
                assessment = test_store.create_assessment({"name": "Authorized segment check",
                    "authorization": True, "network_scope": "192.168.10.0/24"})
                current = datetime.now(timezone.utc)
                test_store.set_scope_policy(assessment["id"], {
                    "active": True,
                    "testing_start": (current - timedelta(days=1)).isoformat(),
                    "testing_end": (current + timedelta(days=1)).isoformat(),
                    "permitted_activities": ["segmentation_reachability"],
                })
                bridge = app.Bridge()
                with patch.object(app.wifi, "network_context", return_value={"local_ip": "192.168.10.5",
                                "network": "192.168.10.0/24", "interface": "en0"}), \
                     patch.object(app, "probe_tcp", return_value={"target": "192.168.10.8", "port": 443,
                                "protocol": "tcp", "status": "reachable", "method": "TCP connect",
                                "timeout_seconds": 0.75}) as probe:
                    with self.assertRaisesRegex(ValueError, "not permitted"):
                        test_store.set_scope_policy(assessment["id"], {
                            "active": True,
                            "testing_start": (current - timedelta(days=1)).isoformat(),
                            "testing_end": (current + timedelta(days=1)).isoformat(),
                            "permitted_activities": [],
                        })
                        bridge.run_segmentation_reachability(assessment["id"], ["192.168.10.8"], "443",
                                                              "Corporate", "blocked", True)
                    probe.assert_not_called()
                    test_store.set_scope_policy(assessment["id"], {
                        "active": True,
                        "testing_start": (current - timedelta(days=1)).isoformat(),
                        "testing_end": (current + timedelta(days=1)).isoformat(),
                        "permitted_activities": ["segmentation_reachability"],
                    })
                    result = bridge.run_segmentation_reachability(assessment["id"], ["192.168.10.8"], "443",
                                                                  "Corporate", "blocked", True)
                    probe.assert_called_once()
                state = test_store.state(assessment["id"])
                self.assertEqual(result["probes"][0]["assessment"], "observed_policy_mismatch")
                self.assertEqual(len(state["evidence"]), 1)
                self.assertEqual(state["findings"][0]["severity"], "Low")
                self.assertEqual(state["executions"][0]["test_id"], "segmentation_reachability")
            finally:
                app.store = original_store
                test_store.close()


if __name__ == "__main__":
    unittest.main()
