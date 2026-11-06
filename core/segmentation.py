"""Bounded, TCP-connect reachability checks for authorized segment reviews."""
from __future__ import annotations

import socket

from .nmap_runner import parse_ports, validate_target_scope


def normalize_plan(targets, ports, network_scope, expected, destination_segment):
    if isinstance(targets, str):
        targets = [part.strip() for part in targets.replace(";", ",").split(",") if part.strip()]
    if not isinstance(targets, (list, tuple)) or not targets:
        raise ValueError("Enter at least one literal IP target.")
    if len(targets) > 8:
        raise ValueError("A reachability review is limited to 8 targets.")
    normalized_targets = []
    for target in targets:
        validated = validate_target_scope(target, network_scope)
        if validated not in normalized_targets:
            normalized_targets.append(validated)
    parsed_ports = parse_ports(ports)
    if not parsed_ports:
        raise ValueError("Enter one to four explicit TCP ports.")
    if len(parsed_ports) > 4:
        raise ValueError("A reachability review is limited to 4 TCP ports.")
    expected = str(expected or "").strip().lower()
    if expected not in {"allowed", "blocked"}:
        raise ValueError("Select the expected policy as allowed or blocked.")
    destination_segment = str(destination_segment or "").strip()
    if not destination_segment or len(destination_segment) > 100:
        raise ValueError("Enter a destination segment label of 1 to 100 characters.")
    return {"targets": normalized_targets, "ports": parsed_ports, "expected": expected,
            "destination_segment": destination_segment}


def probe_tcp(target, port, timeout=0.75, connector=None):
    timeout = max(0.1, min(float(timeout), 2.0))
    connect = connector or socket.create_connection
    try:
        connection = connect((str(target), int(port)), timeout=timeout)
    except (socket.timeout, TimeoutError):
        status = "timeout"
    except ConnectionRefusedError:
        status = "closed"
    except OSError:
        status = "unreachable_or_error"
    else:
        try:
            connection.close()
        finally:
            status = "reachable"
    return {"target": str(target), "port": int(port), "protocol": "tcp", "status": status,
            "method": "TCP connection attempt; no application data sent", "timeout_seconds": timeout}


def evaluate_probe(probe, expected):
    status = str((probe or {}).get("status") or "unknown")
    expected = str(expected or "").strip().lower()
    mismatch = (expected == "blocked" and status == "reachable") or (expected == "allowed" and status == "closed")
    return {"mismatch": mismatch,
            "assessment": "observed_policy_mismatch" if mismatch else "no_direct_mismatch_observed",
            "limitation": "A timeout or generic network error is inconclusive; it does not prove filtering."}
