"""Execution-time authorization checks for engagement scope manifests."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone


def _parse_instant(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _contains_ip(address, entries):
    try:
        candidate = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    for entry in entries or []:
        try:
            network = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            continue
        if candidate.version == network.version and candidate in network:
            return True
    return False


def authorize_execution(assessment, policy, activity, target=None, now=None):
    """Return an explicit allow/block result for an active assessment operation.

    ``policy`` is a persisted manifest. Missing or malformed authorization data
    fails closed. Scope membership in the assessment's declared CIDR/SSID fields
    remains a separate mandatory check in the assessment engine.
    """
    assessment = assessment or {}
    policy = policy or {}
    if not assessment.get("authorization"):
        return {"allowed": False, "reason": "Recorded authorization is required."}
    if policy.get("active") is not True:
        return {"allowed": False, "reason": "Engagement scope is not active; review and activate the scope manifest."}
    start = _parse_instant(policy.get("testing_start"))
    end = _parse_instant(policy.get("testing_end"))
    if not start or not end or start >= end:
        return {"allowed": False, "reason": "A valid timezone-aware testing start and end are required."}
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        return {"allowed": False, "reason": "Execution time must be timezone-aware."}
    current = current.astimezone(timezone.utc)
    if current < start or current > end:
        return {"allowed": False, "reason": "The current time is outside the authorized testing period."}
    permitted = {str(item).strip() for item in (policy.get("permitted_activities") or []) if str(item).strip()}
    if str(activity) not in permitted:
        return {"allowed": False, "reason": f"Activity '{activity}' is not permitted by the engagement rules."}
    windows = policy.get("testing_windows") or []
    if not isinstance(windows, list):
        return {"allowed": False, "reason": "Testing windows are malformed."}
    if windows:
        active = False
        for window in windows:
            if not isinstance(window, dict):
                continue
            window_start = _parse_instant(window.get("start"))
            window_end = _parse_instant(window.get("end"))
            if window_start and window_end and window_start <= current <= window_end:
                active = True
                break
        if not active:
            return {"allowed": False, "reason": "The current time is outside the configured testing windows."}
    if target:
        normalized = str(target).strip().rstrip(".").lower()
        excluded_hosts = {str(item).strip().rstrip(".").lower() for item in (policy.get("excluded_hosts") or [])}
        if normalized in excluded_hosts:
            return {"allowed": False, "reason": f"Target '{target}' is explicitly excluded."}
        if _contains_ip(target, policy.get("excluded_ip_ranges")):
            return {"allowed": False, "reason": f"Target '{target}' falls within an excluded IP range."}
        excluded_devices = {str(item).strip().lower() for item in (policy.get("excluded_devices") or [])}
        if normalized in excluded_devices:
            return {"allowed": False, "reason": f"Target '{target}' matches an excluded device."}
    return {"allowed": True, "reason": "Authorization, activity, time window, and exclusions passed."}
