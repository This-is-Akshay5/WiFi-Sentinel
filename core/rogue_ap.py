"""Evidence-preserving comparison of observed APs with an approved inventory.

An unlisted BSSID is a review item, not proof of a rogue access point. Rows
without an observed BSSID remain indeterminate and are never identity-matched
using SSID alone.
"""
from __future__ import annotations

import re


_BSSID = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def normalize_bssid(value: str) -> str:
    """Return a canonical unicast MAC address suitable for exact BSSID matching."""
    raw = str(value or "").strip().replace("-", ":").lower()
    if not _BSSID.fullmatch(raw):
        raise ValueError("BSSID must contain six hexadecimal octets.")
    octets = bytes.fromhex(raw.replace(":", ""))
    if octets == b"\x00" * 6 or octets == b"\xff" * 6 or octets[0] & 1:
        raise ValueError("BSSID must be a unicast address.")
    return ":".join(f"{part:02x}" for part in octets)


def compare_access_points(observed, approved):
    """Classify exact observations against approved BSSIDs, preserving source rows."""
    if not isinstance(observed, (list, tuple)) or not isinstance(approved, (list, tuple)):
        raise ValueError("Observed and approved access points must be lists.")
    approved_by_bssid = {}
    for item in approved:
        if not isinstance(item, dict) or not item.get("active", True):
            continue
        bssid = normalize_bssid(item.get("bssid"))
        approved_by_bssid[bssid] = dict(item)

    result = []
    for item in observed:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        raw_bssid = row.get("bssid")
        if not raw_bssid:
            status = "identity_unavailable"
            approved_record = None
            bssid = None
            conclusion = "BSSID unavailable; this observation cannot be matched to the inventory."
        else:
            bssid = normalize_bssid(raw_bssid)
            approved_record = approved_by_bssid.get(bssid)
            if approved_record:
                status = "approved"
                conclusion = "Observed BSSID matches the approved inventory."
            else:
                status = "unlisted"
                conclusion = "Unlisted observation; requires investigation."
        result.append({
            "status": status,
            "bssid": bssid,
            "ssid": row.get("ssid") if row.get("ssid_observed", row.get("ssid") is not None) else None,
            "ssid_observed": bool(row.get("ssid_observed", row.get("ssid") is not None)),
            "source": row.get("source") or "Operating-system Wi-Fi scan",
            "observed_at": row.get("observed_at"),
            "channel": row.get("channel"),
            "frequency_ghz": row.get("frequency_ghz"),
            "auth": row.get("auth"),
            "cipher": row.get("cipher"),
            "signal_dbm": row.get("signal_dbm"),
            "approved_record": ({"ssid": approved_record.get("ssid"), "notes": approved_record.get("notes")}
                                if approved_record else None),
            "conclusion": conclusion,
        })
    return result


def in_wireless_scope(observation, declared_scope):
    """Match only observed identifiers; never scope by an unobserved SSID placeholder."""
    if not isinstance(observation, dict):
        return False
    entries = {str(value).strip().casefold() for value in str(declared_scope or "").replace(";", ",").split(",")
               if str(value).strip()}
    if not entries:
        return False
    candidates = set()
    if observation.get("bssid"):
        try:
            candidates.add(normalize_bssid(observation["bssid"]).casefold())
        except ValueError:
            pass
    ssid_observed = observation.get("ssid_observed", observation.get("ssid") is not None)
    if ssid_observed and observation.get("ssid") is not None:
        candidates.add(str(observation["ssid"]).strip().casefold())
    return bool(entries & candidates)
