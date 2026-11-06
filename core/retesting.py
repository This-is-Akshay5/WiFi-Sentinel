"""Conservative retest outcome classification for persisted assessment findings."""
from __future__ import annotations


def _asset_key(value):
    return " ".join(str(value or "").strip().casefold().split())


def classify_finding_retest(finding, execution_result, fresh_findings, prior_evidence=None, fresh_evidence=None):
    """Classify only a completed rerun with new evidence from the same test.

    Finding title and asset are stable, observable comparison keys in the
    existing schema. A different finding for the same asset/category is only
    partial remediation; no comparable remaining finding is fixed. Failed,
    blocked, or evidence-free executions never count as a fix.
    """
    result = {"finding_id": (finding or {}).get("id"), "execution_id": (execution_result or {}).get("execution_id"),
              "evidence_id": (execution_result or {}).get("evidence_id")}
    if (not finding or not isinstance(execution_result, dict)
            or execution_result.get("status") != "completed"
            or not execution_result.get("evidence_id")):
        return {**result, "status": "unable_to_verify",
                "detail": "The matching check did not complete with newly persisted evidence."}

    asset = _asset_key(finding.get("asset"))
    title = _asset_key(finding.get("title"))
    category = _asset_key(finding.get("category"))
    source = _asset_key(finding.get("source_test"))
    same_asset = [row for row in fresh_findings or []
                  if _asset_key(row.get("asset")) == asset and asset]
    same_check = [row for row in same_asset
                  if _asset_key(row.get("source_test")) == source
                  and _asset_key(row.get("category")) == category]
    test_id = str(execution_result.get("test_id") or execution_result.get("test") or "")
    previous = prior_evidence if isinstance(prior_evidence, dict) else {}
    current = fresh_evidence if isinstance(fresh_evidence, dict) else {}
    if test_id == "nmap_scan":
        return {**result, **_compare_nmap(previous, current, asset)}
    if test_id in {"port_assessment", "gateway_exposure"}:
        return {**result, **_compare_tcp_probe(previous, current, asset)}
    if test_id == "connected_profile_audit":
        return {**result, **_compare_connected_profile(finding, previous, current)}
    if any(_asset_key(row.get("title")) == title for row in same_check):
        return {**result, "status": "unresolved",
                "detail": "The rerun reproduced the same finding for the same asset with new evidence."}
    if same_check:
        return {**result, "status": "partial",
                "detail": "The rerun returned a different finding for the same asset and check."}
    return {**result, "status": "unable_to_verify",
            "detail": "This check has no rule-specific negative-evidence comparison; absence of a new finding is not proof of remediation."}


def _port_key(row):
    try:
        port = int(row.get("port"))
    except (TypeError, ValueError):
        return None
    return (port, str(row.get("protocol") or "tcp").casefold())


def _compare_nmap(previous, current, asset):
    target = _asset_key(previous.get("target"))
    if not target or target != _asset_key(current.get("target")) or target != asset:
        return {"status": "unable_to_verify", "detail": "The new Nmap evidence does not establish coverage of the original target."}
    host = next((row for row in current.get("hosts") or []
                 if any(_asset_key(address.get("address")) == target
                        for address in row.get("addresses") or [])), None)
    if not host or host.get("status") != "up":
        return {"status": "unable_to_verify", "detail": "The original host was not confirmed up by the retest."}
    old_open = {_port_key(row) for row in previous.get("open_ports") or [] if _port_key(row)}
    if not old_open:
        return {"status": "unable_to_verify", "detail": "The original evidence does not identify the open ports needed for comparison."}
    states = {_port_key(row): str(row.get("state") or "unknown").casefold()
              for row in host.get("ports") or [] if _port_key(row)}
    missing = old_open - states.keys()
    if missing:
        summaries = host.get("extraports") or []
        try:
            summary_count = int(summaries[0].get("count") or 0) if len(summaries) == 1 else 0
        except (TypeError, ValueError):
            summary_count = 0
        if (len(summaries) != 1 or str(summaries[0].get("state") or "").casefold() != "closed"
                or summary_count != len(missing)):
            return {"status": "unable_to_verify", "detail": "Nmap did not return a per-port state or a complete closed-state summary for every original port."}
        states.update({port: "closed" for port in missing})
    if any(states.get(port) not in {"open", "closed"} for port in old_open):
        return {"status": "unable_to_verify", "detail": "Nmap returned an inconclusive state for at least one originally open port."}
    remain = {port for port in old_open if states.get(port) == "open"}
    if remain == old_open:
        return {"status": "unresolved", "detail": "The same host and all previously open Nmap ports remain open."}
    if remain:
        return {"status": "partial", "detail": "The host remains reachable; some previously open Nmap ports remain open."}
    return {"status": "fixed", "detail": "The same host was confirmed up and every previously open Nmap port was reported closed."}


def _compare_tcp_probe(previous, current, asset):
    target = _asset_key(previous.get("host"))
    if not target or target != _asset_key(current.get("host")) or target != asset:
        return {"status": "unable_to_verify", "detail": "The new TCP evidence does not establish coverage of the original host."}
    old_open = {_port_key(row) for row in previous.get("results") or []
                if str(row.get("state") or row.get("status") or "").casefold() == "open" and _port_key(row)}
    if not old_open:
        return {"status": "unable_to_verify", "detail": "The original evidence does not identify open ports to compare."}
    current_rows = {_port_key(row): str(row.get("state") or row.get("status") or "").casefold()
                    for row in current.get("results") or [] if _port_key(row)}
    if any(port not in current_rows or current_rows[port] not in {"open", "closed"} for port in old_open):
        return {"status": "unable_to_verify", "detail": "The retest did not return a conclusive open/closed state for every originally open port."}
    still_open = {port for port in old_open if current_rows[port] == "open"}
    if still_open == old_open:
        return {"status": "unresolved", "detail": "All previously open TCP ports remain reachable."}
    if still_open:
        return {"status": "partial", "detail": "Some previously open TCP ports remain reachable."}
    return {"status": "fixed", "detail": "All previously open TCP ports were observed closed in the same-host retest."}


def _compare_connected_profile(finding, previous, current):
    old_bssid = _asset_key(previous.get("bssid"))
    new_bssid = _asset_key(current.get("bssid"))
    if previous.get("connected") is not True or current.get("connected") is not True or not old_bssid or old_bssid != new_bssid:
        return {"status": "unable_to_verify", "detail": "The retest did not confirm the same connected BSSID."}
    title = _asset_key(finding.get("title"))
    old_auth = str(previous.get("auth") or "").casefold()
    old_cipher = str(previous.get("cipher") or "").casefold()
    new_auth = str(current.get("auth") or "").casefold()
    new_cipher = str(current.get("cipher") or "").casefold()
    if "not protected" in title:
        old_issue = "open" if any(word in old_auth + " " + old_cipher for word in ("open", "none")) else "unknown"
        new_mode = new_auth + " " + new_cipher
        new_issue = ("open" if any(word in new_mode for word in ("open", "none")) else
                     "wep" if "wep" in new_mode else "tkip" if "tkip" in new_mode else None)
    elif "wep" in title:
        old_issue = "wep"
        new_issue = "wep" if "wep" in new_auth + " " + new_cipher else (
            "legacy" if "tkip" in new_cipher else None)
    elif "tkip" in title:
        old_issue = "tkip"
        new_issue = "tkip" if "tkip" in new_cipher else ("wep" if "wep" in new_auth + " " + new_cipher else None)
    else:
        return {"status": "unable_to_verify", "detail": "This connected-profile finding has no specific remediation rule."}
    if old_issue == "unknown":
        return {"status": "unable_to_verify", "detail": "The original evidence does not confirm the security condition."}
    if new_issue == old_issue:
        return {"status": "unresolved", "detail": "The same connected BSSID still reports the original weak security mode."}
    if new_issue:
        return {"status": "partial", "detail": "The same BSSID reports a different but still weak security mode."}
    return {"status": "fixed", "detail": "The same connected BSSID no longer reports the original weak security mode."}
