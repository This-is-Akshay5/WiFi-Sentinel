"""Evidence-led connected Wi-Fi audit and deterministic risk model."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math


MODEL_VERSION = "wifi-audit-v1"
RISK_BANDS = ((70, "Critical"), (40, "High"), (20, "Moderate"), (0, "Low"))
SEVERITY_FACTOR = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25,
                   "Informational": 0.0}
CORE_CHECKS = ("security_mode", "pmf", "gateway_reachability")


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _band(value):
    for lower, label in RISK_BANDS:
        if value >= lower:
            return label
    return "Low"


def _risk_factor(value, name):
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"Risk factor {name} must be a number from 0 to 1.") from None
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"Risk factor {name} must be a number from 0 to 1.")
    return value


def score_findings(findings, coverage):
    """Combine independent finding groups with noisy-or; correlated items max out.

    Per finding contribution is severity x exploitability x exposure x impact x
    evidence quality. Each input is normalized to [0,1]. The model is a product
    index, not a compliance score or industry-standard probability.
    """
    coverage = coverage or {}
    core_observed = int(coverage.get("core_checks_observed", 0) or 0)
    if core_observed < 0 or core_observed > len(CORE_CHECKS):
        raise ValueError("Core check coverage is outside the supported range.")

    correlated = {}
    contributions = []
    for finding in findings or []:
        if str(finding.get("status", "new")).casefold() in {"resolved", "verified_resolved"}:
            continue
        severity = finding.get("severity")
        if severity not in SEVERITY_FACTOR:
            raise ValueError(f"Unsupported finding severity: {severity}")
        factors = finding.get("risk_factors") or {}
        product = SEVERITY_FACTOR[severity]
        for factor_name in ("exploitability", "exposure", "impact", "evidence_quality"):
            product *= _risk_factor(factors.get(factor_name), factor_name)
        group = str(finding.get("correlation_group") or finding.get("check_id") or "ungrouped")
        previous = correlated.get(group)
        check_id = str(finding.get("check_id") or "")
        if previous is None or product > previous["contribution"] or (
                product == previous["contribution"] and check_id < previous["check_id"]):
            correlated[group] = {"contribution": product, "check_id": check_id}
        contributions.append({"check_id": finding.get("check_id"), "correlation_group": group,
                              "severity": severity, "contribution": round(product * 100, 2),
                              "risk_factors": {key: _risk_factor(factors.get(key), key) for key in
                                               ("exploitability", "exposure", "impact", "evidence_quality")}})

    combined = 1.0
    for group in sorted(correlated):
        combined *= 1.0 - correlated[group]["contribution"]
    for detail in contributions:
        maximum = correlated[detail["correlation_group"]]
        detail["included_in_score"] = detail["check_id"] == maximum["check_id"]
    contributions.sort(key=lambda row: (row["correlation_group"], str(row.get("check_id") or "")))
    risk_value = max(0, min(100, int(round((1.0 - combined) * 100))))
    material_finding = any(
        finding.get("severity") in {"Critical", "High"}
        and str(finding.get("status", "new")).casefold() not in {"resolved", "verified_resolved"}
        for finding in findings or []
    )
    enough_evidence = core_observed >= 2 or (material_finding and core_observed >= 1)
    return {
        "status": "scored" if enough_evidence else "insufficient_evidence",
        "value": risk_value if enough_evidence else None,
        "band": _band(risk_value) if enough_evidence else None,
        "model_version": MODEL_VERSION,
        "formula": "noisy-or: 100 x (1 - product(1 - max(contribution per correlation group))); contribution = severity x exploitability x exposure x impact x evidence quality",
        "severity_factors": dict(SEVERITY_FACTOR),
        "risk_band_thresholds": {"Low": "0-19", "Moderate": "20-39", "High": "40-69", "Critical": "70-100"},
        "factor_rationale": {
            "severity": "Fixed product weight: Critical 1.00, High 0.75, Medium 0.50, Low 0.25, Informational 0.00.",
            "exploitability": "Rule-coded estimate of practical ease for the observed condition; not a probability.",
            "exposure": "Rule-coded estimate of how directly the condition is exposed on the observed radio/network; not a client or attacker count.",
            "impact": "Rule-coded estimate of potential confidentiality, integrity, or availability harm.",
            "evidence_quality": "1.00 for direct OS-reported authentication/cipher; 0.80 for a parsed exact-BSSID PMF advertisement. Unknown evidence creates no finding.",
            "correlation": "Only the maximum contribution in each check correlation group is included; independent groups combine with noisy-or.",
        },
        "core_checks_observed": core_observed,
        "core_checks_required": 2,
        "contributions": contributions,
        "correlation_groups": len(correlated),
        "note": "Product-defined risk index. It is not a probability, compliance rating, or guarantee of security.",
    }


def compare_prior_findings(previous_audit, current_audit):
    """Compare prior findings only against new evidence for the same BSSID."""
    if not isinstance(previous_audit, dict) or not isinstance(current_audit, dict):
        return []
    previous_payload = previous_audit.get("payload") or {}
    previous_network = previous_payload.get("network") or {}
    current_network = current_audit.get("network") or {}
    previous_bssid = str(previous_network.get("bssid") or "").casefold()
    current_bssid = str(current_network.get("bssid") or "").casefold()
    if not previous_bssid or previous_bssid != current_bssid:
        return []
    applied = {str(row.get("finding_id")) for row in previous_audit.get("remediations") or []
               if row.get("status") == "applied"}
    finding_by_id = {str(row.get("id")): row for row in previous_payload.get("findings") or []}
    checks = {row.get("id"): row for row in current_audit.get("checks") or [] if isinstance(row, dict)}
    stamp = str(current_audit.get("observed_at") or _utc_now())
    verified = []
    for finding_id, finding in sorted(finding_by_id.items()):
        check = checks.get(finding.get("check_id"))
        if check and check.get("status") == "pass":
            status = "verified_resolved"
        elif check and check.get("status") == "finding":
            status = "still_present" if finding_id in applied else "recurring"
        else:
            status = "unable_to_verify"
        verified.append({"finding_id": finding_id, "check_id": finding.get("check_id"),
                         "title": finding.get("title"), "status": status,
                         "was_marked_applied": finding_id in applied,
                         "prior_audit_id": previous_audit.get("id"), "verified_at": stamp,
                         "evidence": check.get("evidence") if check else None,
                         "detail": check.get("detail") if check else "The matching check did not return verification evidence."})
    return verified


def _finding(check_id, title, severity, confidence, source, observed_at, evidence,
             description, impact, recommendation, verification, factors, category="Wireless security"):
    return {
        "id": f"WIFI-{check_id.upper()}", "check_id": check_id, "title": title,
        "category": category, "severity": severity, "confidence": confidence,
        "status": "new", "asset": evidence.get("ssid") or "Currently connected Wi-Fi network",
        "description": description, "impact": impact, "source": source,
        "observed_at": observed_at, "evidence": evidence,
        "recommendation": recommendation, "required_permissions": "Authorized network owner or administrator",
        "tradeoffs": "Changing Wi-Fi security may disconnect older client devices; validate compatibility before applying.",
        "verification": verification, "correlation_group": check_id,
        "risk_factors": factors,
    }


def evaluate(context, authorization_confirmed, gateway_probe=None):
    """Evaluate a fresh connected-network context; unavailable evidence stays unavailable."""
    if authorization_confirmed is not True:
        raise ValueError("Explicit authorization is required before running a Wi-Fi audit.")
    context = context if isinstance(context, dict) else {}
    wifi = context.get("wifi") if isinstance(context.get("wifi"), dict) else {}
    network = context.get("network") if isinstance(context.get("network"), dict) else {}
    source = str(context.get("source") or "Operating-system Wi-Fi adapter")
    observed_at = str(context.get("observed_at") or _utc_now())
    connected = wifi.get("connected") is True
    ssid = wifi.get("ssid") if isinstance(wifi.get("ssid"), str) and wifi.get("ssid") else None
    bssid = wifi.get("bssid") if isinstance(wifi.get("bssid"), str) and wifi.get("bssid") else None
    base = {"ssid": ssid, "bssid": bssid, "interface": wifi.get("interface") or network.get("interface"),
            "ssid_observed": wifi.get("ssid_observed"), "ssid_hidden": wifi.get("ssid_hidden") is True,
            "connection_state": "connected" if connected else (wifi.get("state") or "not_connected"),
            "local_ip": network.get("local_ip"), "subnet": network.get("network"),
            "gateway": network.get("gateway"), "band": wifi.get("band"), "channel": wifi.get("channel"),
            "signal_dbm": wifi.get("signal_dbm"), "authentication": wifi.get("auth"),
            "cipher": wifi.get("cipher"), "source": source, "observed_at": observed_at}
    checks, findings, recommendations, limitations = [], [], [], []

    checks.append({"id": "connected_network", "label": "Connected Wi-Fi identity",
                   "status": "pass" if connected and (ssid or bssid) else "unavailable",
                   "evidence": {key: base.get(key) for key in ("ssid", "bssid", "interface", "connection_state", "source", "observed_at")},
                   "detail": "Connected network identity reported by the operating system." if connected and (ssid or bssid)
                             else "The operating system did not confirm a connected Wi-Fi network and identity."})
    auth = str(wifi.get("auth") or "").strip()
    cipher = str(wifi.get("cipher") or "").strip()
    security_evidence = {"ssid": ssid, "bssid": bssid, "authentication": auth or None,
                         "cipher": cipher or None, "source": source, "observed_at": observed_at}
    weak_kind = None
    combined_security = f"{auth} {cipher}".casefold()
    if not connected or not auth:
        security_status, security_detail = "unavailable", "Connected-network authentication metadata was not reported."
    elif "open" in combined_security or auth.casefold() in {"none", "unsecured"}:
        security_status, security_detail, weak_kind = "finding", "The OS reports an open or unsecured network.", "open"
    elif "wep" in combined_security:
        security_status, security_detail, weak_kind = "finding", "The OS reports obsolete WEP security.", "wep"
    elif "tkip" in combined_security or ("wpa" in auth.casefold() and not any(x in auth.casefold() for x in ("wpa2", "wpa3"))):
        security_status, security_detail, weak_kind = "finding", "The OS reports legacy WPA/TKIP security.", "legacy"
    elif any(token in combined_security for token in ("wpa2", "wpa3", "wpa personal", "wpa enterprise")):
        security_status, security_detail = "pass", "The OS reports a protected Wi-Fi mode. The mode alone does not prove the network is secure."
    else:
        security_status, security_detail = "unavailable", "The reported authentication mode could not be classified safely."
    checks.append({"id": "security_mode", "label": "Encryption and authentication",
                   "status": security_status, "evidence": security_evidence if auth else None,
                   "detail": security_detail})
    if weak_kind:
        severity = {"open": "Critical", "wep": "High", "legacy": "High"}[weak_kind]
        recommendation = "Configure WPA3-Personal where supported, or WPA2-Personal with AES/CCMP; replace obsolete protocols and reconnect clients."
        finding = _finding("security_mode", "Weak or absent Wi-Fi encryption", severity, "High", source,
                           observed_at, security_evidence, security_detail,
                           "Nearby radio observers may be able to read traffic or gain network access, depending on the protocol and other protections.",
                           recommendation, "Re-run the audit after the access point reports WPA3 or WPA2-AES.",
                           {"exploitability": 0.95 if weak_kind == "open" else 0.8,
                            "exposure": 0.9 if weak_kind == "open" else 0.75,
                            "impact": 1.0 if weak_kind == "open" else 0.8, "evidence_quality": 1.0})
        findings.append(finding)
        recommendations.append({"finding_id": finding["id"], "priority": 1, "title": finding["title"],
                                "action": recommendation, "verification": finding["verification"], "status": "open"})

    pmf_ap = next((ap for ap in (wifi.get("nearby_aps") or []) if isinstance(ap, dict) and bssid
                   and str(ap.get("bssid") or "").casefold() == bssid.casefold()), None)
    pmf = (pmf_ap or {}).get("pmf_advertisement") if pmf_ap else None
    pmf_evidence = None
    if not connected or not bssid:
        pmf_status, pmf_detail = "unavailable", "Connected BSSID is unavailable; PMF cannot be matched safely."
    elif (not isinstance(pmf, dict) or not isinstance(pmf.get("advertised_capable"), bool)
          or not isinstance(pmf.get("advertised_required"), bool)
          or (pmf.get("advertised_required") is True and pmf.get("advertised_capable") is not True)):
        pmf_status, pmf_detail = "unavailable", "No complete PMF advertisement was reported for the exact connected BSSID."
    else:
        pmf_evidence = {"bssid": bssid, "advertised_capable": pmf["advertised_capable"],
                        "advertised_required": pmf["advertised_required"], "source": source,
                        "observed_at": pmf_ap.get("observed_at") or observed_at}
        pmf_status = "pass" if pmf["advertised_required"] else "finding"
        pmf_detail = "PMF is advertised as required for this BSSID." if pmf["advertised_required"] else (
            "PMF is advertised as capable but not required for this BSSID." if pmf["advertised_capable"]
            else "PMF is not advertised as capable for this BSSID.")
    checks.append({"id": "pmf", "label": "Protected Management Frames (PMF)", "status": pmf_status,
                   "evidence": pmf_evidence, "detail": pmf_detail})
    if pmf_status == "finding":
        finding = _finding("pmf", "PMF is not advertised as required", "Low", "High", source, observed_at,
                           pmf_evidence, pmf_detail,
                           "Management-frame protection is not required according to this access point advertisement; this is a configuration weakness, not evidence of an observed attack.",
                           "Enable 802.11w / Protected Management Frames as required if all client devices support it.",
                           "Re-scan the same BSSID and confirm advertised_required is true.",
                           {"exploitability": 0.35, "exposure": 0.4, "impact": 0.35, "evidence_quality": 0.8})
        findings.append(finding)
        recommendations.append({"finding_id": finding["id"], "priority": 3, "title": finding["title"],
                                "action": finding["recommendation"], "verification": finding["verification"], "status": "open"})

    gateway = network.get("gateway")
    probe = gateway_probe if isinstance(gateway_probe, dict) else {}
    try:
        valid_gateway = str(ipaddress.ip_address(gateway)) if gateway else None
    except ValueError:
        valid_gateway = None
    if valid_gateway and probe.get("status") in {"reachable", "unreachable"}:
        gateway_status = "pass" if probe.get("status") == "reachable" else "inconclusive"
        gateway_detail = "Gateway responded to a bounded ICMP reachability check." if gateway_status == "pass" else (
            "No ICMP response was observed; filtering may block ping, so this does not prove the gateway is offline.")
        gateway_evidence = {"gateway": valid_gateway, "method": "bounded ICMP reachability check",
                            "status": probe["status"], "source": probe.get("source") or "local OS ping",
                            "observed_at": probe.get("observed_at") or observed_at}
    else:
        gateway_status, gateway_detail, gateway_evidence = "unavailable", "A valid gateway and completed reachability check were not available.", None
    checks.append({"id": "gateway_reachability", "label": "Gateway reachability", "status": gateway_status,
                   "evidence": gateway_evidence, "detail": gateway_detail})

    checks.append({"id": "dns_configuration", "label": "DNS configuration", "status": "unavailable",
                   "evidence": None, "detail": "The current WiFiSentinel OS adapters do not expose DNS server configuration to this audit."})
    checks.append({"id": "router_configuration", "label": "Router administration settings", "status": "manual_verification",
                   "evidence": None, "detail": "WPS, firmware age, admin credentials, client isolation, and remote administration require the router owner's administrative interface."})
    checks.append({"id": "network_context_type", "label": "Router or personal hotspot context", "status": "manual_verification",
                   "evidence": None, "detail": "The host OS does not reliably identify whether the connected access point is a router or a phone hotspot. The audit does not infer device type; the owner must verify hotspot-specific controls on the phone."})
    checks.append({"id": "saved_credential", "label": "Saved Wi-Fi credential", "status": "not_accessed",
                   "evidence": None, "detail": "Credential access is a separate optional OS-authorized action and was not requested during this audit. A credential is never included in audit evidence."})
    recommendations.extend([
        {"finding_id": None, "priority": 4, "title": "Review owner-managed router or hotspot settings",
         "action": "As the network owner, install supported firmware updates; disable WPS and unnecessary remote administration; change default administrator credentials; use a long, unique Wi-Fi password; enable guest/client isolation where appropriate; and review connected devices through the legitimate router or phone interface. These are general hardening steps, not confirmed findings.",
         "verification": "Check the owner-managed router or phone settings directly.", "status": "manual_verification"},
        {"finding_id": None, "priority": 5, "title": "Review DNS and hotspot settings manually",
         "action": "Confirm DNS server choices and hotspot security/connected-device settings in the operating system or owner-managed router/phone interface.",
         "verification": "Record the settings from an authorized administrative interface.", "status": "manual_verification"},
    ])
    if not connected:
        limitations.append("No connected Wi-Fi network was confirmed by the operating system.")
        if wifi.get("error"):
            limitations.append(str(wifi["error"]))
    limitations.extend(check["detail"] for check in checks if check["status"] in {"unavailable", "manual_verification", "not_accessed", "inconclusive"})
    core_observed = sum(check["status"] in {"pass", "finding"} for check in checks if check["id"] in CORE_CHECKS)
    coverage = {"checks_total": len(checks), "checks_observed": sum(c["status"] in {"pass", "finding", "inconclusive"} for c in checks),
                "core_checks_total": len(CORE_CHECKS), "core_checks_observed": core_observed,
                "checks_unavailable": sum(c["status"] == "unavailable" for c in checks)}
    score = score_findings(findings, coverage)
    if score["status"] == "insufficient_evidence":
        score["reason"] = "Fewer than two of the core security, PMF, and gateway checks produced usable evidence, and no confirmed high-impact finding supports a score."
    return {"model_version": MODEL_VERSION, "created_at": _utc_now(), "status": "completed" if connected else "partial",
            "authorization_confirmed": True, "scope": "Currently connected Wi-Fi interface only",
            "network": base, "source": source, "observed_at": observed_at,
            "checks": checks, "coverage": coverage, "score": score, "findings": findings,
            "recommendations": recommendations, "limitations": list(dict.fromkeys(limitations)),
            "methodology": "Direct operating-system observations plus one authorized, bounded gateway ICMP check. Unknown values remain unknown."}
