"""Provenance-first device observation profiles.

Profiles describe one observation record at a time. They deliberately do not
join records by IP, MAC, hostname, or vendor into a stable device identity.
"""
from __future__ import annotations


_PROFILE_FIELDS = (
    "ip", "mac", "hostname", "vendor", "os", "type", "status", "interface",
    "is_gateway", "is_self", "observed_at", "first_seen", "last_seen",
    "dhcp_hostname", "ssid", "bssid", "channel", "vlan", "rssi",
)


def build_profiles(observations):
    """Render independent source observations with explicit field provenance."""
    if not isinstance(observations, (list, tuple)):
        raise ValueError("Device observations must be a list.")
    profiles = []
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        raw = observation.get("fields")
        raw = raw if isinstance(raw, dict) else {}
        source = str(observation.get("source") or "Unknown source")
        fields = {}
        for name in _PROFILE_FIELDS:
            value = raw.get(name)
            if name == "observed_at":
                value = value or observation.get("observed_at")
            status = "unavailable" if value is None or value == "" else "directly_observed"
            if name == "type" and value is not None:
                if raw.get("type_inferred") is True:
                    status = "estimated"
                elif raw.get("type_inferred") is False:
                    status = "source_reported"
                else:
                    status = "source_reported_basis_unspecified"
            elif name == "vendor" and raw.get("vendor_inferred") is True and value is not None:
                status = "estimated"
            fields[name] = {"value": value, "status": status, "source": source}

        classification_value = raw.get("type")
        if not classification_value or str(classification_value).casefold() in {"unknown", "unavailable"}:
            classification = {"value": None, "status": "unavailable", "confidence": None,
                              "basis": "No device classification was reported."}
        elif raw.get("type_inferred") is True:
            classification = {"value": classification_value, "status": "estimated", "confidence": "Low",
                              "basis": "Source marked device type as inferred."}
        else:
            classification = {"value": classification_value, "status": "source_reported", "confidence": None,
                              "basis": "Source reported a device type; inference status is unspecified."}

        ports = raw.get("open_ports")
        ports = ports if isinstance(ports, list) else []
        services = []
        for port in ports:
            if not isinstance(port, dict) or str(port.get("state") or "").casefold() != "open":
                continue
            services.append({**port, "source": source,
                             "confidence": "Nmap service fingerprint estimate" if "nmap" in source.casefold()
                             else "Observed open-port record"})

        profiles.append({
            "observation_id": observation.get("observation_id"),
            "assessment_id": observation.get("assessment_id"),
            "source": source,
            "method": observation.get("method"),
            "data_class": observation.get("data_class") or "unknown",
            "observed_at": observation.get("observed_at") or raw.get("observed_at"),
            "first_seen": observation.get("first_seen"),
            "last_seen": observation.get("last_seen"),
            "identity_claim": "observation_only",
            "fields": fields,
            "classification": classification,
            "services": services,
        })
    return profiles
