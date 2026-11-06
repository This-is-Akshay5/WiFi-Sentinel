"""Bounded local Nmap execution for explicitly authorized IPv4/IPv6 hosts."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET


def validate_target_scope(target, scope):
    target = str(target or "").strip()
    if not target:
        raise ValueError("Enter one target IP address.")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Nmap currently accepts a literal IP address only; hostnames are not accepted.") from exc

    entries = [part.strip() for part in str(scope or "").replace(";", ",").split(",") if part.strip()]
    if not entries:
        raise ValueError("Declare a network scope before running Nmap.")

    allowed = False
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if address.version == network.version and address in network:
                allowed = True
                break
        except ValueError:
            try:
                if address == ipaddress.ip_address(entry):
                    allowed = True
                    break
            except ValueError:
                continue
    if not allowed:
        raise ValueError(f"Target {address} is outside the declared network scope.")
    return str(address)


def parse_ports(value):
    if value in (None, "", []):
        return None
    values = value if isinstance(value, (list, tuple)) else str(value).replace(";", ",").split(",")
    ports = set()
    for item in values:
        token = str(item).strip()
        if not token:
            continue
        if "-" in token:
            bits = token.split("-", 1)
            if len(bits) != 2 or not all(bit.strip().isdigit() for bit in bits):
                raise ValueError(f"Invalid port range: {token}")
            start, end = map(int, bits)
            if start > end or end - start > 255:
                raise ValueError("Each port range is limited to 256 ports.")
            ports.update(range(start, end + 1))
        elif token.isdigit():
            ports.add(int(token))
        else:
            raise ValueError(f"Invalid port: {token}")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535.")
    if len(ports) > 256:
        raise ValueError("A maximum of 256 explicitly selected ports is allowed per scan.")
    return sorted(ports)


class NmapRunner:
    def __init__(self, executable=None, timeout=300):
        self.executable = executable or shutil.which("nmap")
        self.timeout = max(30, min(int(timeout), 600))

    def scan(self, target, scope, ports=None):
        if not self.executable:
            raise RuntimeError("Nmap executable was not found. Install Nmap and inspect tools again.")
        target = validate_target_scope(target, scope)
        selected_ports = parse_ports(ports)
        command = [self.executable, "-sT", "-sV", "--version-light", "-T3",
                   "--reason", "--host-timeout", "4m", "-oX", "-", target]
        if selected_ports:
            command[1:1] = ["-p", ",".join(map(str, selected_ports))]
        else:
            command[1:1] = ["-F"]
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=self.timeout, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "Nmap exited unsuccessfully.").strip()
            raise RuntimeError(detail[-2000:])
        try:
            root = ET.fromstring(completed.stdout)
        except ET.ParseError as exc:
            raise RuntimeError("Nmap returned malformed XML; no scan results were persisted.") from exc
        if root.tag != "nmaprun":
            raise RuntimeError("Nmap output did not contain an nmaprun document.")
        hosts = []
        for host in root.findall("host"):
            status = host.find("status")
            addresses = [{"type": item.get("addrtype"), "address": item.get("addr")}
                         for item in host.findall("address")]
            ports_found = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                ports_found.append({
                    "protocol": port.get("protocol"), "port": int(port.get("portid")),
                    "state": state.get("state") if state is not None else "unknown",
                    "reason": state.get("reason") if state is not None else None,
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                })
            extraports = []
            for item in host.findall("./ports/extraports"):
                reasons = [{"reason": reason.get("reason"), "count": int(reason.get("count") or 0)}
                           for reason in item.findall("extrareasons")]
                extraports.append({"state": item.get("state") or "unknown",
                                   "count": int(item.get("count") or 0), "reasons": reasons})
            hosts.append({"status": status.get("state") if status is not None else "unknown",
                          "addresses": addresses, "ports": ports_found, "extraports": extraports})
        runstats = root.find("runstats")
        finished = runstats.find("finished") if runstats is not None else None
        return {
            "target": target, "command": command, "exit_code": completed.returncode,
            "scanner": root.get("scanner"), "version": root.get("version"),
            "started": root.get("startstr"), "finished": finished.get("timestr") if finished is not None else None,
            "hosts": hosts, "host_count": len(hosts),
            "open_ports": [dict(host=host["addresses"][0]["address"] if host["addresses"] else target, **port)
                           for host in hosts for port in host["ports"] if port["state"] == "open"],
            "ports_requested": selected_ports or "Nmap fast default (top 100 TCP ports)",
            "method": "TCP connect scan with light service version detection; no NSE scripts or OS detection",
            "limitations": ["Only the single explicitly scoped IP was scanned.",
                            "Service/version strings are Nmap fingerprint estimates, not authenticated service identity.",
                            "Only TCP connect scanning is used; UDP and wireless 802.11 testing are not included."],
        }
