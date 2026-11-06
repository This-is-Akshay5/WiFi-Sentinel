"""Assessment lifecycle and security-test execution.

Rules enforced here, not in the UI
----------------------------------
* No execution without recorded authorization.
* No network test outside the declared network scope, and no wireless test
  outside the declared wireless scope.
* A test either runs and persists evidence, or is blocked with a reason. There
  is no path that records a finding without an evidence row behind it.
* Findings are derived from observations. Nothing is created to populate a view.
"""
from __future__ import annotations

import ipaddress
import threading
from datetime import datetime, timezone

from .catalog import BY_ID, TEST_CATALOG, categories, get as catalog_get
from .dataset_engine import DEFAULT_DISASSOCIATION_THRESHOLD
from .logging_setup import get_logger
from .posture import calculate as calculate_posture
from .nmap_runner import NmapRunner, validate_target_scope
from .engagement_scope import authorize_execution

log = get_logger("assessment")

MANAGEMENT_PORTS = (21, 22, 23, 53, 80, 443, 445, 554, 3389, 8080, 8443)

#: Ordered lifecycle stages used by the Execution tab and the progress bar.
LIFECYCLE_STAGES = (
    ("scope", "Scope"),
    ("authorization", "Authorization"),
    ("preflight", "Preflight"),
    ("discovery", "Discovery"),
    ("testing", "Testing"),
    ("execution", "Execution"),
    ("evidence", "Evidence"),
    ("findings", "Findings"),
    ("ai", "AI analysis"),
    ("posture", "Posture"),
    ("report", "Report"),
)

CATEGORIES = ("Wireless Security", "Network Discovery", "Traffic Analysis", "Authentication", "Network Security")


class AssessmentEngine:
    def __init__(self, store, wifi, dataset, nmap_path=None):
        self.store = store
        self.wifi = wifi
        self.dataset = dataset
        self.nmap = NmapRunner(nmap_path)
        self._threads = {}

    # ------------------------------------------------------------------ scope
    def _in_scope(self, host, scope):
        """True when ``host`` is inside the declared scope string.

        Scope accepts CIDR networks, comma/semicolon separated lists, bare IPs
        and hostnames. An empty scope means "no network scope declared", which
        the caller treats as a block for network tests.
        """
        if not scope:
            return False
        host = (host or "").strip()
        if not host:
            return False
        entries = [x.strip() for x in str(scope).replace(";", ",").split(",") if x.strip()]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return host.lower() in {e.lower() for e in entries}
        for entry in entries:
            try:
                if "/" in entry:
                    if address in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ipaddress.ip_address(entry) == address:
                    return True
            except ValueError:
                continue
        return False

    def _wireless_in_scope(self, assessment, bssid=None, ssid=None):
        """True when the observed radio falls inside the declared wireless scope.

        Wireless assessment tests require an explicit SSID or BSSID scope.
        """
        declared = (assessment.get("wireless_scope") or "").strip()
        if not declared:
            return False
        entries = [x.strip().lower() for x in declared.replace(";", ",").split(",") if x.strip()]
        candidates = [str(x).strip().lower() for x in (bssid, ssid) if x]
        return any(entry in candidates for entry in entries)

    def _in_scope_aps(self, assessment, aps):
        """Keep only BSSID observations explicitly covered by the assessment."""
        return [ap for ap in (aps or [])
                if self._wireless_in_scope(assessment, ap.get("bssid"), ap.get("ssid"))]

    def _wifi_source(self, operation="scan"):
        os_type = getattr(self.wifi, "os_type", None)
        if os_type == "Windows":
            return f"Windows WLAN netsh {operation}"
        if os_type == "Darwin":
            return f"macOS networksetup/airport {operation}"
        return f"Operating-system Wi-Fi {operation}"

    # -------------------------------------------------------------- preflight
    def preflight(self, aid):
        assessment = self.store.assessment(aid)
        checks = []
        if not assessment:
            return {"assessment": None, "checks": [], "ready": False, "error": "Assessment not found."}

        authorized = bool(assessment["authorization"])
        checks.append({
            "id": "authorization", "label": "Assessment authorization",
            "status": "pass" if authorized else "fail",
            "detail": f"Confirmed{(' by ' + assessment['authorized_by']) if assessment.get('authorized_by') else ''}"
                      if authorized else "Execution is blocked until authorization is recorded.",
        })
        scope = (assessment.get("network_scope") or "").strip()
        checks.append({
            "id": "scope", "label": "Declared network scope",
            "status": "pass" if scope else "warn",
            "detail": scope or "No network scope declared; network tests will be blocked.",
        })
        checks.append({
            "id": "wireless_scope", "label": "Declared wireless scope",
            "status": "pass" if (assessment.get("wireless_scope") or "").strip() else "warn",
            "detail": assessment.get("wireless_scope") or "No wireless scope declared; wireless tests will be blocked.",
        })
        active_policy = self.store.scope_policy(aid)
        policy_activities = active_policy.get("permitted_activities") or []
        policy_check = authorize_execution(
            assessment, active_policy, policy_activities[0] if policy_activities else "",
            now=datetime.now(timezone.utc),
        )
        checks.append({
            "id": "engagement_policy", "label": "Active engagement policy",
            "status": "pass" if policy_check["allowed"] else "fail",
            "detail": policy_check["reason"],
        })
        checks.extend(self.wifi.preflight() if self.wifi else [])
        summary = self.dataset.summary() if self.dataset else {"records": 0, "available": False}
        checks.append({
            "id": "dataset", "label": "Research dataset",
            "status": "pass" if summary.get("records") else "warn",
            "detail": f"{summary.get('records', 0):,} research records available" if summary.get("records")
                      else "Research dataset not present; dataset tests will report as unavailable.",
        })
        blocking = [c for c in checks if c["status"] == "fail"]
        return {
            "assessment": assessment,
            "checks": checks,
            "ready": not blocking,
            "blocking": blocking,
            "executable_locally": sum(1 for t in TEST_CATALOG if t["execution_path"] == "local"),
        }

    # ---------------------------------------------------------------- catalog
    def catalog_view(self, aid=None):
        """Catalog annotated with the current execution status of every test."""
        assessment = self.store.assessment(aid) if aid else None
        executions = self.store.executions(aid, limit=200) if aid else []
        status_by_test = {}
        for execution in executions:
            test_id = execution.get("test_id")
            if not test_id:
                continue
            previous = status_by_test.get(test_id)
            if previous is None or (execution.get("started_at") or "") >= (previous.get("started_at") or ""):
                status_by_test[test_id] = execution
        authorized = bool(assessment and assessment["authorization"])
        scope = (assessment.get("network_scope") or "") if assessment else ""
        wireless_scope = (assessment.get("wireless_scope") or "") if assessment else ""
        gateway = None
        if assessment:
            try:
                gateway = self.wifi.gateway()
            except Exception:
                gateway = None

        groups = []
        for group in categories():
            tests = []
            for test in group["tests"]:
                execution = status_by_test.get(test["id"])
                block_reason = self._block_reason(assessment, test, gateway=gateway)
                blocked = bool(block_reason)
                tests.append({
                    **test,
                    "blocked": blocked,
                    "status": "blocked" if blocked else ((execution or {}).get("status") or "available"),
                    "status_reason": block_reason if blocked else _status_detail(execution),
                    "execution_id": (execution or {}).get("id"),
                    "last_run": (execution or {}).get("completed_at") or (execution or {}).get("started_at"),
                    "evidence_count": self.store.evidence_count(aid, test["id"]) if aid else 0,
                })
            groups.append({**group, "tests": tests})
        return {
            "groups": groups,
            "authorized": authorized,
            "network_scope": scope,
            "wireless_scope": wireless_scope,
            "catalog_size": len(TEST_CATALOG),
        }

    def _block_reason(self, assessment, test, gateway=None, target=None):
        if not assessment:
            return "Open an assessment before running tests."
        if not assessment.get("authorization"):
            return "Authorization is required before execution."
        if test.get("active"):
            policy = self.store.scope_policy(assessment.get("id"))
            decision = authorize_execution(assessment, policy, test["id"], target or gateway)
            if not decision["allowed"]:
                return decision["reason"]
        if test["scope_requirement"] == "network" and not (assessment.get("network_scope") or "").strip():
            return "Declare a network scope before running this test."
        if test["scope_requirement"] == "wireless" and not (assessment.get("wireless_scope") or "").strip():
            return "Declare an explicit SSID or BSSID wireless scope before running this test."
        if test["id"] == "wifi_discovery" or test["id"] in ("connected_profile_audit", "open_authentication_scan",
                                                            "channel_congestion", "rogue_bssid_check"):
            os_type = getattr(self.wifi, "os_type", None)
            if os_type not in ("Windows", "Darwin"):
                return "Live WLAN telemetry is unsupported on this operating system."
            if os_type == "Darwin":
                try:
                    if not self.wifi.interfaces():
                        wifi_info = self.wifi.wifi_info()
                        if wifi_info.get("state") == "permission_required":
                            return wifi_info.get("error") or "macOS permission is required for Wi-Fi discovery."
                        return "No Wi-Fi interface is currently exposed by the operating system."
                except Exception:
                    return "The operating system could not query a Wi-Fi interface."
        if test["id"] in ("association_dataset_analysis", "disassociation_detection"):
            if not (self.dataset and self.dataset.available):
                return "Research dataset is not present on disk."
        if test["id"] == "nmap_scan" and not self.nmap.executable:
            return "Nmap is not installed or could not be located."
        if test["id"] == "nmap_scan" and not self.nmap.executable:
            return "Nmap is not installed or could not be located."
        if test["id"] == "gateway_exposure" and not gateway:
            return "No default gateway is exposed by the operating system."
        return None

    # --------------------------------------------------------------- lifecycle
    def lifecycle(self, aid):
        """Where the assessment currently sits in the documented lifecycle."""
        assessment = self.store.assessment(aid)
        if not assessment:
            return []
        executions = self.store.executions(aid, limit=25)
        evidence = self.store.evidence(aid, limit=1)
        findings = self.store.findings(aid)
        ai_analyses = self.store.ai_analyses(aid, limit=1)
        completed_tests = {e.get("test_id") for e in executions if e.get("status") == "completed"}
        state = {
            "scope": bool((assessment.get("network_scope") or "").strip()
                          or (assessment.get("wireless_scope") or "").strip()),
            "authorization": bool(assessment.get("authorization")),
            "preflight": bool(executions) or bool(self.store.active_execution(aid)),
            "discovery": bool(completed_tests & {"wifi_discovery", "device_discovery"}),
            "testing": len(completed_tests) > 1,
            "execution": bool(executions),
            "evidence": bool(evidence),
            "findings": bool(findings),
            "ai": bool(ai_analyses),
            "posture": bool(executions) and bool(findings),
            "report": bool(self.store.ai_analyses(aid, limit=5)),
        }
        states = {
            "scope": "complete" if state["scope"] else "required",
            "authorization": "complete" if state["authorization"] else "required",
            "preflight": "complete" if state["preflight"] else ("running" if state["execution"] else "pending"),
            "discovery": "complete" if state["discovery"] else ("blocked" if state["execution"] else "pending"),
            "testing": "complete" if state["testing"] else "pending",
            "execution": "complete" if state["execution"] else "pending",
            "evidence": "complete" if state["evidence"] else "pending",
            "findings": "complete" if state["findings"] else "pending",
            "ai": "complete" if state["ai"] else "pending",
            "posture": "complete" if state["posture"] else "pending",
            "report": "complete" if state["report"] else "pending",
        }
        return [
            {"stage": key, "label": label, "state": states[key]}
            for key, label in LIFECYCLE_STAGES
        ]

    # --------------------------------------------------------------- execution
    def execute(self, aid, initiated_by="operator"):
        """Run the default authorized collection pass in the background."""
        assessment = self.store.assessment(aid)
        if not assessment:
            return {"error": "Assessment not found."}
        if not assessment["authorization"]:
            return {"blocked": True, "reason": "Authorization is required before execution."}
        gateway = None
        try:
            gateway = self.wifi.gateway()
        except Exception:
            gateway = None
        plan = self.default_plan(aid, gateway=gateway)
        if not plan:
            return {"blocked": True, "reason": "No locally supported test is currently available."}
        execution_id = self.store.start_execution(aid, "Authorized collection pass", "authorized_collection_pass", initiated_by)
        worker = threading.Thread(target=self._run_pass, args=(aid, execution_id, plan), daemon=True,
                                  name=f"ws-assessment-{aid}")
        self._threads[aid] = worker
        worker.start()
        log.info("assessment_execution_started", extra={"context": {"assessment_id": aid, "execution_id": execution_id}})
        return {"execution_id": execution_id, "planned_tests": [t["id"] for t in plan]}

    def default_plan(self, aid, gateway=None):
        """Locally supported tests that are actually runnable for this assessment."""
        catalog = self.catalog_view(aid)
        plan = []
        for group in catalog["groups"]:
            for test in group["tests"]:
                if test["execution_path"] == "local" and not test["blocked"]:
                    if test["id"] == "gateway_exposure" and not gateway:
                        continue
                    plan.append(test)
        return plan

    def _run_pass(self, aid, execution_id, plan):
        total = len(plan) + 1
        step = 0
        try:
            step += 1
            self.store.update_execution(execution_id, "discovery", int(100 * step / total))
            self.store.event(aid, execution_id, "discovery", f"Starting authorized collection pass over {len(plan)} test(s)")
            for test in plan:
                self.store.update_execution(execution_id, "testing", int(100 * step / total))
                self.store.event(aid, execution_id, "test", f"Running {test['name']}")
                try:
                    self.run_test(aid, test["id"], {}, execution_id=execution_id, quiet=True)
                except Exception as exc:  # one failing test must not abort the pass
                    self.store.event(aid, execution_id, "error", f"{test['name']} failed: {exc}")
                    log.error("test_failed", extra={"context": {"assessment_id": aid, "test": test["id"],
                                                                "error": str(exc)}})
                step += 1
                self.store.update_execution(execution_id, "testing", int(100 * step / total))
            self.store.update_execution(execution_id, "evidence", 100)
            self.store.event(aid, execution_id, "evidence", "Collection pass complete; evidence persisted")
            completed_at = self.store.execution_completed_at(execution_id)
            self.store.set_status(aid, "completed", completed_at=completed_at)
            log.info("assessment_execution_completed", extra={"context": {"assessment_id": aid,
                                                                          "execution_id": execution_id}})
        except Exception as exc:
            self.store.update_execution(execution_id, "failed", 100, "failed", str(exc))
            self.store.set_status(aid, "failed")
            self.store.event(aid, execution_id, "error", f"Collection pass failed: {exc}")
            log.error("assessment_execution_failed", extra={"context": {"assessment_id": aid, "error": str(exc)}})

    # ------------------------------------------------------------- test runner
    def run_test(self, aid, test_id, config=None, execution_id=None, quiet=False):
        """Execute one catalog test. Returns a structured result; never raises."""
        assessment = self.store.assessment(aid)
        config = config or {}
        if not assessment:
            return {"status": "error", "error": "Assessment not found."}
        test = catalog_get(test_id)
        if not test:
            return {"status": "error", "error": f"Unknown test: {test_id}"}
        if not assessment.get("authorization"):
            return self._blocked(aid, test_id, execution_id, "Authorization is required before execution.",
                                 include_evidence=not quiet)

        gateway = None
        if test["scope_requirement"] == "network":
            try:
                gateway = self.wifi.gateway()
            except Exception:
                gateway = None
        requested_target = config.get("target") or config.get("host") or gateway
        block_reason = self._block_reason(assessment, test, gateway=gateway, target=requested_target)
        if block_reason:
            return self._blocked(aid, test_id, execution_id, block_reason, include_evidence=not quiet)

        ex = execution_id or self.store.start_execution(aid, test["name"], test_id)
        meta = {"scope": _scope_label(assessment, test), "test": test_id,
                "data_class": "research" if test["id"].startswith(("association_", "disassociation_")) else "live",
                "execution_path": test["execution_path"]}
        self.store.event(aid, ex, "test", f"{test['name']} started")
        try:
            result = self._run_test_body(aid, ex, test, config, assessment, gateway, meta)
        except Exception as exc:
            self.store.update_execution(ex, "failed", 100, "failed", str(exc))
            self.store.set_status(aid, "failed")
            self.store.event(aid, ex, "error", f"{test['name']} failed: {type(exc).__name__}")
            log.error("test_failed", extra={"context": {"assessment_id": aid, "test": test_id, "error": str(exc)}})
            return {"status": "failed", "execution_id": ex, "test": test_id,
                    "error": f"{test['name']} could not complete: {type(exc).__name__}. See logs/wifisentinel.log."}
        if result.get("status") == "blocked":
            return {**result, "execution_id": result.get("execution_id") or ex}
        self.store.update_execution(ex, "completed", 100, "completed")
        self.store.set_status(aid, "completed", completed_at=self.store.execution_completed_at(ex))
        self.store.event(aid, ex, "completed", f"{test['name']} completed")
        log.info("test_completed", extra={"context": {"assessment_id": aid, "test": test_id, "execution_id": ex}})
        return {"status": "completed", "execution_id": ex, "test": test_id, **result}

    def _run_test_body(self, aid, ex, test, config, assessment, gateway, meta):
        test_id = test["id"]
        if test_id == "wifi_discovery":
            observed = self.wifi.wifi_info()
            aps = self._in_scope_aps(assessment, observed.get("nearby_aps", []))
            info = {"state": observed.get("state"), "observed_at": observed.get("observed_at"),
                    "scope": assessment.get("wireless_scope"), "nearby_aps": aps,
                    "observation_count_in_scope": len(aps)}
            evidence_id = self.store.add_evidence(aid, ex, "wireless_scan", self._wifi_source("scan"), info, meta,
                                                  label=f"{len(aps)} in-scope Wi-Fi observations")
            for ap in aps:
                self.store.add_network(aid, ap)
            return {"summary": f"{len(aps)} in-scope Wi-Fi observations persisted", "observations": len(aps),
                    "evidence_id": evidence_id}

        if test_id == "connected_profile_audit":
            info = self.wifi.wifi_info()
            if not self._wireless_in_scope(assessment, info.get("bssid"), info.get("ssid")):
                return self._wireless_scope_blocked(aid, ex, test, info, assessment)
            evidence_id = self.store.add_evidence(aid, ex, "wireless_observation", self._wifi_source("interface query"),
                                                  info, meta, label="Connected association profile")
            self._profile_findings(aid, ex, info, evidence_id)
            return {"summary": "Connected profile audited", "evidence_id": evidence_id}

        if test_id == "open_authentication_scan":
            info = self.wifi.wifi_info()
            aps = self._in_scope_aps(assessment, info.get("nearby_aps", []))
            weak = [ap for ap in aps if _is_open_or_legacy(ap)]
            evidence_id = self.store.add_evidence(aid, ex, "wireless_scan", self._wifi_source("scan"),
                                                  {"network_observations_examined": len(aps), "open_or_legacy": weak}, meta,
                                                  label=f"{len(weak)} of {len(aps)} in-scope networks")
            if weak:
                self.store.add_finding(
                    aid, ex, "Nearby networks broadcast open or legacy protection",
                    "Medium",
                    f"{len(weak)} of {len(aps)} in-scope network observations report open authentication or a legacy WEP/TKIP cipher.",
                    "Open or legacy-protected wireless networks permit unauthenticated association and weak link protection.",
                    "Nearby network security scan", "Authentication/cipher reported by the host operating-system WLAN scan.",
                    "Verify each listed BSSID belongs to an authorized access point and confirm WPA2-AES or WPA3 is enforced.",
                    evidence_id, confidence="High", category="Authentication",
                    asset=", ".join(str(ap.get("bssid") or ap.get("ssid") or "Identity unavailable") for ap in weak[:8]),
                    validation="Re-scan from the target site and compare the BSSID list with the approved AP inventory.",
                )
            return {"summary": f"{len(weak)} weak network(s) of {len(aps)} observed", "evidence_id": evidence_id}

        if test_id == "channel_congestion":
            info = self.wifi.wifi_info()
            aps = self._in_scope_aps(assessment, info.get("nearby_aps", []))
            congestion = channel_congestion(aps)
            evidence_id = self.store.add_evidence(aid, ex, "derived_analysis", self._wifi_source("scan (derived)"), congestion,
                                                  meta, label="Wi-Fi observations per channel")
            crowded = [c for c in congestion["channels"] if c["observations"] >= congestion["crowded_threshold"]]
            if crowded:
                worst = max(crowded, key=lambda c: c["observations"])
                self.store.add_finding(
                    aid, ex, "Radio channel crowding observed", "Informational",
                    f"{len(crowded)} channel(s) carry at least {congestion['crowded_threshold']} observed Wi-Fi networks; "
                    f"channel {worst['channel']} carries {worst['observations']}.",
                    "Crowded channels raise contention and reduce throughput; this is a planning observation, not a vulnerability.",
                    "Channel congestion observation", "Wi-Fi scan observation count per channel.",
                    "Review the channel plan and, where authorized, move APs to less occupied channels.",
                    evidence_id, confidence="Medium", category="Wireless Security",
                    validation="Repeat the scan during a busy period and compare the per-channel BSSID counts.",
                )
            return {"summary": f"{len(congestion['channels'])} channels observed", "evidence_id": evidence_id}

        if test_id == "rogue_bssid_check":
            info = self.wifi.wifi_info()
            aps = self._in_scope_aps(assessment, info.get("nearby_aps", []))
            duplicates = duplicate_ssids(aps)
            evidence_id = self.store.add_evidence(aid, ex, "derived_analysis", self._wifi_source("scan (derived)"),
                                                  {"duplicate_ssids": duplicates}, meta,
                                                  label=f"{len(duplicates)} SSID(s) with multiple BSSIDs")
            if duplicates:
                self.store.add_finding(
                    aid, ex, "Multiple BSSIDs advertise the same SSID", "Medium",
                    f"{len(duplicates)} observed SSID(s) are broadcast by more than one BSSID.",
                    "Multiple BSSIDs can be legitimate roaming infrastructure, but unexpected radios must be "
                    "validated to rule out rogue access points.",
                    "Duplicate-SSID BSSID check", "Same SSID observed on more than one BSSID.",
                    "Compare each BSSID with the authorized AP inventory and investigate any radio that is unexpected.",
                    evidence_id, confidence="Medium", category="Network Security",
                    asset=", ".join(d["ssid"] for d in duplicates[:8]),
                    validation="Confirm ownership of every BSSID and, where authorized, validate with an independent site survey.",
                )
            return {"summary": f"{len(duplicates)} duplicate SSID(s)", "evidence_id": evidence_id}

        if test_id == "device_discovery":
            observed = self.wifi.resolve_names(self.wifi.arp_devices())
            devices = [device for device in observed
                       if self._in_scope(device.get("ip"), assessment.get("network_scope"))]
            evidence_id = self.store.add_evidence(aid, ex, "device_inventory", "Local neighbor cache", devices, meta,
                                                  label=f"{len(devices)} neighbor entries")
            for device in devices:
                self.store.add_device(aid, device)
            self._device_findings(aid, ex, devices)
            return {"summary": f"{len(devices)} neighbor entries persisted", "evidence_id": evidence_id}

        if test_id == "nmap_scan":
            target = validate_target_scope(config.get("target"), assessment.get("network_scope"))
            result = self.nmap.scan(target, assessment.get("network_scope"), config.get("ports"))
            evidence_id = self.store.add_evidence(
                aid, ex, "nmap_scan", "Local Nmap", result, meta,
                label=f"Nmap scan of {target}", test_id=test_id)
            open_ports = result["open_ports"]
            if open_ports:
                descriptions = []
                for item in open_ports:
                    service = item.get("service") or "unknown service"
                    version = " ".join(x for x in (item.get("product"), item.get("version")) if x)
                    descriptions.append(f"{item['port']}/{item['protocol']} {service}" + (f" ({version})" if version else ""))
                self.store.add_finding(
                    aid, ex, "Open TCP services observed by Nmap", "Informational",
                    f"Nmap reported {len(open_ports)} open TCP service(s) on {target}: " + ", ".join(descriptions[:20]) + ".",
                    "Reachable services expand the host's network attack surface. An open port alone does not establish a vulnerability.",
                    "Nmap host and service assessment",
                    "Nmap TCP connect scan with light service fingerprinting; raw XML output was parsed and persisted.",
                    "Confirm each service is expected, patched, authenticated and restricted to intended source networks.",
                    evidence_id, confidence="High", category="Network Discovery", asset=target,
                    validation="Review the service on the host and repeat the scoped scan after remediation.")
            return {"summary": f"{len(open_ports)} open TCP port(s) reported on {target}",
                    "evidence_id": evidence_id, "host_count": result["host_count"],
                    "open_ports": open_ports, "nmap_version": result.get("version")}

        if test_id == "port_assessment":
            host = config.get("host") or gateway
            if not host:
                raise ValueError("No target host supplied and no default gateway is exposed.")
            if not self._in_scope(host, assessment.get("network_scope")):
                return self._scope_blocked(aid, ex, test, host, assessment)
            ports = _as_port_list(config.get("ports")) or list(MANAGEMENT_PORTS)
            results = self.wifi.tcp_ports(host, ports)
            payload = {"host": host, "ports_requested": ports, "results": results, "method": "tcp_connect"}
            evidence_id = self.store.add_evidence(aid, ex, "test_result", "TCP connect assessment", payload, meta,
                                                  label=f"{sum(1 for r in results if r.get('state') == 'open')} open port(s)")
            open_ports = [r for r in results if r.get("state") == "open"]
            if open_ports:
                self.store.add_finding(
                    aid, ex, "Open TCP services observed", "Medium",
                    f"The authorized TCP connect assessment observed {len(open_ports)} open port(s) on {host}.",
                    "Open services increase the reachable service surface and should match the documented asset configuration.",
                    "TCP connect port assessment", "TCP connect completed successfully on one or more declared ports.",
                    "Confirm each open service is required, patched, authenticated and documented.",
                    evidence_id, confidence="High", category="Network Security", asset=host,
                    validation="Re-run the assessment after remediation and confirm the ports are no longer reachable.",
                )
            return {"summary": f"{len(open_ports)} open port(s) on {host}", "evidence_id": evidence_id,
                    "open_ports": [r["port"] for r in open_ports]}

        if test_id == "gateway_exposure":
            if not self._in_scope(gateway, assessment.get("network_scope")):
                return self._scope_blocked(aid, ex, test, gateway, assessment)
            results = self.wifi.tcp_ports(gateway, list(MANAGEMENT_PORTS))
            payload = {"host": gateway, "ports_requested": list(MANAGEMENT_PORTS), "results": results,
                       "method": "tcp_connect"}
            evidence_id = self.store.add_evidence(aid, ex, "test_result", "TCP connect assessment", payload, meta,
                                                  label="Gateway management surface")
            open_ports = [r for r in results if r.get("state") == "open"]
            if open_ports:
                self.store.add_finding(
                    aid, ex, "Default gateway exposes management services", "Medium",
                    f"TCP connect observed {len(open_ports)} open port(s) on the default gateway {gateway}.",
                    "Gateway management services reachable from the client network widen the administrative attack surface.",
                    "Gateway TCP exposure", "TCP connect succeeded on a management port list.",
                    "Restrict gateway administration to a management VLAN and disable unused services.",
                    evidence_id, confidence="High", category="Network Security", asset=gateway,
                    validation="Repeat the gateway probe from an authorized client and confirm management access is restricted.",
                )
            return {"summary": f"{len(open_ports)} open management port(s)", "evidence_id": evidence_id}

        if test_id == "traceroute":
            host = config.get("host") or gateway
            if not host:
                raise ValueError("No target host supplied and no default gateway is exposed.")
            if not self._in_scope(host, assessment.get("network_scope")):
                return self._scope_blocked(aid, ex, test, host, assessment)
            data = self.wifi.traceroute(host)
            evidence_id = self.store.add_evidence(aid, ex, "test_result", "OS path trace", data, meta,
                                                  label=f"Path to {host}")
            return {"summary": f"Path trace to {host} recorded", "evidence_id": evidence_id}

        if test_id == "association_dataset_analysis":
            analysis = self.dataset.analyze()
            evidence_id = self.store.add_evidence(aid, ex, "research_dataset",
                                                  "Wi-Fi Association/Disassociation research corpus",
                                                  {"summary": analysis["summary"], "totals": analysis.get("totals"),
                                                   "temporal_summary": analysis.get("temporal_summary"),
                                                   "limitations": analysis["limitations"]}, meta,
                                                  data_class="research", label="Research corpus profile")
            self.store.add_finding(
                aid, ex, "Research corpus contains labeled attack activity", "Informational",
                f"The supplied research corpus contains {analysis['summary']['labels'].get('attack', 0):,} attack-labelled "
                f"and {analysis['summary']['labels'].get('normal', 0):,} normal-labelled association events across "
                f"{analysis['summary']['devices']} anonymised devices.",
                "The corpus is research evidence for detection engineering. It says nothing about this network and must "
                "not be reported as live activity.",
                "Research dataset association analysis", "Label counts read directly from the supplied corpus.",
                "Use the corpus to validate detection logic in a lab; never cite it as an observation of the assessed network.",
                evidence_id, confidence="High", category="Traffic Analysis",
                asset="Research corpus",
                validation="Re-derive the counts from data/wifi_association_disassociation.csv and compare.",
            )
            return {"summary": f"{analysis['summary']['records']:,} research records profiled", "evidence_id": evidence_id}

        if test_id == "disassociation_detection":
            threshold = int(config.get("threshold") or DEFAULT_DISASSOCIATION_THRESHOLD)
            detection = self.dataset.detection(threshold)
            evidence_id = self.store.add_evidence(aid, ex, "research_dataset",
                                                  "Wi-Fi Association/Disassociation research corpus", detection, meta,
                                                  data_class="research",
                                                  label=f"{detection['count']} windows matched")
            if detection.get("count"):
                self.store.add_finding(
                    aid, ex, "Disassociation bursts detected in research data", "Medium",
                    f"{detection['count']} corpus time windows matched the rule: {detection['rule']}.",
                    "Repeated disassociation bursts are a known indicator in the supplied corpus and justify monitoring "
                    "for management-frame abuse.",
                    "Disassociation burst detection", detection["rule"],
                    "Deploy management-frame monitoring and alert on disassociation bursts; confirm with an authorized "
                    "authorized packet capture before treating any live burst as an incident.",
                    evidence_id, confidence="Medium", category="Traffic Analysis",
                    asset="Research corpus",
                    validation="Re-run the detection rule with a different threshold and compare the matched windows.",
                )
            return {"summary": f"{detection['count']} window(s) matched", "evidence_id": evidence_id}

        raise ValueError(f"No local execution is implemented for test: {test_id}")

    # ---------------------------------------------------------------- helpers
    def _blocked(self, aid, test_id, execution_id, reason, include_evidence=True):
        if execution_id:
            self.store.update_execution(execution_id, "blocked", 100, "blocked", reason)
            self.store.event(aid, execution_id, "blocked", reason)
        else:
            execution_id = self.store.start_execution(aid, BY_ID.get(test_id, {}).get("name", test_id), test_id)
            self.store.update_execution(execution_id, "blocked", 100, "blocked", reason)
            self.store.event(aid, execution_id, "blocked", reason)
            if include_evidence:
                self.store.add_evidence(aid, execution_id, "blocked_test", "WiFiSentinel execution gate",
                                        {"test": test_id, "reason": reason, "result": "not_executed"},
                                        {"test": test_id, "data_class": "live"},
                                        label="Blocked: capability unavailable")
        return {"status": "blocked", "execution_id": execution_id, "test": test_id,
                "error": reason, "evidence_id": None}

    def _scope_blocked(self, aid, ex, test, host, assessment):
        reason = f"Target {host} is outside the declared network scope."
        self.store.add_evidence(aid, ex, "blocked_test", "WiFiSentinel scope gate",
                                {"test": test["id"], "requested_target": host,
                                 "declared_scope": assessment.get("network_scope"), "result": "not_executed"},
                                {"test": test["id"], "data_class": "live"}, label="Blocked: outside declared scope")
        self.store.update_execution(ex, "blocked", 100, "blocked", reason)
        self.store.event(aid, ex, "blocked", reason)
        return {"status": "blocked", "execution_id": ex, "test": test["id"], "error": reason}

    def _wireless_scope_blocked(self, aid, ex, test, info, assessment):
        observed = info.get("bssid") or info.get("ssid") or "current association"
        reason = f"Observed wireless target {observed} is outside the declared wireless scope."
        self.store.add_evidence(aid, ex, "blocked_test", "WiFiSentinel wireless scope gate",
                                {"test": test["id"], "declared_scope": assessment.get("wireless_scope"),
                                 "result": "not_executed"},
                                {"test": test["id"], "data_class": "live"},
                                label="Blocked: outside declared wireless scope")
        self.store.update_execution(ex, "blocked", 100, "blocked", reason)
        self.store.event(aid, ex, "blocked", reason)
        return {"status": "blocked", "execution_id": ex, "test": test["id"], "error": reason}

    def _profile_findings(self, aid, ex, info, evidence_id):
        if not info.get("connected"):
            return
        ssid = info.get("ssid") or "<unnamed network>"
        auth = (info.get("auth") or "").lower()
        cipher = (info.get("cipher") or "").lower()
        if not auth and not cipher:
            self.store.add_finding(
                aid, ex, "Wireless protection details are unavailable", "Informational",
                f"The operating system did not expose authentication or cipher details for the connected network '{ssid}'.",
                "The available telemetry cannot establish whether the association is protected.",
                "Connected network profile audit", "Authentication and cipher fields were unavailable in the OS observation.",
                "Verify the access-point security configuration through its authorized management interface.",
                evidence_id, confidence="Low", category="Wireless Security", asset=ssid,
                validation="Repeat the profile audit on an OS version and adapter that expose the negotiated security fields.",
            )
        elif "open" in auth or auth.strip() == "none" or cipher.strip() in ("none", "open"):
            self.store.add_finding(
                aid, ex, "Connected network is not protected", "High",
                f"The association to '{ssid}' reports authentication '{info.get('auth') or 'unknown'}' and cipher "
                f"'{info.get('cipher') or 'unknown'}'.",
                "Unauthenticated wireless access exposes traffic and permits unauthorized association.",
                "Connected network profile audit", "Live operating-system authentication/cipher observation.",
                "Enable WPA2-AES or WPA3 and disable open access for the network.",
                evidence_id, confidence="High", category="Wireless Security", asset=ssid,
                validation="Reconnect and confirm the adapter reports a protected authentication and cipher.",
            )
        elif "wep" in auth or "wep" in cipher:
            self.store.add_finding(
                aid, ex, "Connected network uses legacy WEP protection", "High",
                f"The association to '{ssid}' reports a legacy WEP profile.",
                "WEP is broken by design and provides no meaningful protection against an authorized attacker.",
                "Connected network profile audit", "Authentication string reports WEP.",
                "Migrate the network to WPA2-AES or WPA3 and remove WEP compatibility mode.",
                evidence_id, confidence="High", category="Wireless Security", asset=ssid,
                validation="Reconnect and confirm WEP is no longer offered by the access point.",
            )
        elif "tkip" in cipher:
            self.store.add_finding(
                aid, ex, "Connected network uses TKIP protection", "Medium",
                f"The association to '{ssid}' reports the TKIP cipher.",
                "TKIP is a legacy compatibility mode with known weaknesses and reduced throughput on modern hardware.",
                "Connected network profile audit", "Cipher string reports TKIP.",
                "Move the network to WPA2-AES (CCMP) or WPA3.",
                evidence_id, confidence="High", category="Wireless Security", asset=ssid,
                validation="Reconnect and confirm the reported cipher is CCMP.",
            )
        else:
            self.store.add_finding(
                aid, ex, "Connected network profile observed", "Informational",
                f"The association to '{ssid}' reports authentication '{info.get('auth')}' and cipher "
                f"'{info.get('cipher')}' on channel {info.get('channel')}.",
                "Baseline evidence of the current wireless protection in place.",
                "Connected network profile audit", "Live operating-system authentication/cipher observation.",
                "No action required; retain as the assessment baseline.",
                evidence_id, confidence="High", category="Wireless Security", asset=ssid,
                validation="Re-run this test after any configuration change to confirm the profile is unchanged.",
            )

    def _device_findings(self, aid, ex, devices):
        for device in devices:
            if device.get("is_self") or not device.get("ip"):
                continue
            if not device.get("hostname"):
                evidence_id = self.store.add_evidence(
                    aid, ex, "asset_observation", "Local neighbor cache", device,
                    {"scope": "local LAN", "test": "device_discovery"},
                    label=f"Neighbor {device['ip']}")
                self.store.add_finding(
                    aid, ex, "Unresolved network neighbor", "Low",
                    f"Neighbor {device['ip']} ({device.get('mac') or 'MAC unavailable'}) has no reverse-DNS hostname.",
                    "Unidentified assets reduce inventory confidence and slow incident scoping.",
                    "Local neighbor device discovery", "Reverse DNS returned no hostname for the observed neighbor.",
                    "Maintain an authoritative asset inventory and register unmanaged devices.",
                    evidence_id, confidence="Medium", category="Network Discovery", asset=device["ip"],
                    validation="Re-run device discovery after the device has been named and registered.",
                )

    # ---------------------------------------------------------------- posture
    def posture(self, aid):
        state = self.store.state(aid)
        if not state.get("assessment"):
            return {"error": "Assessment not found."}
        return calculate_posture(state)


# ---------------------------------------------------------------- pure helpers
def _is_open_or_legacy(ap):
    auth = (ap.get("auth") or "").lower()
    cipher = (ap.get("cipher") or "").lower()
    return ("open" in auth or auth.strip() == "none" or cipher.strip() in ("none", "open")
            or "wep" in auth or "wep" in cipher or "tkip" in cipher)


def channel_congestion(aps):
    """Count OS-returned network observations per channel, without inferring clients."""
    counts = {}
    for ap in aps:
        channel = ap.get("channel")
        if channel is None:
            continue
        counts[channel] = counts.get(channel, 0) + 1
    channels = [{"channel": ch, "observations": n, "band": _band_for(ch)}
                for ch, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return {"channels": channels, "crowded_threshold": 4, "source": "derived_from_live_scan",
            "note": "Counts OS-returned Wi-Fi observations per channel; no AP-client relationships are inferred."}


def duplicate_ssids(aps):
    grouped = {}
    for ap in aps:
        ssid = ap.get("ssid")
        if not ssid:
            continue
        grouped.setdefault(ssid, []).append(ap)
    duplicates = []
    for ssid, group in grouped.items():
        bssids = sorted({str(ap.get("bssid")) for ap in group if ap.get("bssid")})
        if len(bssids) > 1:
            duplicates.append({"ssid": ssid, "bssids": bssids,
                               "bands": sorted({str(ap.get("band")) for ap in group if ap.get("band")})})
    return sorted(duplicates, key=lambda d: d["ssid"])


def _band_for(channel):
    if channel is None:
        return None
    return 2.4 if channel <= 14 else None


def _scope_label(assessment, test):
    if test["scope_requirement"] == "network":
        return f"declared network scope: {assessment.get('network_scope') or 'none'}"
    if test["scope_requirement"] == "wireless":
        return f"declared wireless scope: {assessment.get('wireless_scope') or 'none'}"
    return "host observation (no scope required)"


def _status_detail(execution):
    if not execution:
        return "Not executed yet."
    stage = (execution.get("stage") or "unknown").replace("_", " ")
    return f"Last run: {execution.get('status')} at stage {stage}"


def _as_port_list(value):
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        ports = []
        for item in value:
            try:
                ports.append(int(item))
            except (TypeError, ValueError):
                continue
        return ports
    ports = []
    for item in str(value).replace(";", ",").split(","):
        item = item.strip()
        if item.isdigit():
            ports.append(int(item))
    return ports
