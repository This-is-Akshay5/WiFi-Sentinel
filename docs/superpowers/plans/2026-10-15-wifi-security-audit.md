# WiFiSentinel Wi-Fi Security Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a dedicated, persisted Wi-Fi audit with evidence-based checks, transparent risk scoring, remediation, and PDF export.

**Architecture:** A pure evaluator in `core/wifi_audit.py` consumes current OS observations. `Store` adds additive v11 audit and remediation-action tables with payload integrity digest; `Bridge` performs authorized fresh collection, remediation comparison, and export; the existing vanilla-JS navigation and ReportLab renderer surface and export persisted audits.

**Tech Stack:** Python 3.12, SQLite, PyWebView, vanilla JavaScript, ReportLab, pytest/unittest, Node tests.

**Spec:** `docs/superpowers/specs/2026-10-15-wifi-security-audit-design.md`

## Global Constraints

- Preserve `.env`, existing database rows, captures, reports, and assessments.
- Never fabricate identifiers, findings, evidence, or pass states.
- Require explicit authorization before a fresh audit and gateway reachability probe.
- Retrieve a saved credential only from the active profile after an explicit UI action and OS permission; never persist, log, export, or transmit it.
- PMF applies only to an exact connected-BSSID observation.
- Unsupported router/DNS/credential checks remain unavailable or manual.
- Never transmit management frames or change router configuration.

## Review Focus

- Missing connection identity or stale/failed OS reads must not produce a successful audit: test bridge errors and explicit state.
- An AP with a matching SSID but different BSSID must not provide PMF evidence: test exact matching.
- Unknown metadata and unavailable checks must not count as passes or justify a low score: test evaluator coverage.
- Repeated/correlated findings must not inflate score, while resolved findings lower it: test deterministic score composition.
- Existing or modified audit JSON must be integrity checked; PDFs must reflect persisted state: test hash mismatch and report consistency.
- Concurrent UI or bridge calls must not launch duplicate OS scans: test disabled submission and backend single-flight rejection.

---

### Task 1: Evidence evaluator and scoring

**Files:** Create `core/wifi_audit.py`; test `tests/test_wifi_audit.py`.

**Interfaces:** `evaluate(context: dict, authorization_confirmed: bool, gateway_probe: dict | None) -> dict`; `score_findings(findings: list[dict], coverage: dict) -> dict`.

- [x] Test known and unknown security modes, exact-BSSID PMF evidence, authorization requirement, score boundaries/formula, correlated duplicates, resolved findings, insufficient evidence, and deterministic output.
- [x] Run the new tests and confirm expected failures.
- [x] Implement the evaluator and documented model `wifi-audit-v1`.
- [x] Run the evaluator tests.

### Task 2: Additive persistence and integrity

**Files:** Modify `core/store.py`; extend `tests/test_wifi_audit.py`.

**Interfaces:** `Store.save_wifi_audit(payload) -> dict`, `Store.wifi_audit(audit_id) -> dict | None`, `Store.wifi_audits(limit=50) -> list[dict]`, `Store.set_wifi_audit_remediation(audit_id, finding_id, applied) -> dict`.

- [x] Test schema upgrade from v10 with existing assessments intact, audit save/read/history, action-state persistence, and digest mismatch detection.
- [x] Confirm tests fail before implementation.
- [x] Add schema v11 tables and canonical JSON SHA-256 without destructive migration.
- [x] Run store/audit tests using temporary SQLite databases.

### Task 3: Authorized bridge collection and PDF export

**Files:** Modify `main.py`, `core/reporting.py`; extend `tests/test_wifi_audit.py`.

**Interfaces:** `Bridge.run_wifi_audit(authorization_confirmed)`, `Bridge.wifi_audit_history()`, `Bridge.set_wifi_remediation_applied(audit_id,finding_id,applied)`, `Bridge.export_wifi_audit_pdf(audit_id)`, `write_wifi_audit_pdf(path, audit)`.

- [x] Test refusal without authorization, concurrent-call rejection, current OS + network context collection, exact connected AP selection, bounded gateway probe, persisted audit ID export, and generated PDF structure.
- [x] Implement bridge orchestration with sanitized errors and no secret logging.
- [x] Render only stored audit payload in PDF; include uncertainty and manual checks.
- [x] Run bridge/PDF tests.

### Task 4: Dedicated audit UI

**Files:** Modify `gui/js/app.js`, `gui/css/style.css`; test `tests/ui_wifi_audit.test.js` and `tests/ui_capability_state.test.js` if shared helpers apply.

- [x] Test escaped/missing context, authorization state, insufficient evidence, remediation status, audit history, and PDF action bindings with Node tests.
- [x] Add navigation, accessible authorization control, loading/error/empty states, result/history rendering, and PDF export action.
- [x] Run JavaScript tests and syntax checks.

### Task 5: Full verification and manual guide

**Files:** Update `README.md`, `docs/phase-3-manual-verification.md`.

- [x] Run full Python and Node suites, compileall, and JavaScript syntax checks.
- [x] Initialize the backend/bridge and inspect the existing database after additive migration; GUI and user-authorized audit execution remain manual checks.
- [x] Record current macOS permissions/hardware limitations and exact Windows/Kali/manual verification steps without claiming they ran.

### Task 6: Explicit saved-credential access safeguards

**Files:** Create `core/credential_access.py`; update `main.py`, `gui/js/app.js`, `gui/js/wifi_audit.js`, tests, README, and manual verification.

- [x] Test connected-profile-only lookups, denied access, shell-free bounded command execution, and unsupported platforms with mocked OS responses.
- [x] Implement explicit user-triggered macOS Keychain and elevated Windows current-profile lookup, masked UI, reveal-gated copy, and clearing on navigation/window hiding.
- [x] Verify credentials are excluded from SQLite audit payloads, logs, PDFs, AI, and Kali paths.
- [x] Document that OS credential access is optional and requires real platform permission validation.

