# WiFiSentinel Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Stabilize wireless observations, make device provenance inspectable, enable independent offline capture review, and add scoped passive/simulated deauthentication-defense assessments.

**Architecture:** Retain the current Python engine, OS adapters, PyWebView bridge, browser UI, SQLite store, and report generators. Add an explicit discovery attempt/result state, bounded source-specific history, an unscoped locally authorized capture workspace, passive Dot11 evidence parsing, and a persisted defense-assessment run model. No new live-radio transmit or capture interface is introduced.

**Tech Stack:** Python 3.10+, SQLite, Scapy (already required), PyWebView, vanilla JavaScript/CSS, Python `unittest`, Node test runner.

**Spec:** `docs/superpowers/specs/2026-10-14-phase-3-wireless-evidence-design.md`

## Global Constraints

- Preserve the existing database, scan history, evidence, captures, reports, `.env`, connector token, OpenAI configuration, and existing UI design.
- Keep macOS CoreWLAN/airport, Windows WLAN/netsh, and Kali connector observations separately attributed.
- An unsuccessful scan retains the last successful data as cached; a successful empty scan means zero current observations and keeps prior history.
- Never infer hidden SSID, BSSID, vendor, client association, device reachability, PMF enforcement, or live deauthentication from absent or unrelated evidence.
- Offline capture is local-only, bounded, read-only, hash-verified, and never extracts application credentials.
- Deauthentication features are passive or synthetic simulation only; live transmission is `Not supported`.
- Use tests first for every production behavior and verify the targeted regression fails before implementing it.

## Files and responsibilities

- `core/wifi_engine.py`: single-flight scan generation, attempt status, last-success cache semantics, source snapshot history hooks, and device observation provenance.
- `core/platform_adapters.py`, `core/connector_discovery.py`, `kali_connector/server.py`: field/state accuracy, macOS permission details, and separate source semantics.
- `core/store.py`: additive schema migration, source-specific observation history, capture workspace metadata, and deauthentication run persistence.
- `core/capture_analysis.py`, `core/capture_storage.py`: passive management-frame/PMF evidence and optional wireless scope filtering with existing safety limits.
- `core/assessment_engine.py`, `core/catalog.py`, `main.py`: authorization/scope validation, transactional evidence, dedicated bridge methods, and explicit unsupported live operation response.
- `core/reporting.py`: provenance, passive findings, capture details, simulation labels, and limitations in exports.
- `gui/js/capability_state.js`, `gui/js/app.js`, `gui/index.html`, `gui/css/style.css`: stable scan rendering, source-separated device inspector, independent capture upload flow, and dedicated defensive assessment/simulator.
- Tests: `tests/test_core.py`, new `tests/test_discovery_state.py`, `tests/test_device_observations.py`, `tests/test_deauth_assessment.py`, capture/persistence/report tests, `tests/ui_capability_state.test.js`, and new `tests/ui_capture_flow.test.js` and `tests/ui_deauth_flow.test.js`.

## Review Focus

- A permission error encoded as a normal result must not be mistaken for a successful empty scan: pin with a collector sequence regression.
- A slow older scan must not overwrite a newer result: pin with a generation-order regression.
- Two sources reporting one IP must remain two evidence records: pin with device-source identity tests.
- A capture without an AP scope must remain usable but explicit authorization is still required: pin with Bridge/storage integration tests.
- PMF capability flags, reason codes, and protected bits must not be conflated with negotiated/enforced PMF: pin with generated Scapy frame tests and uncertainty assertions.

---

### Task 1: Stable discovery state and network row provenance

**Files:**
- Modify: `core/wifi_engine.py`
- Modify: `core/platform_adapters.py`
- Modify: `core/connector_discovery.py`
- Modify: `main.py`
- Modify: `gui/js/capability_state.js`, `gui/js/app.js`
- Test: `tests/test_discovery_state.py`, `tests/test_core.py`, `tests/ui_capability_state.test.js`

**Interfaces:**
- `RealWiFiEngine.poll_refresh() -> dict` publishes a monotonic completed attempt plus a last-success snapshot.
- Snapshot adds `scan_attempt = {id, status, started_at, finished_at, successful_at, source, error}` and `wifi.freshness` (`live`, `cached`, `unavailable`); each AP keeps its own `observed_at` and `source`.
- Add an injectable `RealWiFiEngine` collector callable for deterministic ordering tests without invoking real radios.

- [x] **Step 1: Write failing backend regressions** for successful 3-AP scan → permission error → successful refresh → repeated poll; successful empty; and stale-generation completion. Expect prior rows to remain cached on error and newer generation to win.
- [x] **Step 2: Run only those tests and verify the failure is the cache replacement/order behavior.** Run `./.venv-macos-arm64/bin/python -m unittest discover -s tests -p 'test_discovery_state.py' -v`.
- [x] **Step 3: Implement separate attempt and last-success state** in `core/wifi_engine.py`. Treat `permission_required`, `scan_unavailable`, `wlan_unavailable`, and `error` as failures; only a successful empty result clears current live rows. Preserve timestamps on cached rows. Assign monotonic generation IDs and publish only the current generation.
- [x] **Step 4: Add source-level adapter regression cases** for CoreWLAN denied/missing fields, a genuine returned SSID/BSSID, and unchanged source/time through `Bridge.live_snapshot()`; keep raw identifiers out of test logs.
- [x] **Step 5: Fix permission and fallback status mapping** in adapters and connector fallback so permission instructions survive and a failed Kali fallback does not mutate last-success state.
- [x] **Step 6: Write failing UI state tests** for loading versus empty, cached label/time, successful empty, selection stability, multiple evidence-derived targets, and live-mode exclusion.
- [x] **Step 7: Update `capability_state.js` and `app.js`** to use the snapshot attempt state, preserve cached row labels/timestamps, suppress zero count while first scan is running, and prevent overlapping frontend requests/timer retries.
- [x] **Step 8: Run targeted Python and Node tests** and confirm all new assertions pass.

### Task 2: Persisted source-specific observation history and device inspector

**Files:**
- Modify: `core/store.py`, `core/wifi_engine.py`, `main.py`
- Modify: `gui/js/app.js`, `gui/css/style.css`
- Test: `tests/test_device_observations.py`, `tests/test_core.py`, `tests/test_reporting.py`

**Interfaces:**
- Add schema version 7 table `observation_snapshots(id, kind, source, method, interface, status, started_at, observed_at, first_seen, last_seen, fingerprint, data_class, results_json, limitations_json)` with a unique dedup key for equivalent consecutive snapshots of the same kind/source/interface/data class.
- `Store.save_observation_snapshot(snapshot) -> dict` and `Store.observation_history(kind=None, limit=100) -> list[dict]` return source-preserving records.
- Existing `device_discovery_runs` remains the record of authorized ICMP jobs; no source is merged into it.

- [x] **Step 1: Add failing migration/store tests** for existing v6 DB preservation, source-separated AP/neighbor snapshots, equivalent-snapshot dedup, changed observations, and first/last-seen timestamps.
- [x] **Step 2: Verify RED** with `./.venv-macos-arm64/bin/python -m unittest discover -s tests -p 'test_device_observations.py' -v`.
- [x] **Step 3: Add the additive schema migration and store methods** in `core/store.py`; do not rewrite existing rows or tables.
- [x] **Step 4: Persist completed successful scans and neighbor snapshots** through the Bridge using source labels, method, interface, timestamps, and limitations. Store fingerprints deduplicate equivalent results and update last-seen.
- [x] **Step 5: Add device-view regression tests** proving one neighbor and one ICMP record for the same IP remain distinct and a stale neighbor state is not promoted to online.
- [x] **Step 6: Replace IP merging in `devices()` UI** with separate source sections, selectable source rows, source-specific history, and a detail inspector. Cross-reference matching identifiers without combining their source/status/timestamps. Render unknown vendor/category honestly.
- [x] **Step 7: Run device/store tests and existing Python/Node UI tests.**

### Task 3: Independent Capture Review upload and persisted result reopening

**Files:**
- Modify: `main.py`, `core/store.py`, `core/capture_analysis.py`, `core/capture_storage.py`
- Modify: `gui/js/app.js`, `gui/js/capability_state.js`
- Test: `tests/test_capture_storage.py`, `tests/test_capture_analysis.py`, `tests/ui_capability_state.test.js`

**Interfaces:**
- `Bridge.select_capture()` opens the native picker without an AP/assessment argument and returns only selection token, basename, bytes, and allowed format.
- `Bridge.analyze_capture_selection(selection_id, authorized, wireless_scope=None)` requires explicit `authorized is True`; it creates/reuses an offline-capture assessment with optional SSID/BSSID scope and returns only after evidence persistence succeeds.
- `Bridge.capture_analysis(capture_id)` returns persisted analysis for a history row in its authorized workspace.
- Empty scope means retain supported capture metadata; non-empty scope filters wireless identity details. Existing capture limits and hash-based duplicate storage remain unchanged.

- [x] **Step 1: Write failing Bridge-flow tests** proving native-picker selection works without an AP, authorization is required before analysis, results persist, duplicate imports are idempotent, and persisted results reopen.
- [x] **Step 2: Verify RED** with the new Bridge test in `tests/test_capture_storage.py`; browser state regressions live in `tests/ui_capability_state.test.js`.
- [x] **Step 3: Add optional-scope storage semantics and standalone workspace bridge methods** in `main.py`/`core/capture_analysis.py`; validate authorization, extension, bytes, and status exactly as before.
- [x] **Step 4: Add history detail lookup** in `core/store.py`/`main.py` without returning raw file paths or packet payloads.
- [x] **Step 5: Make Capture Review independent of `state.aid`** in `app.js`, show Upload always, and wire picker → authorization/scope → progress → persisted result → history reopen. Keep current theme and layout. UI behavior was syntax-checked; native picker integration was Bridge-tested with a mocked dialog, not visually exercised.
- [x] **Step 6: Run capture, UI-flow, persistence, export, and existing regression tests.**

### Task 4: Passive management-frame and PMF evidence parser

**Files:**
- Modify: `core/capture_analysis.py`
- Test: `tests/test_capture_analysis.py`

**Interfaces:**
- Add `management_frame_observations` with separate `deauthentication`, `disassociation`, `protected_management_frames`, and `rsn_pmf_advertisements` aggregates plus bounded per-observation records.
- Each record includes only parsed timestamp, frame subtype, unambiguous transmitter/receiver/BSSID roles, reason code if parsed, and source capture/interface context.
- PMF result is `advertised_capable`, `advertised_required`, and `negotiated_or_enforced: "unknown"`; no inference from a protected bit alone.

- [x] **Step 1: Write failing generated-frame tests** for deauth/disassociation reason codes, transmitter/receiver mapping, timestamps/repetition, RSN MFPC/MFPR flags, protected-bit-only uncertainty, Ethernet exclusion, and packet/identifier limits.
- [x] **Step 2: Verify RED** with `./.venv-macos-arm64/bin/python -m unittest discover -s tests -p 'test_capture_analysis.py' -v`.
- [x] **Step 3: Implement bounded Scapy parsing** without saving packet payloads; handle malformed/unknown management frames conservatively and keep all existing size/time/frame bounds.
- [x] **Step 4: Run parser, storage, and reporting capture regressions.**

### Task 5: Scoped passive/simulated deauthentication assessment

**Files:**
- Modify: `core/store.py`, `core/catalog.py`, `core/assessment_engine.py`, `main.py`
- Modify: `gui/index.html`, `gui/js/app.js`, `gui/css/style.css`
- Test: `tests/test_deauth_assessment.py`, `tests/test_network_workflow.py`, `tests/ui_deauth_flow.test.js`

**Interfaces:**
- Add schema version 8 table `wireless_defense_runs(id, assessment_id, mode, status, scope, ap_evidence_ref, targets_json, authorization_evidence_ref, started_at, completed_at, result_json, evidence_id)`.
- `Bridge.run_deauth_assessment(mode, capture_id, ap_ref, target_refs, authorized)` accepts only `passive` or `simulation`; passive AP and target references must exist in selected, scoped capture evidence, while simulation targets must have been generated by the current session.
- Any live mode returns `Not supported` before connector or packet-transmitter access.
- `Store.save_wireless_defense_run(...)` persists a completed run and linked integrity-hashed evidence transactionally.

- [x] **Step 1: Write failing validation/persistence tests** for missing authorization, scope mismatch, unknown AP, arbitrary target identity, target evidence mismatch, multi-target valid selection, and rollback.
- [x] **Step 2: Write failing safety tests** proving unsupported live mode returns `Not supported`, makes no connector/packet-transmitter call, and creates no success evidence.
- [x] **Step 3: Write failing parser-to-assessment tests** for selected capture evidence, PMF unknown/advertised distinctions, evidence references, and cautious finding rationale.
- [x] **Step 4: Verify RED** with `./.venv-macos-arm64/bin/python -m unittest discover -s tests -p 'test_deauth_assessment.py' -v`.
- [x] **Step 5: Implement schema v8, exact scope/evidence validation, transactional storage, and only passive/simulation execution** in `store.py` and `main.py`. Keep active transmission unavailable.
- [x] **Step 6: Add dedicated UI route** with AP source, multi-select targets, authorization/scope summary, passive analysis, synthetic lab simulator, and explicit live `Not supported` state. Clearly label all simulated records and keep them out of live observations/history.
- [x] **Step 7: Add UI-state regressions** for evidence-derived multi-target selection and live-mode exclusion, plus Bridge tests for authorization/scope validation, simulation labeling, persistence, and unsupported transmission.
- [x] **Step 8: Run backend safety, workflow, and UI state tests.**

### Task 6: Evidence-linked findings and export integration

**Files:**
- Modify: `core/reporting.py`, `core/store.py`, `main.py`
- Modify: `gui/js/app.js`
- Test: `tests/test_reporting.py`, `tests/test_capture_persistence.py`, `tests/test_deauth_assessment.py`

- [x] **Step 1: Add failing export tests** for snapshot provenance, cached freshness, capture details/reopened analysis, passive defense runs, simulation labels, methodology, limitations, evidence IDs, CSV formula injection, and multipage PDF history.
- [x] **Step 2: Verify RED** with `./.venv-macos-arm64/bin/python -m unittest tests.test_reporting tests.test_deauth_assessment -v`.
- [x] **Step 3: Extend JSON/CSV/PDF using persisted records only**; no placeholder findings or raw packet bytes; simulation always carries `data_class=simulation` and `mode=simulation`.
- [x] **Step 4: Run reporting and evidence transaction suites.**

### Task 7: Documentation, cross-platform verification, and manual checks

**Files:**
- Modify: `README.md`, `docs/kali-connector.md`
- Test: all existing Python and JavaScript suites.

- [x] **Step 1: Document** capture upload without a network scan, macOS Location Services remediation, source-specific device coverage, deauthentication passive/simulation-only behavior, and Windows/Kali limitations.
- [x] **Step 2: Run full Python suite:** `./.venv-macos-arm64/bin/python -m unittest discover -s tests -p 'test_*.py' -v`.
- [x] **Step 3: Run all UI tests and syntax checks:** `node --test tests/*.test.js`; run `node --check` on every changed frontend module.
- [x] **Step 4: Run Python compilation:** `./.venv-macos-arm64/bin/python -m compileall -q core kali_connector main.py tests`.
- [ ] **Step 5: Complete a real macOS scan and visible UI/file-picker verification after OS permission is granted.** The current sanitized CoreWLAN result is `permission_required`; the native picker flow was verified with a mocked dialog. See `docs/phase-3-manual-verification.md` for exact steps.
- [x] **Step 6: Do not claim real Windows/Kali/hardware verification unless actually performed.** This workspace has no `.git` directory, so do not create commits or modify repository metadata.
