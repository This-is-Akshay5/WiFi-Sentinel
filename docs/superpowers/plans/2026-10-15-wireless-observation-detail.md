# Wireless Observation Detail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve real AP identities and native radio metadata end-to-end, surface available details honestly in the existing UI, and retain the already implemented defensive discovery/capture workflows.

**Architecture:** Keep OS-specific acquisition in the existing CoreWLAN and Windows WLAN adapters. Normalize only fields the native API actually returns, persist AP observations as-is, and render optional radio metadata in an expandable detail panel with source provenance. Do not introduce live frame transmission or infer unavailable device associations.

**Tech Stack:** Python, PyObjC/CoreWLAN, Windows WLAN API through `ctypes`, SQLite, PyWebView, vanilla JavaScript, pytest/unittest, Node tests.

**Spec:** `/Users/akshay/.codex/attachments/9c3104d3-0191-4f42-a5cf-68a3ac6fbbe0/Pasted text.txt`

## Global Constraints

- Modify the existing project in place and preserve `.env`, connector credentials, database, captures, reports, and history.
- Never substitute or fabricate SSIDs, BSSIDs, security, devices, or associations.
- Failed scans preserve cached observations; successful empty scans are live empty.
- Distinguish live, cached, historical, capture-derived, and simulated data.
- Never transmit deauthentication or other forged frames.
- Do not call tool availability an integrated assessment execution.

## Review Focus

- A CoreWLAN API selector can differ by PyObjC/macOS version; fallback only to supported general-scan selectors and expose actual errors.
- A zero-length Windows SSID field alone may not prove an explicitly hidden SSID; require a zero-length SSID information element to label it hidden.
- Malformed/truncated information elements must remain unknown without crashing or creating metadata.
- Optional radio metadata must survive JSON serialization and be rendered escaped in the UI.
- Existing capture upload, passive deauthentication, lab simulation, and cache-retention paths must remain unchanged and regression-tested.

---

### Task 1: General macOS scan and source-preserving radio metadata

**Files:**
- Modify: `core/platform_adapters.py`
- Test: `tests/test_core.py`

**Interfaces:**
- Produces optional AP fields: `ssid_data_hex`, `beacon_interval_ms`, `country_code`, `noise_dbm`, `channel_width`, `ibss`, `information_elements` (ID/name/length only), and `pmf_advertisement`.

- [x] Test the general `scanForNetworksWithSSID_includeHidden_error_` selector, `includeHidden=True`, and SSID/BSSID/radio metadata preservation; test fallback to older general-scan selectors and exact permission error classification.
- [x] Add bounded, defensive information-element parsing; report hidden SSID only when an empty SSID IE is actually present.
- [x] Run targeted CoreWLAN adapter tests.

### Task 2: Preserve Windows WLAN BSS metadata

**Files:**
- Modify: `core/windows_wlan.py`
- Test: `tests/test_core.py`

**Interfaces:**
- Adds optional fields `radio_type`, `beacon_interval_ms`, `supported_rates_mbps`, `capability_flags`, `information_elements`, and `pmf_advertisement` to each decoded BSS record.

- [x] Test real-shaped BSS fields and malformed/empty IEs; verify SSID/BSSID remain bound to each AP and hidden status requires explicit source evidence.
- [x] Decode bounded rates, PHY enum and capability bits; preserve unknown values as `None`.
- [x] Run targeted Windows parser tests on the current host using deterministic structures; do not claim Windows hardware verification.

### Task 3: Full Radio Details and source filtering

**Files:**
- Modify: `gui/js/app.js`, `gui/js/capability_state.js`, `gui/css/style.css`
- Test: `tests/ui_capability_state.test.js`

**Interfaces:**
- Existing AP detail renderer displays optional normalized fields and sanitized diagnostics without changing backend APIs.

- [x] Add expandable “Full Radio Details” and “Raw Source Data” panels that group absent values by source limitation and escape all source text.
- [x] Add filter/sort options for BSSID, band, signal, and security alongside existing name/channel options.
- [x] Test UI status, field rendering helpers, and filtering/sorting behavior without relabeling cached data.

### Task 4: Read-only Kismet visibility and honest cached-source status

**Files:** `kali_connector/server.py`, `connector.py`, `main.py`, `core/connector_discovery.py`, `gui/js/app.js`, `.env.example`, `docs/kali-connector.md`

- [x] Add loopback-only read-only Kismet status, datasource, paginated AP, and bounded client queries; refuse non-loopback endpoints.
- [x] Surface supported bands/channels, driver-reported monitor capability, source permissions, and explicit unknown last-packet time without fabricating packet timestamps.
- [x] Label `nmcli --rescan no` results as cached and keep them from being recorded as a successful live Mac scan.
- [x] Add regression tests for the Kismet API envelope, client source attribution, loopback restriction, adapter capability details, and cached scan state.
- [x] Document optional Kali Kismet configuration and exact limits.

### Task 4: End-to-end regression and manual verification

**Files:**
- Modify: `docs/phase-3-manual-verification.md`
- Test: existing discovery, device, capture, and deauthentication suites.

- [x] Run targeted adapter/UI tests and the existing Python/Node regression suites.
- [x] Verify app startup; the Capture Review upload path remains covered by its direct bridge/storage regression tests.
- [x] Record exact Mac, Windows, and Kali hardware limitations; distinguish mocked tests from physical radio verification.
