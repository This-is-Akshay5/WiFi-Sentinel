# WiFiSentinel Platform Reconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the current WiFiSentinel desktop app into a scoped, evidence-grounded wireless, LAN, traffic, and web-application security platform while preserving current user data and working features.

**Architecture:** Keep the existing PyWebView bridge, Python `core/` modules, SQLite `Store`, vanilla JS UI, and PyInstaller packaging. Add focused domain modules and additive, versioned migrations; actively gate every scan through one backend scope validator.

**Tech Stack:** Python 3.12, SQLite, PyWebView, vanilla JavaScript/CSS, existing Nmap/TShark/tcpdump/Scapy/ReportLab/OpenAI integrations.

**Spec:** `docs/superpowers/specs/2026-10-31-platform-reconstruction-design.md`

## Global Constraints

- Preserve source and Application Support databases, history, captures, reports, `.env`.
- Never fabricate an observation, finding, receiver, score, capability, or delivery acknowledgement.
- Never execute untrusted source code; web checks are bounded, authorized, and non-destructive.
- Never collect real passwords in source scans, AI requests, phishing simulation, reports, or message flows.
- Never transmit forged 802.11 frames or claim monitor mode without verified compatible hardware.
- Never actively scan a target without recorded authorization, permitted activity, valid time window, in-scope target, and exclusion checks.
- Migrations are additive and must preserve old rows.
- Keep existing PyWebView/SQLite architecture and macOS launch/package path.
- A tool being installed is not proof it is integrated or usable.

## Review Focus

- Expired or excluded targets: authorization evaluator must block before spawning a process; test expired windows and exact/CIDR exclusions.
- IPv6, DNS rebinding, redirect-to-private/metadata and cross-origin URLs: web scanner must reject out-of-scope destinations on every redirect; test each case.
- Symlinks and secret-bearing source files: white-box analyzer must not escape the chosen root and must redact values; test traversal and common secret formats.
- Randomized MACs and conflicting observations: inventory must preserve source records and avoid false permanent identity merges; test same IP/different MAC and same MAC/different source.
- Missing radios/tools and permission errors: capability states must remain distinct and never show simulated/live success; test unavailable and denied adapters.

---

### Milestone 0 — Audit and baseline (complete)

- [x] Inventory project-owned source, UI, tests, dependencies, build configuration, and current app-data location.
- [x] Historical pre-reconstruction baseline: 164 passed, 6 subtests passed; one obsolete connector localhost bind was sandbox-blocked and subsequently removed with the retired connector-only tests.
- [x] Current baseline before Device Intelligence work: Python 163 passed, 14 subtests passed; JavaScript 21 passed; Python compile and JS syntax checks passed.
- [x] Record that no Git metadata is present and preserve both existing DB locations.

### Milestone 1 — Engagement scope and authorization

**Files:** Create `core/engagement.py`, `tests/test_engagement.py`; modify `core/store.py`, `core/assessment_engine.py`, `main.py`, `gui/js/app.js`, `gui/css/style.css`.

- [x] Add additive schema v12 engagement manifests and append-only scope history; test a v11 upgrade with retained assessment/evidence rows.
- [x] Gate active network tests on recorded authorization, timezone-aware engagement dates, exact permitted activity IDs, optional test intervals, and host/device/IP-range exclusions; test blocked/reasoned cases. (Full site/SSID/BSSID policy validation remains open.)
- [x] Connect the scope editor and active network execution entry points to this gate while retaining legacy read access; test bridge-level blocked executions.
- [x] Add native authorization-document selection, bounded local copy, SHA-256/provenance, audited removal, report metadata, and path/size rejection. Additive schema v13 preserves prior assessment/evidence rows; tests use temporary directories and databases. Native dialog launch still requires manual UI verification.

### Milestone 2 — LAN Inventory and device profiles (partial)

**Files:** Create `core/device_intelligence.py`, `tests/test_device_intelligence.py`, `tests/ui_device_intelligence.test.js`; modify `core/wifi_engine.py`, `core/store.py`, `main.py`, `gui/js/app.js`, `gui/css/style.css`, `gui/index.html`.

- [x] Preserve OS neighbor-cache and bounded authorized ICMP observations as separate source-specific records with timestamps; no ARP entry is equated with a live Wi-Fi client.
- [x] Add a Device Intelligence view over persisted neighbor-cache, ICMP, and Nmap evidence. Profiles remain separate observations, expose field provenance/status, and label Nmap service fingerprints as estimates; tests cover same-IP/different-MAC source records and unavailable fields.
- [ ] Add router/DHCP, mDNS/Bonjour, service discovery, more detailed network configuration and confidence-backed fingerprinting where supported; test randomized MAC, changing IP, conflict, and stale observation cases.
- [x] Add LAN Inventory and Device Intelligence routes; do not restore the removed Devices page.

### Milestone 3 — Wireless inventory and capability reporting (partial)

**Files:** Create `core/capabilities.py`, `tests/test_capabilities.py`; modify `core/platform_adapters.py`, `core/wifi_engine.py`, `main.py`, `gui/js/app.js`, `README.md`.

- [ ] Report OS, interface, permissions, tools, permissions, and hardware separately as tested/partial/unavailable/permission/configuration-required.
- [x] Add approved AP inventory and scoped evidence-based comparison; unlisted observations are review items, never confirmed unauthorized APs.
- [ ] Verify Mac adapter and permission behavior; Windows and monitor-mode claims remain fixtures/manual unless real host hardware is available.

### Milestone 4 — Traffic intelligence and segmentation (partial)

**Files:** Create `core/traffic_analysis.py`, `core/segmentation.py`, focused tests; modify `main.py`, `core/store.py`, `gui/js/app.js`, `gui/css/style.css`.

- [x] Extend bounded offline PCAP analysis with protocol/endpoints and scoped unencrypted DNS question metadata; do not decode TLS, DoH/DoT, answers, or payloads. No live TShark/tcpdump capture is implemented.
- [x] Add bounded TCP reachability from the current host, gated by assessment authorization, active dates, permitted activity, network scope, and exclusions. UI segment labels remain operator supplied and are not treated as verified topology.
- [x] Persist evidence/provenance; test scope, policy, target/port limits, open/closed/timeout/error classification, and evidence.
- [ ] Add live capture, TCP/UDP traffic volumes and flow summaries, remote source-segment testing, ICMP matrix, and topology verification where supported.

### Milestone 5 — White-box and black-box web analyzer

**Files:** Create `core/web_analyzer.py`, `core/source_analysis.py`, tests; modify `core/store.py`, `main.py`, `gui/js/app.js`, `gui/css/style.css`.

- [x] Add a single-page same-origin, read-only GET snapshot with URL validation, pinned DNS, redirect checks, timeout/response-size limits, and evidence persistence.
- [x] Expand to a bounded 20-page same-origin GET crawl and observed route/status/content-type inventory. Redirect and scope tests pass, and a real local test server verified the request path. API-path labels remain heuristics.
- [x] Add a bounded selected-file static source review through the desktop bridge, without executing code and without returning/storing source excerpts or secret values.
- [x] Add a bounded native repository-root review with symlink, generated/dependency, `.env`, and common key/credential exclusions; persist redacted indicators and local manifest dependency inventory. No advisory lookup or code execution.
- [ ] Add deterministic security rules with stable IDs and evidence references; no unverified advisory claims or arbitrary findings.
- [ ] Add UI states and bridge integration; test localhost, allowed host, redirect escape, SSRF targets, malformed URL, symlink escape, secret redaction, and persistence.

### Milestone 6 — Attack graph and AI explanation

**Files:** Create `core/attack_paths.py`, tests; modify `core/ai_engine.py`, `main.py`, `core/store.py`, `gui/js/app.js`.

- [x] Build deterministic finding/evidence nodes and support edges only from explicit persisted evidence references; same-asset overlap is emitted only as a theoretical correlation candidate. Tests prove unlinked findings do not connect.
- [ ] Generate ordered exploit paths and label verified/high-confidence/theoretical transitions with evidence IDs and preconditions. Current storage has no verified transition model; the UI shows no ordered paths.
- [ ] Make optional AI explanation opt-in, disclosed, redacted, and constrained to supplied evidence; test invalid/unreferenced AI statements are not converted to findings/edges.

### Milestone 7 — Controlled phishing-awareness simulator

**Files:** Create `core/training_simulator.py`, tests; modify `main.py`, `core/store.py`, `gui/index.html`, `gui/js/app.js`, `gui/css/style.css`.

- [x] Provide an original fixed local training page hosted on loopback with expiring random session token and explicit shutdown; no third-party lookalike or external target.
- [x] Record visit/click and synthetic yes/no outcomes only; strict allowlist rejects free-form fields and no participant address or credential value is stored.
- [x] Add 90-day inactive history deletion, interrupted-session recovery, and tests for token expiry, allowlisted input, loopback host binding, persistence, and listener shutdown. Multiple concurrent sessions are intentionally unsupported.

### Milestone 8 — LAN messaging

**Files:** Create `core/lan_messaging.py`, tests; modify `main.py`, `core/store.py`, UI files.

- [x] Implement explicit in-memory receiver enrollment, receiver-bound scoped token, expiring HMAC-signed announcement, and signed/validated acknowledgement for the supplied compatible receiver.
- [x] Report unsupported devices distinctly; no broadcast packets, captive portals, or OS notification bypass. Acknowledgement means receiver acceptance only, not popup or human-read confirmation.
- [x] Test authorization, token expiry/replay, receiver identity, delivery/acknowledgement status, TLS certificate pinning, and a real loopback HTTP receiver integration. Physical cross-host TLS remains unverified.

### Milestone 9 — Unified findings, reporting and retesting

**Files:** Modify `core/store.py`, `core/reporting.py`, `main.py`, tests, UI.

- [ ] Normalize all finding sources into one cross-workflow lifecycle without rewriting historic data. Existing Wi-Fi audit and general assessment findings remain in distinct persisted workflows.
- [x] Retest selected supported catalog findings only when the original persisted scope matches the current assessment scope; reuse the original target and only prior open Nmap ports from evidence; store fixed/partial/unresolved/unable-to-verify outcomes only with rule-specific comparison evidence. Non-catalog and legacy findings without scope metadata remain unable to verify.
- [x] Export persisted assessment records to JSON/CSV/PDF and connected Wi-Fi audit records to PDF; retest history is included. PDF pagination and CSV formula neutralization are implemented. A unified signed attestation and full cross-workflow normalization/retest remain open.

### Milestone 10 — Full UI refinement and integration

**Files:** Modify `gui/index.html`, `gui/css/style.css`, `gui/js/app.js`, tests, docs, macOS spec/build files only as required.

- [ ] Apply existing token system consistently, grouped navigation, accessible interactions, and meaningful loading/empty/error/permission states.
- [x] Re-run the final Python/Node suites and compile checks after LAN Messaging and selected-finding retests; build the macOS ARM64 bundle to a temporary output path.
- [x] Launch the final packaged app and verify all 21 primary navigation routes render without a page error, including Repository Review, Web Crawl, Evidence Correlation, AP Inventory, Capture Review, Findings/Retest, Awareness Training, and LAN Messaging. Windows desktop/hardware behavior remains unverified.
- [x] Update manual verification, known limitations, migration notes, and acceptance report. The roadmap and standalone capability matrix remain incomplete.

## Checkpoints

- After Milestone 1: test scope blocks before any active command and preserve v11 records.
- After Milestones 2–3: live and historical device observations remain clearly distinct; run Mac capability check.
- After Milestones 4–6: all network/web findings have stable evidence references and run through bounded public interfaces.
- After Milestones 7–9: no real credential values exist in simulator/message/AI/report storage; retest status requires fresh evidence.
- Final: full tests, package build, app launch, database preservation, and explicit incomplete/hardware-dependent list.
