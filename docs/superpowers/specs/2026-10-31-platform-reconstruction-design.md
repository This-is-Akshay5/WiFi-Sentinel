# WiFiSentinel Platform Reconstruction Design

## Intent

Extend the existing WiFiSentinel desktop application into a source- and runtime-evidence security platform while preserving its Wi-Fi discovery, assessments, Nmap, PCAP, SQLite history, reporting, and macOS build workflow. The distinguishing application-security capability correlates only directly linked scanner and source evidence into inspectable attack paths.

## Goals

- Provide explicit engagement scope, authorization, activity windows, exclusions, and a change history before active tests.
- Improve authorized LAN inventory with separate source observations, timestamps, confidence, and non-permanent device identity handling.
- Add capability-aware wireless monitoring and traffic analysis using tools already installed and verified at runtime.
- Add safe, non-destructive web black-box checks and static source analysis; keep findings deterministic and evidence referenced.
- Correlate verified evidence into explainable attack paths and optionally request AI interpretation with explicit disclosure.
- Provide an original, local phishing-awareness simulation that stores synthetic interaction events only.
- Support LAN announcements only through receivers that explicitly enroll and acknowledge; do not claim arbitrary device delivery.
- Unify findings, retesting, reporting, and capability reporting without replacing the current Python/PyWebView/SQLite architecture.
- Refine the existing UI’s tokens, hierarchy, accessibility, and navigation while keeping its visual identity.

## Non-goals and safety boundaries

- No forged wireless frames, packet injection, credential cracking, password harvesting, or access-control bypass.
- No execution of submitted repositories, downloaded build scripts, arbitrary shell commands, or untrusted plugins.
- No destructive or state-changing web tests. Black-box web checks are scoped GET requests and read-only parsing.
- No credential values in simulated forms, event storage, logs, reports, AI requests.
- No message delivery claims without an enrolled receiver acknowledgement. A normal LAN packet cannot force an arbitrary device to display a notification.
- No inference that neighbor-cache entries or randomized MACs are unique, online, or Wi-Fi-associated devices.
- No router configuration changes or hidden SSID recovery claims from ordinary scans.

## Existing constraints and findings

- The source tree is the existing PyWebView desktop app: Python bridge in `main.py`, focused `core/` modules, SQLite `Store`, vanilla JavaScript UI, and a PyInstaller macOS bundle.
- Existing modules include OS wireless adapters, bounded ICMP discovery, Nmap, authorized assessments, passive PCAP review, AI integration, reports, and a dedicated connected-network audit.
- The current navigation includes LAN Inventory, Device Intelligence, Approved Access Point Inventory, Web Snapshot, bounded Web Crawl, selected-file and repository-root source review, Evidence Correlation, Reachability & Segmentation, Awareness Training, and explicitly enrolled LAN Messaging. The AP workflow compares exact BSSIDs from completed operating-system scans with a locally maintained approved list and persists scoped evidence. Unlisted observations remain unverified informational review items. The removed legacy Devices page is not restored. The local awareness exercise binds only to loopback and records synthetic event classes. LAN Messaging supports only the supplied receiver client and never claims OS-popup display or human reading.
- The working project has no Git repository metadata. The installed database is under `~/Library/Application Support/WiFiSentinel`; after final verification it is schema 15, integrity check `ok`, with 3 assessments, 4 executions, 3 findings, 4 evidence records, 0 captures, and 75 observation snapshots. Three additional source-labelled observations were recorded during app startup/navigation verification; the original historical counts remain. Schema 15 adds only finding-retest history. Neither database may be recreated or overwritten.
- Baseline: The pre-change baseline included a connector-only localhost bind test blocked by the sandbox. The connector and its dedicated tests have since been removed as obsolete; the current suite result is recorded in `docs/platform-reconstruction-progress.md`.
- Nmap 7.993, TShark, tcpdump, Aircrack-ng, hcxtools, and Bettercap executables are present on this Mac. Nmap was exercised through a temporary authorized assessment against loopback port 9 and its evidence persisted. Presence of other tools does not prove capability or invocation; the current tool matrix correctly distinguishes detection from integration.
- `.env` exists in source and installed application storage. Do not read or copy secret values. Existing `.gitignore` ignores secret environment files and exempts `.env.example`.

## Approaches considered

1. **Replace the desktop with a web framework and new database.** This would enable a conventional web scanning architecture, but it would discard working native adapters, SQLite history, capture handling, and the existing macOS packaging path. Rejected.
2. **Add one large security dashboard to the current UI and keep checks in `main.py`.** This is quick initially, but mixes authorization, scanning, AI, and persistence and makes scope mistakes difficult to test. Rejected.
3. **Extend the current app with bounded modules and additive schema migrations.** Keep `main.py` as the PyWebView bridge, put validation and deterministic analysis in focused `core/` modules, persist evidence/results in SQLite, and expose real capability states in the existing UI. Recommended and selected by the implementation constraints in the request.

## Architecture

- **Engagement:** Existing assessments remain the top-level engagement records. An additive scope document stores authorized assets, permitted activity, start/end windows, exclusions, contact/rules metadata, and versioned change history. A single backend authorization evaluator gates active operations; legacy records remain readable and are clearly marked until their scope is renewed.
- **Observations:** Discovery sources remain distinct. Each device field carries source, timestamp, confidence, and an inference/unavailable label. History links observations without declaring randomized MAC addresses to be permanent identities.
- **Tools:** A capability registry checks executable presence, bounded version output, OS permissions, native tool availability, and hardware claims independently. Existing Nmap execution is reused; other binaries are never invoked merely because installed.
- **Web analysis:** A web scan is bound to an authorized host and assessment. Black-box checks use same-origin bounded GET requests, redirect revalidation, response-size limits, and no form submission. White-box analysis reads allowlisted source files, excludes generated/dependency/secret files, never executes code, and redacts secret values. Findings include stable rule IDs and evidence references.
- **Attack paths and AI:** A deterministic graph builder links nodes only through explicit shared asset/evidence references and declared relationships. AI is optional, disclosed, and given redacted evidence IDs/snippets; it may explain but not create findings or unreferenced graph edges.
- **Evidence correlation:** Current graph output links a finding only to its persisted evidence reference. Same-asset overlap is a theoretical candidate; the app does not create ordered exploit chains until evidence relations and preconditions can be verified.
- **Training and messaging:** The current awareness exercise uses one original fixed local template, loopback-only hosting, synthetic yes/no outcomes, bounded expiry, and aggregate event persistence. It never persists submitted field values, identities, or client addresses. LAN messaging is implemented only with the supplied compatible receiver: an explicit in-memory enrollment, bounded HMAC-signed message, and HMAC-validated acknowledgement. Remote delivery requires HTTPS with a pinned certificate and a private-network IP. The compatible receiver prints accepted messages in its terminal; no OS popup or human-read proof is claimed. Enrollment is lost at desktop restart, there is no multi-recipient delivery workflow, and physical cross-host TLS verification remains outstanding.
- **Persistence and reports:** Schema upgrades are additive and transactional. Reports are produced from stored records with provenance, limitations, redaction, and selected finding retest outcomes. A retest requires persisted original test/evidence scope to match the assessment's current scope and is re-run through the same backend authorization gate. The current lifecycle covers supported catalog findings; source/web/capture/AP-specific normalization and an attestation remain future work. Existing assessment and Wi-Fi audit reports remain intact.
- **UI:** Continue with HTML/CSS/vanilla JS and current PyWebView bridge, use the existing dark/light token system, add grouped navigation without restoring the obsolete Devices page, and give every new screen loading, empty, error, permission, and capability states.

## Verification bar

Every scanner, workflow, and UI action must be exercised through its public bridge or module boundary, with persistence and failure tests. OS/hardware behavior is reported separately from fixtures. Full regression suite, JavaScript checks, macOS build, and installed-app launch are required before declaring the platform complete. No user database, `.env`, captures, or reports are used as test fixtures.
