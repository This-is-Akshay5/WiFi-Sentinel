# WiFiSentinel Phase 3 — Wireless Evidence and Defensive Assessment

> Superseded by the 2026-10-31 platform reconstruction. Kali Linux, Kismet, and the remote connector were explicitly retired; do not implement the connector-specific instructions below. The supported architecture uses native OS adapters, offline capture analysis, and the labeled software-only lab simulator.

## Goal

Make wireless discovery stable and honest, show device observations with source-level provenance, make offline capture review independently usable, and add a passive/simulated deauthentication-defense assessment. Preserve existing user data, credentials, reports, captures, connector configuration, and the existing desktop application.

## Verified baseline and root causes

- A read-only CoreWLAN scan on this Mac returned `permission_required`, zero APs, and no SSID/BSSID values. The host therefore supplied no identifiers to preserve during this check. CoreWLAN's adapter, connector normalization, and UI use the returned SSID/BSSID fields when present. A successful macOS permission-enabled scan is still required to validate actual radio results.
- `RealWiFiEngine.poll_refresh()` publishes every non-raising future result. Adapter failures and permission-limited scans can be returned as ordinary snapshots with empty `nearby_aps`; those replace a prior successful result. `refreshLiveNow()` then replaces the UI state with that snapshot. This explains the zero-network flicker path.
- The frontend starts a 12-second interval and independently starts short polling loops while `refreshing`. Request IDs reject older UI responses, and the engine prevents simultaneous futures, but the polling paths do not distinguish a successful empty scan from a non-raising failed scan at the cache boundary.
- Capture Review is navigable, but `captureReview()` returns an instruction-only empty state without `state.aid`; its upload control also requires assessment authorization and a wireless scope. Thus a local offline capture cannot be uploaded directly from the page without first selecting/reviewing an AP.
- `devices()` merges neighbor-cache and ICMP responder records by IP, then combines their source labels. That loses the distinction between two observations and can blur their timestamps/status. AP scan records are separately rendered and do not establish client association.
- `deauth_validation` is declared in the general catalog as active connector work, but `_block_reason()` always blocks it. There is no dedicated defense-assessment data model or workflow. Capture analysis currently does not report deauthentication/disassociation management frames or RSN PMF capability bits.

## 1. Wireless discovery state and permissions

Continue using the current macOS CoreWLAN/airport, Windows WLAN/netsh, and authenticated Kali connector adapters. Do not replace them with a research dataset or merge sources into one AP observation.

Represent scan attempt state separately from the last successful scan. The normalized snapshot reports `scanning`, `success`, `empty`, `error`, `permission_required`, or `unavailable`, along with attempt timestamps, last-success time, source, error, and freshness. AP records retain the source's SSID/BSSID and other available values, original observation time, and stable identity. An unsuccessful attempt leaves the last successful AP records intact as `cached`; a successful empty scan sets the current live set to zero and preserves earlier scans in history. A snapshot being collected never renders a zero count as a completed empty scan.

Keep refresh single-flight in the engine, reject obsolete generations before publication, and coalesce frontend refresh requests so timer and manual refreshes cannot race. Use a conservative interval and avoid retry loops that create duplicate scans. The local result is preferred when it is permitted; the Kali fallback remains independently sourced and is used only for supported local-unavailable states. A fallback failure does not erase the last successful observation.

Show the actual macOS permission limitation and actionable steps: enable Location Services and grant access to the app launching WiFiSentinel (usually Terminal), then restart/rescan. Do not elevate permissions, alter privacy settings, or reveal local SSIDs/BSSIDs in logs. Report what the source returned; absence is not hidden-network evidence.

## 2. Source-labeled device intelligence

Keep APs, local neighbor entries, authorized ICMP responders, capture-observed stations, and historical records as different record kinds. Do not merge them into one "online device" or associated-client claim. Cross-reference matching IP/MAC values in the inspector only, with each source claim, method, timestamp, state, and limitation shown independently.

Persist completed wireless and neighbor snapshots in an additive SQLite history model. Preserve the existing `device_discovery_runs` for authorized bounded ICMP work. Deduplicate repeated UI reads and equivalent scan snapshots without removing a distinct observation, source, or changed result. Preserve first/last-seen times and original observation timestamps. AP scan observations remain distinct from OS neighbor devices and capture evidence; simulated targets remain in a simulation-only data class.

The Devices page gains source filters, sorting, refresh, selectable rows, history, and a details inspector. Neighbor-cache status is not proof of reachability; an ICMP responder is evidence only for that probe/time. A Wi-Fi scan is evidence of an AP only. Capture-derived station identity is displayed only if the captured 802.11 address roles support it, and never implies current presence. No AP/client association is claimed absent explicit source evidence.

Display IP, MAC, hostname, vendor, interface, source/method, first/last observed, status, and confidence only when actually supplied or resolved. Do not bundle or query an OUI/vendor database in this phase. Do not classify from IP or MAC alone. Hostname-derived device category, if retained, is explicitly low-confidence with its textual basis; otherwise use `Unknown`/`Unclassified`. Randomized MACs and missing hostnames remain ordinary unknown identifiers.

## 3. Independently usable offline capture review

Keep the existing bounded PCAP/PCAPNG parser, safe content-addressed storage, SHA-256 verification, duplicate detection, SQLite evidence transaction, and JSON/CSV/PDF integration. Make Capture Review render its upload action without a selected AP or assessment. Selecting a file opens the native picker; Analyze requires explicit confirmation that the operator is authorized to review that file. The user may optionally scope wireless details to an SSID/BSSID; no scope means offline analysis of the supplied file's supported metadata, not a live-network operation. The selection, analysis and persisted results are local-only.

Store standalone imports in a dedicated locally authorized offline-capture assessment/workspace, created only after the user chooses Analyze and confirms authorization. Do not require or fabricate a nearby AP. If an existing assessment is deliberately selected, preserve its existing scope and authorization rules. Invalid/unsupported/truncated files fail visibly without storing a successful result. Show progress, errors, result status, packet counts, link types, protocol counts, supported wireless observations, evidence/hash, limitations, and a history list with a way to reopen persisted analysis details.

## 4. Defensive deauthentication assessment

Add a dedicated Deauthentication Assessment view. Its modes are `Passive capture analysis`, `Lab simulation`, and `Live transmission: Not supported`. No execution path sends, forges, injects, or requests deauthentication frames. The existing active catalog entry must not imply otherwise; unsupported requests return `Not supported` and create no success evidence.

Require a persisted assessment with explicit authorization and an exact wireless scope for assessment runs. AP choices come from actual current scan or imported capture observations. Passive target choices come only from station identities in selected capture evidence. Support selecting multiple such targets while preserving each source and evidence reference; do not accept free-form real target MAC addresses. Lab targets are synthetic labels stored and rendered only as simulation records, separate from AP/device observations and live history.

Extend offline frame analysis to report actual deauthentication and disassociation management frame counts, capture timestamps, transmitter/receiver/BSSID roles when unambiguous, reason codes when the corresponding Scapy layer carries them, repetition counts, and relevant protected-frame flag observations. Parse RSN capabilities from Beacon/Probe Response information elements into advertised PMF capable/required bits when available. Keep three conclusions separate: advertised capability, passive frame behavior observed, and negotiated/enforced PMF, which remains unknown without evidence that directly supports it. A protected bit alone is not proof of enforced PMF or an attack. Findings are evidence-linked and informational unless a reproducible passive pattern justifies a cautious detection; they never claim a disconnect or vulnerability from a synthetic run.

The simulator demonstrates a documented state transition against synthetic targets and ends `Simulation completed`. Passive analysis ends `Analysis completed`. Unsupported live mode ends `Not supported`. Persist run mode, AP, selected target references, scope, authorization, methodology, timestamps, results, evidence, limitations, and status transactionally. Simulation outputs carry an explicit simulation data class and never enter live network or device tables.

## 5. Persistence, migrations, exports, and safety

Use additive, idempotent migrations only. Preserve existing assessments, findings, history, evidence, capture files, settings, `.env`, tokens, and reports. Add provenance-preserving scan history and deauthentication-assessment records as needed; link each passive finding to a real capture/AP evidence row. Save each assessment run and its evidence/findings atomically. Repeated identical captures continue to deduplicate by assessment and SHA-256.

JSON, CSV, and PDF exports include source/method, observed/imported timestamps, freshness, run mode, evidence references, methodology, and limitations. CSV formula escaping and PDF pagination stay intact. Simulation is always marked as such in exports; unsupported operations produce no finding. Raw packet payloads, credentials, `.env` values, and unnecessary identifiers are not logged or exported.

## 6. Cross-platform and verification contract

macOS continues to use CoreWLAN and the existing airport fallback. Windows continues to use native WLAN/netsh and OS neighbor APIs. Linux/Kali reports real `iw` Wi-Fi interfaces separately from virtual Ethernet and uses only supported passive `nmcli --rescan no` observations in the connector. Offline capture review works without any radio or Kali service. The phase does not add monitor-mode capture or live radio transmission.

Automated tests cover state transitions and races, adapter field preservation/permission states, source-separated device records/history, upload UI-to-bridge-to-store invocation, capture parsing/persistence/reopen, PMF and management-frame parsing, assessment authorization/scope, simulation labelling, unsupported-live refusal, and exports. Tests using mocked native adapters or a local connector are labeled as such. Manual macOS verification records only whether SSID/BSSID fields were returned and their counts, not the actual sensitive values. Windows/Kali/hardware behavior is not claimed unless actually exercised.

## Acceptance criteria

1. A transient/permission scan failure never replaces the last successful AP list; cached rows retain their original source/time and are labeled cached. A successful empty scan is live-empty and leaves prior history intact.
2. Concurrent/manual/background refreshes cannot publish out of order or show zero as a completed scan while work is in progress.
3. AP, neighbor, ICMP, capture-station, historical, and simulated records remain separable and explainable in the UI and reports.
4. Capture Review shows Upload capture with no selected network; selection, authorization, optional scope, local analysis, persistence, and reopening results work end-to-end.
5. Deauthentication assessments support only scoped passive analysis or synthetic simulation. No forged-frame transmit path exists; unsupported live mode is explicit.
6. Existing data and credentials are preserved, migrations are additive, and all Python/UI regression suites pass.
