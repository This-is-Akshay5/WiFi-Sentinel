# Phase 3 manual verification

## Bounded web crawl

1. Open **Web Crawl**, enter a website you own or are explicitly authorized to inspect, set a page limit from 1 to 20, and confirm authorization.
2. Run the crawl. Verify only observed same-origin HTML links are visited, the persisted route inventory shows returned status/content type, and findings link to the crawl evidence.
3. Confirm a same-origin redirect stays in scope and a cross-origin or scheme-changing redirect is rejected before a second request.
4. Confirm query strings, URL credentials, form submissions, authenticated routes, client-side JavaScript routes, and non-GET methods are not used. API labels are path heuristics, not verified endpoints.
5. Use a local test web server to check the actual GET path without accessing an external service. A localhost test is environment-dependent when socket binding is restricted.

## Repository review

1. Open **Repository Review** and choose a repository folder you own or are authorized to inspect.
2. Confirm the UI lists the selected folder name only; it does not display the absolute path or file contents. Explicitly confirm authorization and analyze.
3. Verify the persisted result contains relative file paths, SHA-256 values, redacted pattern indicators, and dependency names/constraints from supported local manifests. No dependency advisory lookup or code execution occurs.
4. Add a harmless test secret to a temporary `.env` and a matching string under `node_modules`; verify neither value nor file appears in results. Verify symbolic links are not followed and file/total limits are respected.

## Local awareness training

1. Open **Awareness Training**, choose a short duration, confirm authorization, and start a session.
2. Confirm the reported listener host is `127.0.0.1` and open the temporary exercise link on this computer.
3. Visit the fixed exercise page, click **Review notice**, and choose only the synthetic Yes/No option. Confirm visits, clicks, and choices appear in analytics and history.
4. Try a request containing an extra `password` field; it must return HTTP 400 and that value must not appear in SQLite, app logs, or the UI.
5. Stop the session and confirm its URL no longer responds. Inactive history older than 90 days can be deleted from the page. Active sessions are marked stopped on app restart; their event history is retained.

## Enrolled LAN receiver messaging

1. On a computer you administer, generate a random token of at least 32 bytes and set it as `WIFISENTINEL_RECEIVER_TOKEN` in that receiver process environment. Do not use an account password.
2. Generate or obtain a TLS certificate for the receiver, then run `python receiver_client.py --receiver-id lab-laptop --bind 192.168.1.20 --port 8765 --cert receiver.crt --key receiver.key`. Use the receiver's actual private interface IP. The client does not alter firewall settings; configure them through your normal administrator workflow if needed.
3. Record the receiver ID, endpoint, shared random token, and SHA-256 certificate fingerprint printed by the receiver. The token must be shared only with the authorized WiFiSentinel operator.
4. In **LAN Messaging**, enter those values and explicitly enroll the receiver. Send a short announcement only after confirming the selected receiver and authorization.
5. Verify the receiver console displays the accepted announcement and WiFiSentinel shows `acknowledged` only after HMAC verification. This means the compatible receiver accepted it; it does not prove an operating-system pop-up or human read.
6. Repeat with a wrong fingerprint, token, receiver ID, expired message, and an unavailable endpoint. Each case must fail without showing `acknowledged`. Forget the receiver and rotate its token separately to revoke any other copies.

## Finding retests and report history

1. Open an assessment with authorization and a declared scope. Run a catalog check that produces a finding with persisted evidence, such as a bounded authorized gateway service check.
2. Do not change the assessment scope. Open **Findings** and choose **Retest** on that finding. Confirm the current-scope consent dialog; backend policy still gates the check.
3. Confirm the new retest row includes a timestamp, outcome, execution, and new evidence reference when the check completed. The workflow reuses target/ports from the original stored evidence rather than accepting a new target from the page.
4. Repeat after changing the declared scope. The check must not run and the outcome must be `unable_to_verify`. A missing or failed check must never be labeled fixed.
5. Export assessment JSON, CSV, and PDF. Confirm each contains the retest status and evidence/execution references. CSV formula-like text must remain neutralized.
6. Findings created by specialized workflows without a supported catalog execution or original scope-linked evidence are not eligible for an automatic fix claim; they remain unable to verify until a dedicated comparison exists.

Run these checks after starting the existing project with `run_simulator.command` on macOS or `run_simulator.bat` on Windows. Use a capture file you are authorized to inspect; it remains local.

## macOS wireless discovery

1. Open **System Settings → Privacy & Security → Location Services**. Enable Location Services and grant access to the terminal application or WiFiSentinel launcher that starts Python.
2. Quit and restart WiFiSentinel. Open **Wireless Networks** and refresh.
3. Check that a scan is labeled `SCANNING` while running, `LIVE EMPTY` only after a successful empty scan, and `CACHED · LAST GOOD` after a failed refresh with earlier observations. Verify SSIDs/BSSIDs only when the operating system actually returns them.
4. If permission is still denied, the UI should show `PERMISSION REQUIRED` and its remediation text; do not interpret that as zero nearby networks.
5. Select an access point and expand **Full Radio Details** and **Raw Source Data**. Compare available SSID/BSSID/channel/signal/security values with the sanitized native fields and inspect any reported beacon interval, country, noise, channel width, rates, capabilities, IE IDs, or PMF advertisement. Missing values stay grouped as unavailable; IE payload bytes are not shown.
6. On macOS, the adapter prefers CoreWLAN's general `scanForNetworksWithSSID` API with a nil SSID and hidden-network inclusion when the installed PyObjC binding exposes it. It falls back to supported general-scan selectors for older bindings. After a denied scan, verify both the Location Services guidance and the native OS error are visible.

The actual macOS application process completed a CoreWLAN scan with four records once; database inspection confirmed all four had channel/signal/security fields but no native SSID or BSSID (`ssid`/`bssid` accessors returned nil), so none were fabricated or copied from the connected network. A later direct scan returned `permission_required` with zero rows. The local deprecated `airport` utility was not present. The UI now marks rows with no BSSIDs as `IDENTIFIERS LIMITED` and shows a Location Services hint. A permission-enabled real scan is still required to confirm that macOS will provide SSID/BSSID values.

The earlier `nearby_bssids > 0` followed by `live_snapshot_failed | error=unavailable` path was caused by a successful non-empty CoreWLAN scan leaving the adapter's initial `scan_outcome=unavailable` unchanged. The adapter now marks that branch `success`; a regression test verifies the exact transition. This correction does not bypass macOS permission policy.

The real desktop launch also exposed a legacy database schema missing `executions.test_id` even though its `user_version` was 8. The new additive schema version 9 migration adds the nullable column and preserves existing execution rows; the migration test verifies both preservation and subsequent writes.

The final retest-history migration is schema version 15. It adds `finding_retests` and does not rewrite existing assessment, execution, finding, or evidence rows. The v14-to-v15 test starts from an existing assessment/finding fixture, removes only the new table to simulate v14, upgrades, and verifies the original rows and fresh retest evidence links remain.

## Authorization document workflow

1. Open **Assessments**, choose an assessment, and open **Authorization Documents**.
2. Select a PDF, DOC, DOCX, or TXT file no larger than 20 MiB. Confirm the selected filename and size are correct, then explicitly confirm it is appropriate authorization evidence.
3. Attach the copy. Verify the active list shows filename, format, byte count, SHA-256, timestamp, and uploader, but no document content or local storage path.
4. Export a JSON and PDF assessment report. Verify the reports contain document metadata and hashes only.
5. Remove the document copy. Verify the active list no longer includes it, the stored file is removed, and an immutable-style audit row retains the action and hash. Existing assessment, finding, and evidence rows remain.
6. Try an unsupported file, a symbolic link, an empty file, and a file over 20 MiB; each must be rejected before storage. A selection changed after choosing must require reselection.

Automated tests cover bounded copy, hashes, path containment, active/deleted metadata, audit history, report metadata, and a schema v12-to-v13 migration using temporary files and databases. The native file dialog has not been exercised in a launched desktop window.

## Windows wireless discovery

1. Start the existing app with `run_simulator.bat` and open **Wireless Networks**.
2. Confirm the UI reports Native WLAN observations or a labeled `netsh` fallback, and that unreported values remain unavailable. For native BSS records, inspect returned PHY type, beacon interval, supported rates, capability flags, and IE summaries.
3. Refresh with a working scan, then temporarily disable/deny WLAN discovery if practical. Confirm the last successful rows remain labeled cached and are not converted into a successful zero result.

Automated tests cover Windows native response parsing and fallback classification on macOS. They are deterministic adapter fixtures, not a Windows hardware run.

## Approved access-point inventory review

1. Open **AP Inventory** and verify the current observations identify their OS scan source and time. A failed or empty scan must not be treated as positive inventory coverage.
2. Add a known, authorized BSSID using the `02:11:22:33:44:55` format, optionally adding an SSID label and notes. Confirm the inventory authorization box and save.
3. Create or select an assessment that records authorization and an explicit comma- or semicolon-separated SSID/BSSID wireless scope. For an isolated check, scope it to one observed BSSID.
4. Confirm the review authorization box and run **Compare in-scope observations**. Verify only completed-scan rows matching the declared SSID/BSSID scope appear in the result.
5. Confirm an exact BSSID match is `approved`; an in-scope BSSID absent from the inventory is an informational, low-confidence review item with persisted evidence. It must not be called a confirmed rogue access point. An observation without BSSID must remain `identity_unavailable`; matching by SSID alone is prohibited.
6. Open the assessment's evidence and findings views and confirm the comparison evidence and any unlisted-BSSID finding are linked. Remove an inventory entry and verify the next review reflects the change.
7. Duplicate SSIDs and neighboring AP observations are not proof of rogue infrastructure. Validate unlisted BSSIDs with the network owner before taking action.

This UI flow has automated bridge/persistence coverage. It has not yet been exercised in a launched desktop window or against a permission-enabled radio scan.

## LAN Device Intelligence

1. Open **Device Intelligence** and verify the page reports observation profiles, not unique device totals.
2. Select rows from the operating-system neighbor cache, authorized ICMP history, and any persisted Nmap result. Confirm the source and observation timestamp remain visible for each row.
3. If the same IP appears with different MAC addresses or sources, verify each row remains separate and the detail view says the record is an observation only.
4. For an Nmap service result, verify only stored open ports are listed and the service/version wording identifies scanner fingerprints as estimates. A capture without Nmap evidence must not show Nmap services.
5. Verify missing vendor, OS, DHCP, VLAN, RSSI, or classification values appear unavailable; they must not be inferred from an IP address or a nearby SSID.
6. Confirm the page discloses that router/DHCP, mDNS/Bonjour, Wi-Fi association sessions, and traffic behavior are not implemented in this view.

Backend profile and persistence aggregation tests use temporary SQLite records. This page has not yet been exercised in a launched desktop window.

## Offline traffic metadata and reachability checks

1. For an authorized 802.11 capture, open **Capture Review**, enter the exact SSID or BSSID, confirm authorization, and analyze it. Verify only DNS question names tied to that wireless scope appear. A capture-wide DNS count may include out-of-scope questions, but their names must not be displayed or persisted in the scoped detail.
2. Confirm the DNS view includes observed timestamp, client/resolver IPs, numeric query type, and BSSID when present. It must not display raw application payload, DNS answers, TLS content, or decrypted data. A capture with no exact AP scope must withhold DNS names.
3. Open **Reachability & Segmentation Review**. Select an assessment whose authorization is recorded, whose active date window includes the current time, whose policy permits `segmentation_reachability`, and whose network scope includes each test IP.
4. Enter no more than 8 literal in-scope target IPs, no more than 4 TCP ports, a destination label, and an expected `allowed` or `blocked` policy. Confirm authorization and run the test from the current machine.
5. Verify the result records the actual local source context if available and each target/port result. A completed TCP handshake may be reported as reachability; a refused port as closed; timeouts and generic network errors remain inconclusive.
6. Verify an observed policy mismatch links to persisted evidence. Do not interpret the operator-provided segment label as verified VLAN membership or claim a test from a remote source segment. No application payload is sent.

DNS parsing, scope filtering, and reachability logic have automated PCAP/bridge tests. No real DNS-bearing capture or authorized segmented network has been used for manual verification in this session.

## Offline capture upload and persistence

1. Open **Capture Review** directly from the left navigation; no scan or assessment selection is needed.
2. Choose **Upload capture**, select an authorized `.pcap` or `.pcapng`, and verify only basename, size, and format are previewed.
3. Optionally enter an exact SSID/BSSID scope. Check the authorization box and select **Analyze capture**.
4. Verify packet counts, SHA-256, parser limitations, and an evidence ID appear only after local analysis and database persistence complete.
5. Navigate away and return. Open the row from **Previously imported captures** and verify the persisted analysis reopens.
6. For a capture containing probe/authentication/association-request/reassociation-request management frames, verify **Station identifiers observed in this capture** lists the frame transmitter, frame subtype, timestamp, and capture name. It must say capture-only and leave associated AP as not established unless direct evidence supports one.
7. Repeat with a structurally valid empty capture: it should report zero packets and still be persisted. Try a wrong extension, malformed file, and a file over the size limit; those should fail without creating successful evidence.

## Passive management frames, PMF, and deauthentication

1. Use a capture containing authorized 802.11 management frames; captures without those frames cannot offer target identities.
2. Open **Deauthentication Assessment**, select the persisted capture, select an observed AP BSSID, choose one or more target identities from that capture, confirm authorization, and run passive analysis.
3. Confirm only evidence-backed deauthentication/disassociation observations and reason codes appear. Advertised MFPC/MFPR values are separate from negotiated PMF enforcement, which remains `unknown`.
4. Generate synthetic targets in **Lab Simulator** and run the simulation. Verify its records say `SIMULATED` and `packet_transmission: none`.
5. Confirm live mode reports `Not supported`. The app must not transmit forged management frames or call a transmitter.

## Database and reports

1. Restart the app and verify existing assessments, captures, reports, and configuration remain available after additive SQLite migrations.
2. Export JSON, CSV, and PDF for an assessment containing capture and defense evidence. Confirm evidence IDs, capture SHA-256, scope, data class, limitations, and simulation labeling are included.
3. Open the CSV in a text editor and verify values beginning with spreadsheet formula characters are prefixed safely.

No real Windows host or authorized management-frame capture was available during automated verification. Report those as manual/hardware checks, not as already completed results.

## Wi-Fi Security Audit

1. Launch the existing app with `./run_simulator.command` on macOS or `run_simulator.bat` on Windows and open **Wi-Fi Security Audit**.
2. Confirm SSID, BSSID, interface, IP/subnet, gateway, authentication, band/channel, source, and timestamp either match the OS or show **Not reported**. On macOS, first grant Location Services to the launching app if CoreWLAN reports permission denied.
3. Leave the authorization checkbox unchecked and verify the audit button stays disabled. Check it only for a network you are authorized to assess.
4. Run an audit. Verify it collects a fresh OS Wi-Fi result, performs at most one bounded ping to the OS-reported gateway, and records no ping output. If disconnected or permission-limited, expect a partial result and unavailable fields.
5. Verify PMF is available only when the observed AP BSSID exactly matches the connected BSSID. A matching SSID with a different BSSID must remain unavailable.
6. Verify Open/WEP/TKIP or legacy WPA is reported only when the current OS source reports it. WPA2/WPA3 alone is not a secure-network guarantee. Unknown controls must not show as pass.
7. With no evidence in at least two core checks, verify the score says **Insufficient evidence**. For a score, check the model `wifi-audit-v1`, product-defined band, coverage, and per-finding risk factors.
8. Mark a recommendation applied. Verify the current score does not change and its state explicitly says verification is still required. Re-run on the same BSSID; only new check evidence can produce verified resolved/still present/unable to verify.
9. Export PDF and compare audit ID, time, network fields, score/insufficient-evidence explanation, findings, remediation state, formula, and limitations with the stored UI record. The PDF must not contain saved passwords or raw packet payloads.
10. Restart the app and open the saved history row. Confirm the integrity indicator passes. For a local integrity-negative test, alter a copy of the audit payload in a disposable test database, not the user's database; export must be blocked.
11. For the optional saved credential, click **Request from operating system** only for the currently connected profile. On macOS, approve or deny the Keychain prompt. On Windows, the app must be launched with an authorized elevated account; the command is restricted to the current SSID. Verify the value starts masked, Reveal enables Copy only after retrieval, and Clear/page navigation/window hiding empties it. Confirm an access denial shows a manual OS instruction and does not create database, report, log, AI, or connector content.

Automated adapter and bridge checks use fixtures; the execution suite does not prove a physical Windows radio, a permission-enabled macOS radio, a real Keychain prompt, an elevated Windows credential lookup, or physical wireless hardware behavior. The current audit does not inspect DNS, router settings, hotspot-specific configuration, or LAN services. Use the existing authorized Assessments, local Tool Integrations, and Capture Review workflows for those separately labeled evidence sources.


## LAN Inventory and static source review

1. Open **LAN Inventory** and verify the OS neighbor-cache table, network context, and source history load independently of the Wi-Fi AP scan. A count is labeled as entries/IPs, not total connected devices.
2. Start local ICMP discovery only after checking the authorization box. Confirm the bounded subnet and address cap are displayed, then verify responders remain in a separate table and non-responders are not called absent.
3. Search by IP, MAC, hostname, vendor, or source. Select a row and confirm the detail panel preserves its original source and timestamp.
4. Open **Source Review**, select a disposable source file containing a test credential-like assignment, and confirm authorization. Verify the result stores rule, file, and line references but never source text or the literal value.
5. Verify a static review assessment and evidence row are persisted. Confirm clean code can produce zero indicators and unsupported/oversized inputs have clear skip or rejection states.
6. This is selected-file static pattern analysis only. It does not clone a repository, query dependency advisories, execute source, or test a running web application.

## Application security snapshots

1. Open **Web Snapshot** and enter a site you own or are explicitly authorized to inspect. Confirm the authorization checkbox before starting.
2. Verify the flow issues one GET request, rejects embedded credentials/query strings, rejects cross-origin redirects, and caps the response body. It must not submit forms.
3. Confirm the saved result includes response status, allowlisted headers, same-origin links, form method/action metadata, cookie flags without cookie values, indicator evidence, and an evidence ID.
4. Verify HTTP errors and invalid targets show a clear error and do not create a successful result. Do not interpret missing headers as proof of exploitation.
5. This version is a one-page snapshot; it does not crawl, authenticate, test APIs, inspect source from a repository, or establish vulnerability exploitability.
