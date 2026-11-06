# WiFiSentinel

WiFiSentinel is a local Python/PyWebView desktop application for evidence-based wireless and network security assessment. It uses the host operating system's Wi-Fi and neighbor APIs, a local SQLite database, and optional locally installed security tools. Kali and remote connector services are not part of the active architecture.

## Current capabilities

- Native Wi-Fi discovery through macOS CoreWLAN/system utilities or Windows WLAN APIs, with source labels, timestamps, and explicit permission/error states.
- Assessments with explicit authorization, network/wireless scope, a versioned engagement manifest, permitted test IDs, timezone-aware dates, optional testing windows and exclusions. Active network checks are blocked unless policy and target-scope gates pass. Scope documents and full site/controller verification remain in development.
- Selected finding retests rerun the original supported catalog check only when the saved scope matches the current assessment scope. Outcomes are stored with new evidence as fixed, partial, unresolved, or unable to verify; unsupported/legacy finding sources are not reported as fixed.
- A LAN Inventory page that presents OS neighbor-cache rows and explicitly authorized, bounded ICMP responders as separate observations, with source history and search. It does not claim complete client discovery or merge identities.
- Device Intelligence and Approved Access Point Inventory pages preserve source-specific records and compare exact observed BSSIDs within declared wireless scope. Review items are not labelled confirmed rogue APs.
- Authorization documents can be attached to an assessment as bounded local copies with SHA-256 provenance and audited removal; document content is not included in reports.
- Offline PCAP/PCAPNG import and bounded analysis with SHA-256 evidence persistence.
- Passive deauthentication/disassociation and PMF evidence review, plus a clearly labelled software-only lab simulator. No forged management frames are transmitted.
- Connected-network Wi-Fi audit, findings, evidence, deterministic posture, AI-assisted evidence explanation, and reports.
- Read-only static source review for selected local source/configuration files, with size limits, deterministic review indicators, evidence persistence, and no code execution or secret-value output.
- Read-only repository-root review with generated/dependency and common secret-file exclusions, local dependency-manifest inventory, and explicit size limits. It does not execute code or consult an advisory database.
- A read-only web surface snapshot for an authorized URL: one bounded GET, same-origin redirect checks, pinned DNS resolution, header/cookie/form/link metadata, and persisted evidence. It does not submit forms or claim to be a full vulnerability scanner.
- A bounded same-origin Web Crawl that records only observed route/status/content-type metadata and rule indicators from up to 20 pages. It does not use authentication, query strings, JavaScript, or state-changing requests.
- Evidence Correlation displays direct persisted finding-to-evidence references and theoretical same-asset candidates. It does not generate ordered exploit paths.
- Awareness Training hosts one fixed synthetic exercise at `127.0.0.1`; it records only visit, click, and yes/no synthetic-choice events. It does not send email or LAN announcements, collect credentials, or host on a LAN interface.
- LAN Messaging works only with a compatible, explicitly enrolled `receiver_client.py`. Remote endpoints require private-LAN HTTPS with a pinned certificate and scoped HMAC token. A signed acknowledgement means accepted by that receiver, not displayed as a system pop-up or read by a person.
- Local executable detection for Nmap, TShark, tcpdump, Aircrack-ng, hcxtools, Bettercap, and Wireshark. Detection is distinct from execution: Nmap is wired to the assessment catalog; the other listed tools are not invoked unless a specific workflow says so.

## Run from source

Use Python 3.12 and install dependencies from `requirements.txt`. On macOS, run `./run_simulator.command`; on Windows, run `run_simulator.bat`. The UI uses the native OS APIs and may require macOS Location Services permission to reveal Wi-Fi identifiers. If permission is denied, the application keeps the state visible and does not invent scan results.

The macOS packaged app keeps its database, captures, reports, logs, and local `.env` under `~/Library/Application Support/WiFiSentinel`. Source-run development uses the project directory. Preserve those data files when upgrading.

## Hardware and permissions

Ordinary software-based Wi-Fi scans can discover networks exposed by the OS and require a supported built-in or external Wi-Fi adapter. A separate adapter is **not** required for offline PCAP review, local neighbor-cache inspection, Nmap scans over an authorized IP scope, or software-only simulation. WiFiSentinel does not currently implement live monitor-mode capture or frame injection; installing packet tools does not prove radio capability. A compatible adapter and driver may be required for future monitor-mode work, but are not sufficient by themselves.

## Local configuration

Copy `.env.example` to `.env` if needed. Keep API keys and `.env` out of source control. `OPENAI_API_KEY` is optional; it is used only for AI explanations of persisted evidence. `OPENAI_MODEL` optionally selects a model. `WIFISENTINEL_MAX_CAPTURE_MB` changes the bounded offline capture size limit.

## Compatible LAN receiver

The optional standard-library receiver can run on a Mac or Windows computer where Python is available. Generate a random token of at least 32 bytes, set it as `WIFISENTINEL_RECEIVER_TOKEN` in that process environment, and use a TLS certificate/private key for a private interface. For example:

```sh
python receiver_client.py --receiver-id lab-laptop --bind 192.168.1.20 --port 8765 --cert receiver.crt --key receiver.key
```

Use the receiver's actual private IP. The receiver prints its certificate SHA-256 fingerprint for pinning in the **LAN Messaging** page. WiFiSentinel keeps the shared token in memory only; re-enroll after restarting the desktop app. The receiver accepts short-lived signed announcements and returns an HMAC-signed acknowledgement. It does not send operating-system notifications or claim a person read the message. Unknown devices and hosts without the receiver client are unsupported.

## Tests

Run the suite with `python3 -m pytest`. Automated adapter tests use fixtures; they do not establish physical Windows hardware behavior or a permission-enabled macOS radio result. Localhost-server tests are kept when they test a supported feature, and environment restrictions must be reported rather than hidden.

## Limitations

The larger roadmap is still incomplete. Open work includes router/DHCP and mDNS device intelligence, live traffic capture and flow summaries, broader authenticated/runtime web analysis, verified ordered attack paths and optional AI explanation, LAN-hosted or multi-user awareness workflows, persistent receiver credential management and cross-host receiver testing, full finding normalization/attestation/retesting for non-catalog sources, and Windows physical-hardware/package validation. See `docs/platform-reconstruction-progress.md` for the current implementation ledger.
