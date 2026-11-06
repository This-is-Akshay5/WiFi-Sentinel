# WiFiSentinel Wi-Fi Security Audit

> Historical design note: Kali/Kismet connector references below are superseded by the user's later instruction to retire Kali and the connector. Use native OS observations, local authorized checks, and offline evidence only.

## Goal

Add a persisted, evidence-led Wi-Fi Security Audit to the existing desktop application. It reports the currently connected network as exposed by the operating system, checks only controls supported by available evidence, computes a deterministic risk score only when evidence is sufficient, and exports the stored result as PDF.

## Constraints and existing capabilities

- Keep the current app, adapters, Store, and ReportLab reporting dependency.
- Preserve `.env`, existing SQLite records, capture evidence, reports, and assessment history.
- The current OS adapter exposes connected Wi-Fi details, IP/subnet/gateway context, and nearby AP observations. PMF is considered only when an AP with the exact connected BSSID has a parsed advertisement.
- The existing assessment workflow already provides separately authorized bounded LAN discovery, offline PCAP review, connector/Kismet support, and passive defense analysis. The new audit must not duplicate or relabel those sources.
- No router changes or wireless frame transmission are part of this feature.

## Design

Add `core/wifi_audit.py` as a pure audit evaluator. The bridge obtains one fresh OS Wi-Fi result and network context, asks for an explicit authorization confirmation, and performs one bounded ping of the observed gateway. The evaluator records connection/security/PMF/gateway checks, explicit unavailable checks, source and timestamps, findings, recommendations, coverage, and limitations. It never guesses the connected BSSID from an SSID or treats unknown checks as passed.

An additive schema v11 table stores immutable audit payloads with a SHA-256 digest; a separate actions table stores whether the operator marked each recommendation applied. Reads verify the payload digest and expose integrity status. A later audit compares prior findings only against new evidence for the same BSSID and reports verified resolved, recurring, still present, or unable to verify. The score uses severity factors Critical=1.00, High=0.75, Medium=0.50, Low=0.25, Informational=0.00, multiplied by normalized [0,1] exploitability, exposure, impact, and evidence-quality factors. Evidence quality is 1.00 for direct OS-reported authentication/cipher and 0.80 for a parsed exact-BSSID PMF advertisement. Per correlation group, only the greatest contribution counts; independent groups combine as `100 × (1 − ∏(1 − group_contribution))`, rounded to an integer. Product-coded exploitability, exposure, and impact factors describe the specific check and are not probabilities. A score is withheld when there is no confirmed high-impact finding and fewer than two core controls have usable evidence. Thresholds are 0–19 Low, 20–39 Moderate, 40–69 High, and 70–100 Critical. Model version is stored with every result.

Add an Audit navigation page that shows the connected-network context, explicit authorization, current result, coverage, severity distribution, findings, remediation steps and verification status, limitations, and persisted history. The UI and backend reject overlapping audit starts. Links lead to existing separately labeled LAN, Kali/Kismet, and offline PCAP workflows. A dedicated PDF action renders an integrity-verified stored audit payload through the existing ReportLab dependency using a Unicode CID font for network names and evidence. The report never includes credentials or packet payloads.

Saved Wi-Fi credential access is an optional, explicit action separate from scanning. macOS uses the Keychain `security` utility for the exact current SSID and honors Keychain access controls/prompts. Windows invokes `netsh` for the exact current profile only when the process is elevated; otherwise it returns an actionable limitation. The value is returned only to the active UI, masked by default, copied only after reveal, never logged/stored/exported/sent to AI or connector, and cleared on page exit or window hiding. The audit/report path uses a whitelisted network context and cannot include this credential. DNS configuration and router settings remain unavailable/manual unless a current adapter provides direct evidence. Active LAN discovery remains in the existing explicitly authorized workflow.

## Acceptance criteria

1. Audit requires explicit authorization and uses a fresh OS query; failed or disconnected states remain explicit.
2. SSID/BSSID, radio/security fields, IP/subnet/gateway, source, and time are shown only when returned by the OS.
3. PMF evidence is matched by exact connected BSSID; absent evidence is unavailable.
4. Open, WEP, legacy WPA/TKIP, and observed optional PMF produce evidence-linked findings with practical remediation.
5. Unknown checks do not pass; insufficient evidence does not receive a low score.
6. Risk scoring is deterministic, bounded, versioned, deduplicates correlated risks, and excludes verified-resolved findings.
7. Audit payloads persist without rewriting existing rows and report tampering through digest validation.
8. PDF content is built from the persisted payload and includes evidence, coverage, limitations, formula/version, findings, and remediation.
9. Existing test suite and the new audit, migration, bridge, UI, and PDF tests pass. Physical Windows/Kali validation is reported only if performed.
