# WiFiSentinel

WiFiSentinel is a desktop application for wireless and network security assessment. Built with Python and PyWebView, it brings network discovery, security checks, device observations, evidence analysis and reporting into one place.

It uses native operating system APIs, locally installed security tools and an SQLite database. Kali Linux and remote connector services are not part of the current architecture.

## Features

### Wireless Discovery and Security

WiFiSentinel discovers nearby wireless networks through macOS CoreWLAN and system utilities or the Windows WLAN API. It displays available information such as SSID, BSSID, channel, frequency, signal strength and security configuration.

Each observation includes its source and timestamp. When the operating system blocks access to wireless information, the application reports the permission or capability issue instead of displaying invented results.

The WiFi Security Audit examines the connected network, evaluates available security settings and produces findings with supporting evidence. It also maintains audit history and provides deterministic security posture results, with optional AI explanations.

### Assessments and Authorization

Assessments define what can be tested and under which conditions.

Each assessment can include its target, tester, environment, network scope, wireless scope, permitted test IDs, authorization period and exclusions. A versioned engagement manifest records the assessment configuration.

Active network checks are blocked unless the authorization policy and target scope requirements are satisfied.

Authorization documents can be attached as local copies. WiFiSentinel records their SHA 256 hashes and removal history. Document contents are not included in exported reports.

Scope documents and complete site or controller verification are still under development.

### LAN Inventory and Device Intelligence

LAN Inventory displays devices observed through the operating system's neighbor cache and explicitly authorized, bounded ICMP discovery.

These observations remain separate, with their source and history preserved. WiFiSentinel does not claim to discover every device connected to a network or merge different observations into a single device without sufficient evidence.

Device Intelligence maintains source specific device records. Approved Access Point Inventory compares observed BSSIDs against an approved list within the assessment's declared wireless scope.

Unlisted access points are marked for review. They are not automatically classified as confirmed rogue access points.

Router and DHCP integration, mDNS discovery and more advanced device identification remain under development.

### Network Assessment

WiFiSentinel supports authorized network checks through its assessment engine. Nmap is integrated into the assessment catalog for host and service assessment.

Reachability checks use bounded TCP connection attempts against permitted targets. Results are stored with their execution history and supporting evidence.

Network segmentation analysis is currently limited. Complete network topology discovery and testing from multiple network segments are not yet available.

### Packet Capture Analysis

WiFiSentinel supports offline PCAP and PCAPNG imports with bounded analysis.

Capture files are validated, hashed using SHA 256 and stored with their analysis results. Supported checks examine packet metadata, wireless management events, deauthentication and disassociation activity, PMF observations, EAPOL and SAE events, and in scope DNS queries.

The application also includes a software only lab simulator for demonstrating wireless assessment concepts.

It does not currently perform live monitor mode capture or transmit forged wireless management frames.

### Source Code and Repository Review

Source Review examines selected local source and configuration files using read only static analysis.

Repository Review scans a selected project directory, applies common exclusions for generated files and dependencies, and inventories supported dependency manifests.

Both workflows use file size limits and deterministic security checks. Source code is never executed, and detected secret values are not displayed or included in findings.

Dependency versions are inventoried, but the current implementation does not consult a vulnerability advisory database.

### Web Application Analysis

Web Snapshot performs a bounded GET request against an authorized URL. It examines response headers, cookies, forms, links and other available page metadata. Redirects are checked against the permitted origin, and DNS resolution is validated before the request is made.

Web Crawl follows same origin links and examines up to 20 pages. It records observed routes, response status codes, content types and supported security indicators.

These workflows are read only. They do not submit forms, use authenticated sessions, execute JavaScript or perform state changing requests. They should not be treated as a complete web vulnerability scanner.

### Evidence Correlation

Evidence Correlation displays persisted findings and their direct evidence references. It also identifies theoretical relationships between findings that share an explicitly recorded asset.

These relationships help with investigation, but the current implementation does not generate ordered exploit chains or verify that one weakness can be used to reach another.

### Awareness Training

The Awareness Training module hosts a fixed synthetic exercise on the local machine at `127.0.0.1`.

It records page visits, clicks and synthetic yes or no choices. It does not collect passwords, send emails or distribute LAN announcements. Hosting exercises on a LAN interface and supporting multiple participants remain future work.

### LAN Messaging

LAN Messaging supports explicitly enrolled devices running the compatible `receiver_client.py` program.

Messages use scoped HMAC authentication, expiry checks and signed acknowledgements. Remote receivers require private LAN HTTPS with a pinned certificate.

An acknowledgement confirms that the receiver accepted the message. It does not mean that an operating system notification appeared or that someone read it.

Devices without the compatible receiver are not supported.

### Reports and Retesting

WiFiSentinel stores assessment findings, evidence and execution history in SQLite. Supported reports can be exported for assessment records.

Selected finding retests rerun the original supported catalog check when the saved scope matches the current assessment. Results are recorded as fixed, partial, unresolved or unable to verify, with new evidence where available.

Unsupported or legacy finding sources are not marked as fixed simply because a retest was attempted.

### AI Assistance

AI assistance is optional and uses the OpenAI API.

It is intended to explain persisted evidence and assessment findings. It does not perform the underlying scans or independently establish that a vulnerability exists.

The application uses deterministic checks for its implemented security analysis. It does not currently include a trained machine learning model for intrusion detection.

### Tool Detection

WiFiSentinel checks whether supported local security tools are installed, including:

• Nmap  
• TShark  
• tcpdump  
• Aircrack ng  
• hcxtools  
• Bettercap  
• Wireshark  

Tool availability is separate from actual integration. Nmap is connected to the assessment catalog. The other tools are not automatically executed simply because they are installed.

## Technology Stack

| Component | Technology |
|---|---|
| Application backend | Python |
| Desktop framework | PyWebView |
| User interface | HTML, CSS and JavaScript |
| Database | SQLite |
| macOS wireless integration | CoreWLAN and system utilities |
| Windows wireless integration | Windows WLAN APIs |
| Network assessment | Nmap |
| Packet analysis | Scapy |
| Optional AI | OpenAI API |
| Report generation | PDF, CSV and JSON export |
| macOS packaging | PyInstaller |

## Running the Application

WiFiSentinel requires Python 3.12 and the dependencies listed in `requirements.txt`.

On macOS, run:

```bash
./run_simulator.command
```

On Windows, run:

```bat
run_simulator.bat
```

The application uses native operating system APIs. On macOS, Location Services permission may be required to retrieve wireless identifiers.

If permission is denied or a capability is unavailable, WiFiSentinel displays the relevant state rather than generating substitute data.

## Data Storage

When running as a packaged macOS application, WiFiSentinel stores its database, captures, reports, logs and local `.env` file under:

```text
~/Library/Application Support/WiFiSentinel
```

When running from source, development data is stored in the project directory.

Preserve the existing database, configuration and Application Support files when upgrading the application.

## Configuration

Copy `.env.example` to `.env` when configuration is required.

The following settings are supported:

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | Optional API key for AI explanations |
| `OPENAI_MODEL` | Optional model selection |
| `WIFISENTINEL_MAX_CAPTURE_MB` | Maximum permitted offline capture size |

Keep `.env` and all API keys out of source control.

## Compatible LAN Receiver

The optional receiver can run on a Mac or Windows computer with Python installed.

Generate a random token containing at least 32 bytes and set it in the receiver process environment as `WIFISENTINEL_RECEIVER_TOKEN`. Configure a TLS certificate and private key for the receiver's private network interface.

Example:

```bash
python receiver_client.py --receiver-id lab-laptop --bind 192.168.1.20 --port 8765 --cert receiver.crt --key receiver.key
```

Replace the example address with the receiver's actual private IP address.

The receiver displays its certificate SHA 256 fingerprint. Enter this fingerprint in the LAN Messaging page when enrolling the device.

The desktop application keeps the shared token in memory. Receivers must be enrolled again after the desktop application restarts.

## Hardware and Permissions

Normal WiFi discovery uses the wireless information exposed by the operating system. A supported built in or external WiFi adapter is required.

A separate adapter is not needed for offline packet capture analysis, local neighbor cache inspection, authorized Nmap scans or software only simulations.

Live monitor mode capture and wireless frame injection are not currently implemented. Installing packet analysis tools does not guarantee that the computer's wireless hardware supports these capabilities.

Future monitor mode functionality may require a compatible adapter and drivers. Hardware compatibility and operating system support must be verified separately.

## Testing

Run the Python test suite with:

```bash
python3 -m pytest
```

The automated adapter tests use fixtures. They do not prove that physical Windows hardware works or that macOS wireless permissions allow a live scan.

Localhost tests are retained when they cover supported application features. If the execution environment blocks a test, the restriction should be reported rather than hidden.

## Current Limitations and Development Work

WiFiSentinel is still under active development. The following areas need further implementation and verification:

• Router and DHCP integration, mDNS discovery and deeper device intelligence.

• Live traffic capture, flow summaries and broader network segmentation testing.

• Authenticated web application analysis and more extensive runtime security checks.

• Ordered, evidence linked attack paths with verified transitions and optional AI explanations.

• LAN hosted and multi user awareness training.

• Persistent receiver credential management and cross host messaging verification.

• Complete finding normalization, reporting, retesting and assessment attestation across all modules.

• Physical Windows hardware testing and packaged application verification.

The implementation status and development history are maintained in:

```text
docs/platform-reconstruction-progress.md
```

WiFiSentinel is designed to make authorized wireless and network assessments easier to conduct, investigate and document, while keeping findings tied to the evidence actually collected.
