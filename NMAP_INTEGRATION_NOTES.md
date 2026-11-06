# WiFiSentinel Nmap integration patch

This patch adds a first local Nmap execution path.

## Current behavior
- Adds `nmap_scan` to the security test catalog.
- Requires recorded assessment authorization and a declared network scope.
- Accepts one literal IP address only; the address must be inside a declared CIDR or match an exact IP scope entry.
- Runs TCP connect scanning (`-sT`) with light service version detection (`-sV --version-light`) and a conservative timing profile.
- Uses Nmap fast mode (top 100 TCP ports) by default, or accepts an explicit list/ranges capped at 256 ports.
- Does not use NSE scripts, OS detection, UDP scanning, host discovery sweeps, or wireless frame operations.
- Parses Nmap XML output and persists the actual result as evidence in SQLite.
- Creates an informational finding only when Nmap actually reports open TCP ports.
- Adds a prompt for target and optional ports in the Security Test Catalog UI.

## Not yet complete
- The scan currently runs synchronously. A cancellable background job, live progress, and UI cancellation control are not included in this patch.
- Reports already include persisted evidence and findings generically, but no dedicated Nmap report section has been added.
- Tool Integrations reports `INTEGRATION PARTIAL` intentionally; do not label this fully integrated until cancellation and end-to-end UI verification are completed.

## Configuration
`main.py` already loads the frozen app configuration from:
`~/Library/Application Support/WiFiSentinel/.env`

The model identifier is left unchanged. Do not treat `gpt-6-luna` as verified for API use without checking the currently available OpenAI API model list.

## Validation performed in this environment
- Python syntax compilation passed for `main.py`, `core/catalog.py`, `core/assessment_engine.py`, and `core/nmap_runner.py`.
- `tests/test_nmap_runner.py`: 4 passed.
- Full test collection could not complete in this environment because `scapy` is not installed; no claim is made that the complete project suite passes.
