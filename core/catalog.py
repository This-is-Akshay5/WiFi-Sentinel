"""Security test catalog.

Every entry declares how it can actually be executed. A test either runs on
the local host using supported OS facilities or is blocked with an explicit
reason. Nothing in this
file fabricates a result and nothing here can widen the declared assessment
scope.

Fields
------
``id``             stable identifier used by the UI and the execution log
``name``           operator-facing label
``category``       one of CATEGORY_ORDER
``purpose``        what the test establishes
``prerequisites``  what must be true before the test is runnable
``execution_path`` ``local`` (supported host OS)
``scope_requirement`` ``none`` / ``network`` / ``wireless``
``evidence_type``  evidence row type produced on success
``findings``       True when the runner can raise evidence-linked findings
``active``         True when the test transmits or injects frames
"""

CATEGORY_ORDER = (
    "Wireless Security",
    "Network Discovery",
    "Traffic Analysis",
    "Authentication",
    "Network Security",
)

TEST_CATALOG = (
    {
        "id": "wifi_discovery",
        "name": "Nearby wireless network scan",
        "category": "Wireless Security",
        "purpose": "Enumerate networks returned by the host WLAN scan, including BSSID, channel, signal and security fields when exposed.",
        "prerequisites": ["Host WLAN service or scan utility available", "Wireless adapter present and enabled", "OS privacy permission where required"],
        "execution_path": "local",
        "scope_requirement": "wireless",
        "evidence_type": "wireless_scan",
        "findings": False,
        "active": False,
    },
    {
        "id": "connected_profile_audit",
        "name": "Connected network profile audit",
        "category": "Wireless Security",
        "purpose": "Audit the association the host is actually using: authentication, cipher, radio type and signal.",
        "prerequisites": ["Host associated to a WLAN"],
        "execution_path": "local",
        "scope_requirement": "wireless",
        "evidence_type": "wireless_observation",
        "findings": True,
        "active": False,
    },
    {
        "id": "open_authentication_scan",
        "name": "Nearby open / legacy network scan",
        "category": "Authentication",
        "purpose": "Check every visible BSSID for open authentication or legacy WEP/TKIP protection.",
        "prerequisites": ["Host WLAN service or scan utility available", "OS privacy permission where required"],
        "execution_path": "local",
        "scope_requirement": "wireless",
        "evidence_type": "wireless_scan",
        "findings": True,
        "active": False,
    },
    {
        "id": "channel_congestion",
        "name": "Channel congestion observation",
        "category": "Wireless Security",
        "purpose": "Derive radio crowding per channel from observed network counts to support a channel plan.",
        "prerequisites": ["A non-empty nearby BSSID observation set"],
        "execution_path": "local",
        "scope_requirement": "wireless",
        "evidence_type": "derived_analysis",
        "findings": True,
        "active": False,
    },
    {
        "id": "rogue_bssid_check",
        "name": "Duplicate-SSID BSSID check",
        "category": "Network Security",
        "purpose": "Identify SSIDs broadcast by more than one BSSID so unknown radios can be validated against the AP inventory.",
        "prerequisites": ["A non-empty nearby BSSID observation set"],
        "execution_path": "local",
        "scope_requirement": "wireless",
        "evidence_type": "derived_analysis",
        "findings": True,
        "active": False,
    },
    {
        "id": "device_discovery",
        "name": "Local neighbor device discovery",
        "category": "Network Discovery",
        "purpose": "Read the local neighbor cache for IP, MAC, neighbor state and reverse-DNS hostname.",
        "prerequisites": ["Host attached to a network"],
        "execution_path": "local",
        "scope_requirement": "network",
        "evidence_type": "device_inventory",
        "findings": True,
        "active": False,
    },
    {
        "id": "port_assessment",
        "name": "TCP connect port assessment",
        "category": "Network Discovery",
        "purpose": "TCP connect to an explicitly requested port list on one in-scope host and record the real connect result and latency.",
        "prerequisites": ["Declared network scope", "An in-scope target host"],
        "execution_path": "local",
        "scope_requirement": "network",
        "evidence_type": "test_result",
        "findings": True,
        "active": True,
    },
    {
        "id": "nmap_scan",
        "name": "Nmap host and service assessment",
        "category": "Network Discovery",
        "purpose": "Run a bounded TCP connect and light service-version scan against one literal IP inside the declared network scope.",
        "prerequisites": ["Recorded assessment authorization", "Declared CIDR or exact IP scope", "Nmap installed"],
        "execution_path": "local",
        "scope_requirement": "network",
        "evidence_type": "nmap_scan",
        "findings": True,
        "active": True,
    },
    {
        "id": "traceroute",
        "name": "Scoped path trace",
        "category": "Network Discovery",
        "purpose": "Record the OS path trace to an in-scope host to show where traffic is actually routed.",
        "prerequisites": ["Declared network scope", "An in-scope target host"],
        "execution_path": "local",
        "scope_requirement": "network",
        "evidence_type": "test_result",
        "findings": False,
        "active": True,
    },
    {
        "id": "gateway_exposure",
        "name": "Gateway TCP exposure",
        "category": "Network Security",
        "purpose": "Probe the observed default gateway on a fixed management port list, in scope only, and record open services.",
        "prerequisites": ["Declared network scope", "A default gateway observed by the OS"],
        "execution_path": "local",
        "scope_requirement": "network",
        "evidence_type": "test_result",
        "findings": True,
        "active": True,
    },
    {
        "id": "association_dataset_analysis",
        "name": "Research dataset association analysis",
        "category": "Traffic Analysis",
        "purpose": "Profile the supplied association/disassociation corpus: record mix, device distribution and time range.",
        "prerequisites": ["Research dataset present on disk"],
        "execution_path": "local",
        "scope_requirement": "none",
        "evidence_type": "research_dataset",
        "findings": True,
        "active": False,
    },
    {
        "id": "disassociation_detection",
        "name": "Disassociation burst detection",
        "category": "Traffic Analysis",
        "purpose": "Apply a deterministic rule to the research corpus and list the windows that satisfy it.",
        "prerequisites": ["Research dataset present on disk"],
        "execution_path": "local",
        "scope_requirement": "none",
        "evidence_type": "research_dataset",
        "findings": True,
        "active": False,
    },

)

BY_ID = {test["id"]: test for test in TEST_CATALOG}


def get(test_id):
    return BY_ID.get(test_id)


def categories():
    """Catalog grouped by category, preserving :data:`CATEGORY_ORDER`."""
    grouped = []
    for category in CATEGORY_ORDER:
        tests = [dict(t) for t in TEST_CATALOG if t["category"] == category]
        if tests:
            grouped.append({"category": category, "tests": tests})
    return grouped


def requirements():
    """Host capabilities the catalog depends on, for the preflight panel."""
    return {
        "local": sorted({t["id"] for t in TEST_CATALOG if t["execution_path"] == "local"}),
        "network_scope_required": sorted({t["id"] for t in TEST_CATALOG if t["scope_requirement"] == "network"}),
        "wireless_scope_required": sorted({t["id"] for t in TEST_CATALOG if t["scope_requirement"] == "wireless"}),
        "active_tests": sorted({t["id"] for t in TEST_CATALOG if t["active"]}),
    }
