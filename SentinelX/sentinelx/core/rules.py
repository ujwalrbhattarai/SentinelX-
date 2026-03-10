"""
SentinelX – Rule-Based Detection Engine Rules
Defines detection rules and their evaluation logic.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Rule:
    """A detection rule evaluated by the engine."""

    name: str
    condition: str  # Identifier for the condition to check
    threshold: int  # Number of events to trigger
    time_window: int  # Seconds
    severity: Severity
    description: str = ""
    module: str = ""  # network, host, file, process
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    # ── Per-second rate monitoring (DoS/flood rules) ──
    rate_per_second: int = 0        # Base requests/sec threshold (0 = not rate-monitored)
    min_rate_threshold: int = 0     # Floor after adaptive decay
    decay_rate: float = 0.0         # How fast threshold decreases per second of sustained traffic
    alert_cooldown: int = 5         # Seconds between repeated alerts for same IP

    @property
    def is_rate_monitored(self) -> bool:
        return self.rate_per_second > 0

    @property
    def risk_score(self) -> int:
        scores = {
            Severity.LOW: 10,
            Severity.MEDIUM: 30,
            Severity.HIGH: 70,
            Severity.CRITICAL: 100,
        }
        return scores.get(self.severity, 0)


# ── Built-in Detection Rules ───────────────────────────────────

DEFAULT_RULES: List[Rule] = [
    # === Network Rules ===
    Rule(
        name="Port Scan Detected",
        condition="same_ip_multiple_ports",
        threshold=15,
        time_window=10,
        severity=Severity.HIGH,
        description="Single external IP accessing 15+ distinct service ports within 10 seconds.",
        module="network",
        tags=["reconnaissance", "port_scan"],
    ),
    Rule(
        name="ARP Spoofing Detected",
        condition="arp_spoof",
        threshold=1,
        time_window=30,
        severity=Severity.CRITICAL,
        description="ARP reply with changed MAC address for a known IP.",
        module="network",
        tags=["mitm", "arp_spoof"],
    ),
    Rule(
        name="Excessive DNS Requests",
        condition="excessive_dns",
        threshold=50,
        time_window=10,
        severity=Severity.MEDIUM,
        description="50+ DNS requests from a single host in 10 seconds.",
        module="network",
        tags=["exfiltration", "dns_tunnel"],
    ),
    Rule(
        name="Suspicious Outbound Connection",
        condition="suspicious_outbound",
        threshold=3,
        time_window=120,
        severity=Severity.HIGH,
        description="Multiple connections to known malicious ports on external IPs.",
        module="network",
        tags=["c2", "outbound"],
    ),

    # === Event Log Rules ===
    Rule(
        name="Brute Force Login Attempt",
        condition="failed_logins",
        threshold=5,
        time_window=60,
        severity=Severity.HIGH,
        description="5+ failed logins within 60 seconds.",
        module="host",
        tags=["brute_force", "authentication"],
    ),
    Rule(
        name="Suspicious User Account Created",
        condition="user_created",
        threshold=1,
        time_window=300,
        severity=Severity.HIGH,
        description="New user account created on the system.",
        module="host",
        tags=["persistence", "user_creation"],
    ),
    Rule(
        name="Admin Privilege Escalation",
        condition="admin_privilege",
        threshold=1,
        time_window=60,
        severity=Severity.HIGH,
        description="Special privileges assigned to a new logon.",
        module="host",
        tags=["privilege_escalation"],
    ),
    Rule(
        name="Suspicious PowerShell Execution",
        condition="suspicious_powershell",
        threshold=1,
        time_window=60,
        severity=Severity.HIGH,
        description="PowerShell with suspicious parameters detected.",
        module="host",
        tags=["execution", "powershell"],
    ),

    # === File Integrity Rules ===
    Rule(
        name="Ransomware Behavior Detected",
        condition="mass_file_modification",
        threshold=50,
        time_window=30,
        severity=Severity.CRITICAL,
        description="50+ file changes within 30 seconds – possible ransomware.",
        module="file",
        tags=["ransomware", "mass_modification"],
    ),
    Rule(
        name="Protected File Modified",
        condition="file_modified",
        threshold=1,
        time_window=60,
        severity=Severity.MEDIUM,
        description="A monitored file was modified.",
        module="file",
        tags=["integrity", "modification"],
    ),
    Rule(
        name="Protected File Deleted",
        condition="file_deleted",
        threshold=1,
        time_window=60,
        severity=Severity.HIGH,
        description="A monitored file was deleted.",
        module="file",
        tags=["integrity", "deletion"],
    ),

    # === Process Rules ===
    Rule(
        name="High CPU Usage Sustained",
        condition="high_cpu",
        threshold=1,
        time_window=30,
        severity=Severity.MEDIUM,
        description="Process consuming >80% CPU for 30+ seconds.",
        module="process",
        tags=["resource_abuse", "cryptominer"],
    ),
    Rule(
        name="Suspicious Process Chain",
        condition="suspicious_process_chain",
        threshold=1,
        time_window=60,
        severity=Severity.HIGH,
        description="Suspicious parent-child process relationship detected.",
        module="process",
        tags=["execution", "reverse_shell"],
    ),
    Rule(
        name="Reverse Shell Pattern",
        condition="reverse_shell",
        threshold=1,
        time_window=60,
        severity=Severity.CRITICAL,
        description="Potential reverse shell process pattern.",
        module="process",
        tags=["reverse_shell", "c2"],
    ),

    # === DoS Detection Rules (rate-monitored: checked every 1 second) ===
    Rule(
        name="DoS Attack Detected",
        condition="dos_flood",
        threshold=500,
        time_window=10,
        severity=Severity.CRITICAL,
        description="High packet rate from a single source — possible DoS attack. "
                    "Threshold adapts: sustained traffic triggers at progressively lower rates.",
        module="network",
        tags=["dos", "flood", "availability"],
        rate_per_second=100,       # Initial: 100 req/s to trigger
        min_rate_threshold=15,     # After sustained attack, even 15/s triggers
        decay_rate=0.15,           # Threshold halves in ~7 seconds of activity
        alert_cooldown=5,
    ),
    Rule(
        name="HTTP Flood Detected",
        condition="http_flood",
        threshold=200,
        time_window=15,
        severity=Severity.CRITICAL,
        description="High HTTP request rate from a single source — possible application-layer flood. "
                    "Threshold adapts: sustained traffic triggers at progressively lower rates.",
        module="network",
        tags=["dos", "http_flood", "availability"],
        rate_per_second=50,        # Initial: 50 req/s to trigger
        min_rate_threshold=8,      # After sustained attack, even 8/s triggers
        decay_rate=0.12,           # Slightly slower decay for HTTP
        alert_cooldown=5,
    ),
    Rule(
        name="SYN Flood Detected",
        condition="syn_flood",
        threshold=100,
        time_window=5,
        severity=Severity.CRITICAL,
        description="High SYN packet rate from a single source — possible SYN flood. "
                    "Threshold adapts over sustained attack duration.",
        module="network",
        tags=["dos", "syn_flood", "availability"],
        rate_per_second=50,
        min_rate_threshold=10,
        decay_rate=0.15,
        alert_cooldown=5,
    ),
]


def get_rules_by_module(module: str) -> List[Rule]:
    """Get all enabled rules for a specific module."""
    return [r for r in DEFAULT_RULES if r.module == module and r.enabled]


def get_rule_by_name(name: str) -> Optional[Rule]:
    for r in DEFAULT_RULES:
        if r.name == name:
            return r
    return None
