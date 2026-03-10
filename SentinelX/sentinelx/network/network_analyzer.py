"""
SentinelX – Network Traffic Analyzer
Analyzes parsed packets for threats and submits events to the detection engine.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sentinelx.core.engine import DetectionEngine, Event
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("network_analyzer")


class NetworkAnalyzer:
    """
    Analyzes network packet data for suspicious patterns:
    - Port scanning
    - SYN flood
    - ARP spoofing
    - Excessive DNS requests
    - Suspicious outbound connections
    """

    # Suspicious outbound ports commonly used by malware
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 12345}

    # Private / local IP prefixes to skip (not external threats)
    _LOCAL_PREFIXES = (
        "127.", "10.", "192.168.", "169.254.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "0.0.0.0", "255.255.255.255", "::", "fe80:",
    )

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.config = Config()
        self.db = DatabaseManager()

        self._lock = threading.Lock()

        # Tracking structures
        self._port_access: Dict[str, Set[int]] = defaultdict(set)  # ip -> set of ports
        self._port_access_times: Dict[str, List[datetime]] = defaultdict(list)
        self._syn_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._dns_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._arp_table: Dict[str, str] = {}  # ip -> mac mapping

        # Alert cooldown: ip -> last alert time (prevent alert flooding)
        self._alert_cooldown: Dict[str, datetime] = {}
        self._cooldown_seconds = 120  # 2 minutes between repeat alerts per IP

        # Traffic stats for GUI
        self._traffic_history: List[Dict[str, Any]] = []
        self._traffic_lock = threading.Lock()

        # Whitelist
        self._whitelist: Set[str] = set(self.config.get("network.whitelist_ips", []))

        # Start cleanup thread
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    @staticmethod
    def _is_local_ip(ip: str) -> bool:
        """Return True if ip is a private / local / broadcast address."""
        if not ip:
            return True
        return any(ip.startswith(p) for p in NetworkAnalyzer._LOCAL_PREFIXES)

    def _is_cooled_down(self, ip: str, now: datetime) -> bool:
        """Return True if we should suppress alerts for this IP (cooldown)."""
        last = self._alert_cooldown.get(ip)
        if last and (now - last).total_seconds() < self._cooldown_seconds:
            return True
        return False

    def analyze_packet(self, packet_data: Dict[str, Any]) -> None:
        """Analyze a parsed packet dict from the sniffer."""
        src_ip = packet_data.get("source_ip", "")
        dst_ip = packet_data.get("destination_ip", "")

        if src_ip in self._whitelist or dst_ip in self._whitelist:
            return

        # Skip analysis of traffic between local/private IPs
        if self._is_local_ip(src_ip) and self._is_local_ip(dst_ip):
            return

        protocol = packet_data.get("protocol", "")
        now = packet_data.get("timestamp", datetime.utcnow())

        # Record traffic for stats
        with self._traffic_lock:
            self._traffic_history.append({
                "timestamp": now,
                "protocol": protocol,
                "size": packet_data.get("packet_size", 0),
            })
            # Keep only last 5 minutes
            cutoff = now - timedelta(minutes=5)
            self._traffic_history = [t for t in self._traffic_history if t["timestamp"] > cutoff]

        # Store to database (sampled – every 10th packet)
        import random
        if random.random() < 0.1:
            try:
                self.db.add_network_event(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=packet_data.get("source_port"),
                    destination_port=packet_data.get("destination_port"),
                    protocol=protocol,
                    packet_size=packet_data.get("packet_size"),
                )
            except Exception as e:
                logger.debug("DB write error (sampled): %s", e)

        # === Detection Checks ===

        # 1. ARP Spoofing
        if packet_data.get("is_arp"):
            self._check_arp_spoof(packet_data)
            return

        # 2. Port Scan Detection  (only for external sources hitting well-known ports)
        dst_port = packet_data.get("destination_port")
        if protocol == "TCP" and dst_port and not self._is_local_ip(src_ip):
            # Only count well-known / service ports (< 10000) – ignore ephemeral reply ports
            if dst_port < 10000:
                self._check_port_scan(src_ip, dst_port, now)

        # 3. SYN Flood Detection  (only from external IPs)
        if protocol == "TCP" and packet_data.get("flags") and not self._is_local_ip(src_ip):
            flags = packet_data["flags"]
            if "S" in flags and "A" not in flags:
                self._check_syn_flood(src_ip, now)

        # 4. DNS Excessive Requests
        if protocol == "DNS":
            self._check_dns_excessive(src_ip, now, packet_data.get("dns_query", ""))

        # 5. Suspicious Outbound  (only meaningful for outbound to external IPs)
        if (
            packet_data.get("destination_port") in self.SUSPICIOUS_PORTS
            and not self._is_local_ip(dst_ip)
        ):
            self._check_suspicious_outbound(src_ip, dst_ip, packet_data["destination_port"], now)

    def _check_port_scan(self, src_ip: str, dst_port: int, now: datetime) -> None:
        threshold = self.config.get("network.port_scan_threshold", 15)
        window = self.config.get("network.port_scan_window", 10)
        cutoff = now - timedelta(seconds=window)

        with self._lock:
            # Prune timestamps outside the window
            self._port_access_times[src_ip].append(now)
            self._port_access_times[src_ip] = [
                t for t in self._port_access_times[src_ip] if t > cutoff
            ]

            # Only count ports observed within the current time window
            # (reset port set if all timestamps were pruned)
            if not self._port_access_times[src_ip]:
                self._port_access[src_ip].clear()
                return

            self._port_access[src_ip].add(dst_port)

            if len(self._port_access[src_ip]) >= threshold:
                if not self._is_cooled_down(src_ip, now):
                    self._alert_cooldown[src_ip] = now
                    self.engine.submit_event(Event(
                        event_type="same_ip_multiple_ports",
                        source=src_ip,
                        details={
                            "destination_port": dst_port,
                            "unique_ports": len(self._port_access[src_ip]),
                        },
                    ))
                # Reset to avoid repeated alerts
                self._port_access[src_ip].clear()

    def _check_syn_flood(self, src_ip: str, now: datetime) -> None:
        threshold = self.config.get("network.syn_flood_threshold", 100)
        window = self.config.get("network.syn_flood_window", 5)
        cutoff = now - timedelta(seconds=window)

        with self._lock:
            self._syn_counts[src_ip].append(now)
            self._syn_counts[src_ip] = [t for t in self._syn_counts[src_ip] if t > cutoff]

            if len(self._syn_counts[src_ip]) >= threshold:
                self.engine.submit_event(Event(
                    event_type="syn_flood",
                    source=src_ip,
                    details={"syn_count": len(self._syn_counts[src_ip])},
                ))
                self._syn_counts[src_ip].clear()

    def _check_arp_spoof(self, packet_data: Dict[str, Any]) -> None:
        if packet_data.get("arp_op") != 2:  # Only check ARP replies
            return

        ip = packet_data.get("arp_src_ip", "")
        mac = packet_data.get("arp_src_mac", "")

        with self._lock:
            if ip in self._arp_table:
                if self._arp_table[ip] != mac:
                    self.engine.submit_event(Event(
                        event_type="arp_spoof",
                        source=ip,
                        details={
                            "old_mac": self._arp_table[ip],
                            "new_mac": mac,
                        },
                    ))
                    logger.warning("ARP spoof: %s changed MAC %s -> %s", ip, self._arp_table[ip], mac)
            self._arp_table[ip] = mac

    def _check_dns_excessive(self, src_ip: str, now: datetime, query: str) -> None:
        threshold = self.config.get("network.dns_request_threshold", 50)
        window = self.config.get("network.dns_request_window", 10)
        cutoff = now - timedelta(seconds=window)

        with self._lock:
            self._dns_counts[src_ip].append(now)
            self._dns_counts[src_ip] = [t for t in self._dns_counts[src_ip] if t > cutoff]

            if len(self._dns_counts[src_ip]) >= threshold:
                self.engine.submit_event(Event(
                    event_type="excessive_dns",
                    source=src_ip,
                    details={"dns_count": len(self._dns_counts[src_ip]), "last_query": query},
                ))
                self._dns_counts[src_ip].clear()

    def _check_suspicious_outbound(self, src_ip: str, dst_ip: str, port: int, now: datetime) -> None:
        with self._lock:
            if self._is_cooled_down(dst_ip, now):
                return
            self._alert_cooldown[dst_ip] = now

        self.engine.submit_event(Event(
            event_type="suspicious_outbound",
            source=src_ip,
            destination=dst_ip,
            details={"destination_port": port},
        ))

    def get_traffic_stats(self) -> Dict[str, Any]:
        """Get current traffic statistics for the GUI."""
        with self._traffic_lock:
            now = datetime.utcnow()
            last_minute = [t for t in self._traffic_history if t["timestamp"] > now - timedelta(minutes=1)]

            proto_counts = defaultdict(int)
            total_bytes = 0
            for t in last_minute:
                proto_counts[t["protocol"]] += 1
                total_bytes += t.get("size", 0)

            return {
                "packets_per_minute": len(last_minute),
                "bytes_per_minute": total_bytes,
                "protocol_distribution": dict(proto_counts),
                "history_length": len(self._traffic_history),
            }

    def _cleanup_loop(self) -> None:
        """Periodically clean tracking structures."""
        while self._running:
            time.sleep(30)
            now = datetime.utcnow()
            cutoff_short = now - timedelta(seconds=30)
            cutoff_long = now - timedelta(minutes=5)

            with self._lock:
                for ip in list(self._port_access_times.keys()):
                    self._port_access_times[ip] = [
                        t for t in self._port_access_times[ip] if t > cutoff_short
                    ]
                    if not self._port_access_times[ip]:
                        del self._port_access_times[ip]
                        self._port_access.pop(ip, None)

                for ip in list(self._syn_counts.keys()):
                    self._syn_counts[ip] = [t for t in self._syn_counts[ip] if t > cutoff_short]
                    if not self._syn_counts[ip]:
                        del self._syn_counts[ip]

                for ip in list(self._dns_counts.keys()):
                    self._dns_counts[ip] = [t for t in self._dns_counts[ip] if t > cutoff_short]
                    if not self._dns_counts[ip]:
                        del self._dns_counts[ip]

    def stop(self) -> None:
        self._running = False
        logger.info("Network analyzer stopped")
