"""
SentinelX – Network Packet Sniffer
Captures live packets using scapy and feeds them to the detection engine.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set

from sentinelx.utils.logger import get_logger
from sentinelx.utils.config import Config

logger = get_logger("sniffer")

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, ARP, Ether, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not available – network sniffing disabled")


class PacketSniffer:
    """
    Captures network packets and provides parsed packet data
    to the network analyzer for threat detection.
    """

    def __init__(self):
        self.config = Config()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable] = []

        # Packet statistics
        self._stats = {
            "total_packets": 0,
            "tcp": 0,
            "udp": 0,
            "dns": 0,
            "icmp": 0,
            "arp": 0,
            "other": 0,
        }
        self._stats_lock = threading.Lock()

    def register_callback(self, callback: Callable) -> None:
        """Register a callback for each captured packet."""
        self._callbacks.append(callback)

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return self._stats.copy()

    def start(self) -> None:
        """Start packet capture in a background thread."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start sniffer: scapy not installed")
            return

        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True, name="PacketSniffer")
        self._thread.start()
        logger.info("Packet sniffer started")

    def stop(self) -> None:
        """Stop packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Packet sniffer stopped")

    def _capture_loop(self) -> None:
        """Main capture loop using scapy."""
        try:
            iface = self.config.get("network.interface", "auto")
            if iface == "auto":
                iface = None  # scapy default

            sniff(
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                iface=iface,
            )
        except PermissionError:
            logger.error("Permission denied – run as Administrator for packet capture")
        except Exception as e:
            logger.error("Sniffer error: %s", e)

    def _process_packet(self, packet) -> None:
        """Process a single captured packet."""
        try:
            parsed = self._parse_packet(packet)
            if parsed is None:
                return

            with self._stats_lock:
                self._stats["total_packets"] += 1
                proto = parsed.get("protocol", "other").lower()
                if proto in self._stats:
                    self._stats[proto] += 1
                else:
                    self._stats["other"] += 1

            for cb in self._callbacks:
                try:
                    cb(parsed)
                except Exception as e:
                    logger.error("Packet callback error: %s", e)

        except Exception as e:
            logger.error("Packet processing error: %s", e)

    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse a scapy packet into a structured dict."""
        result: Dict[str, Any] = {
            "timestamp": datetime.utcnow(),
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": "OTHER",
            "packet_size": len(packet),
            "flags": None,
            "dns_query": None,
            "is_arp": False,
            "arp_op": None,
            "arp_src_mac": None,
            "arp_src_ip": None,
        }

        # ARP layer
        if packet.haslayer(ARP):
            arp = packet[ARP]
            result["is_arp"] = True
            result["protocol"] = "ARP"
            result["arp_op"] = arp.op  # 1=request, 2=reply
            result["arp_src_mac"] = arp.hwsrc
            result["arp_src_ip"] = arp.psrc
            result["source_ip"] = arp.psrc
            result["destination_ip"] = arp.pdst
            return result

        # IP layer
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        result["source_ip"] = ip.src
        result["destination_ip"] = ip.dst

        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result["protocol"] = "TCP"
            result["source_port"] = tcp.sport
            result["destination_port"] = tcp.dport
            result["flags"] = str(tcp.flags)

        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            result["protocol"] = "UDP"
            result["source_port"] = udp.sport
            result["destination_port"] = udp.dport

            # DNS
            if packet.haslayer(DNS):
                result["protocol"] = "DNS"
                dns = packet[DNS]
                if dns.qr == 0 and dns.qd:
                    result["dns_query"] = dns.qd.qname.decode(errors="ignore")

        # ICMP
        elif packet.haslayer(ICMP):
            result["protocol"] = "ICMP"

        return result
