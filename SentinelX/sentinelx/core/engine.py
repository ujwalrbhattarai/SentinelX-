"""
SentinelX – Core Detection Engine
Continuously evaluates events against rules and generates alerts.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from sentinelx.core.rules import DEFAULT_RULES, Rule, Severity, get_rules_by_module
from sentinelx.core.threat_scoring import ThreatScorer, SEVERITY_SCORES
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("engine")


class Event:
    """Represents a raw detection event passed to the engine."""

    def __init__(
        self,
        event_type: str,
        source: str = "",
        destination: str = "",
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.event_type = event_type
        self.source = source
        self.destination = destination
        self.details = details or {}
        self.timestamp = timestamp or datetime.utcnow()


class DetectionEngine:
    """
    The core detection engine. Accepts events from monitoring modules,
    evaluates them against rules, and generates alerts.
    """

    _instance: Optional["DetectionEngine"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DetectionEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.config = Config()
        self.db = DatabaseManager()
        self.scorer = ThreatScorer()
        self._running = False

        # Event buffer: condition_key -> list of (timestamp, event)
        self._event_buffer: Dict[str, List[Tuple[datetime, Event]]] = defaultdict(list)
        self._buffer_lock = threading.Lock()

        # ── Per-IP rate tracking for DoS detection ──
        # condition -> { source_ip -> first_seen_datetime }
        self._ip_first_seen: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        # condition -> { source_ip -> last_alert_datetime }
        self._rate_alert_cooldown: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        self._rate_lock = threading.Lock()

        # Callbacks for GUI real-time updates
        self._alert_callbacks: List[Callable] = []

        # Collect rate-monitored rules once for fast lookup
        self._rate_rules = [r for r in DEFAULT_RULES if r.is_rate_monitored and r.enabled]

        logger.info("Detection engine initialized with %d rules (%d rate-monitored)",
                     len(DEFAULT_RULES), len(self._rate_rules))

    def register_alert_callback(self, callback: Callable) -> None:
        """Register a callback that fires when a new alert is created."""
        self._alert_callbacks.append(callback)

    def _notify_alert(self, alert_dict: dict) -> None:
        """Notify all registered callbacks of a new alert."""
        for cb in self._alert_callbacks:
            try:
                cb(alert_dict)
            except Exception as e:
                logger.error("Alert callback error: %s", e)

    def submit_event(self, event: Event) -> None:
        """Submit an event for evaluation against rules."""
        with self._buffer_lock:
            self._event_buffer[event.event_type].append((event.timestamp, event))

        # Immediately evaluate applicable rules
        self._evaluate_event(event)

    def _evaluate_event(self, event: Event) -> None:
        """Evaluate a single event against all matching NON-rate-monitored rules.
        Rate-monitored rules are handled by the 1-second polling loop instead.
        """
        for rule in DEFAULT_RULES:
            if not rule.enabled:
                continue
            if rule.condition != event.event_type:
                continue
            # Skip rate-monitored rules — they are checked by _check_rates()
            if rule.is_rate_monitored:
                continue

            if self._check_rule(rule, event):
                self._trigger_alert(rule, event)

    # ── Rate Monitor (1-second polling) ──────────────────────────

    def start_rate_monitor(self) -> None:
        """Start a daemon thread that checks per-IP request rates every second."""
        self._running = True

        def _monitor():
            while self._running:
                time.sleep(1)
                try:
                    self._check_rates()
                except Exception as e:
                    logger.error("Rate monitor error: %s", e)

        t = threading.Thread(target=_monitor, daemon=True, name="RateMonitor")
        t.start()
        logger.info("Rate monitor started (1-second polling, %d rate rules)", len(self._rate_rules))

    def _check_rates(self) -> None:
        """Check every rate-monitored rule against per-IP event counts in the last second."""
        now = datetime.utcnow()
        one_second_ago = now - timedelta(seconds=1)

        for rule in self._rate_rules:
            condition = rule.condition
            window_start = now - timedelta(seconds=rule.time_window)

            with self._buffer_lock:
                all_events = self._event_buffer.get(condition, [])
                # Events in the last 1 second (for rate counting)
                recent = [(ts, ev) for ts, ev in all_events if ts >= one_second_ago]
                # Events in the full time window (for activity tracking)
                in_window = [(ts, ev) for ts, ev in all_events if ts >= window_start]

            # Group last-second events by source IP for rate counting
            ip_counts: Dict[str, List[Event]] = defaultdict(list)
            for ts, ev in recent:
                ip_counts[ev.source or "unknown"].append(ev)

            # Also track which IPs are active in the broader window
            active_in_window: set = set()
            for ts, ev in in_window:
                active_in_window.add(ev.source or "unknown")

            for source_ip, events in ip_counts.items():
                count = len(events)

                # Track first-seen for adaptive decay
                with self._rate_lock:
                    if source_ip not in self._ip_first_seen[condition]:
                        self._ip_first_seen[condition][source_ip] = now
                    first_seen = self._ip_first_seen[condition][source_ip]

                elapsed = max(0.0, (now - first_seen).total_seconds())

                # Adaptive threshold: decays as the IP sustains traffic
                # Formula: threshold = max(min_rate, base_rate / (1 + decay * elapsed))
                effective_threshold = max(
                    rule.min_rate_threshold,
                    int(rule.rate_per_second / (1.0 + rule.decay_rate * elapsed)),
                )

                if count >= effective_threshold:
                    # Check cooldown — don't alert for same IP within cooldown window
                    with self._rate_lock:
                        last_alert = self._rate_alert_cooldown[condition].get(source_ip)
                        if last_alert and (now - last_alert).total_seconds() < rule.alert_cooldown:
                            continue
                        self._rate_alert_cooldown[condition][source_ip] = now

                    # Build a representative event for the alert
                    representative = events[0]
                    representative.details["rate_per_second"] = count
                    representative.details["effective_threshold"] = effective_threshold
                    representative.details["base_threshold"] = rule.rate_per_second
                    representative.details["elapsed_seconds"] = round(elapsed, 1)
                    representative.details["threshold_decay"] = f"{rule.rate_per_second} -> {effective_threshold}"

                    self._trigger_alert(rule, representative)
                    logger.warning(
                        "RATE ALERT: %s — %s sent %d req/s (threshold: %d, base: %d, elapsed: %.1fs)",
                        rule.name, source_ip, count, effective_threshold,
                        rule.rate_per_second, elapsed,
                    )

            # Clean up first-seen only for IPs no longer active in the full time window
            with self._rate_lock:
                stale = [
                    ip for ip in self._ip_first_seen[condition]
                    if ip not in active_in_window
                ]
                for ip in stale:
                    del self._ip_first_seen[condition][ip]
                    self._rate_alert_cooldown[condition].pop(ip, None)

    def _check_rule(self, rule: Rule, event: Event) -> bool:
        """Check if a rule's threshold has been met."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=rule.time_window)

        with self._buffer_lock:
            events_in_window = [
                (ts, ev)
                for ts, ev in self._event_buffer.get(rule.condition, [])
                if ts >= window_start
            ]

        # For threshold-1 rules, any matching event triggers
        if rule.threshold <= 1:
            return True

        # Group by source for per-source thresholds
        source_key = event.source or "unknown"
        source_events = [
            (ts, ev) for ts, ev in events_in_window if ev.source == source_key
        ]

        # Special condition: same_ip_multiple_ports
        if rule.condition == "same_ip_multiple_ports":
            ports = set()
            for ts, ev in source_events:
                port = ev.details.get("destination_port")
                if port:
                    ports.add(port)
            return len(ports) >= rule.threshold

        # Default: count-based threshold
        return len(source_events) >= rule.threshold

    def _trigger_alert(self, rule: Rule, event: Event) -> None:
        """Create an alert from a triggered rule."""
        severity_str = rule.severity.value if isinstance(rule.severity, Severity) else rule.severity

        # Build description
        description = rule.description
        if event.details:
            details_str = ", ".join(f"{k}={v}" for k, v in event.details.items())
            description += f" | Details: {details_str}"

        alert_data = {
            "alert_type": rule.module,
            "severity": severity_str,
            "risk_score": rule.risk_score,
            "title": rule.name,
            "description": description,
            "source": event.source or None,
            "destination": event.destination or None,
            "module": rule.module,
        }

        try:
            alert = self.db.add_alert(**alert_data)
            alert_dict = alert.to_dict()

            # Update threat score
            if event.source:
                self.scorer.add_score(event.source, severity_str, rule.name)

            logger.warning(
                "ALERT: [%s] %s — Source: %s — Score: %d",
                severity_str,
                rule.name,
                event.source,
                rule.risk_score,
            )

            self._notify_alert(alert_dict)

        except Exception as e:
            logger.error("Failed to create alert: %s", e)

    def cleanup_buffer(self, max_age_seconds: int = 300) -> None:
        """Remove stale events from the buffer."""
        cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
        with self._buffer_lock:
            for key in list(self._event_buffer.keys()):
                self._event_buffer[key] = [
                    (ts, ev) for ts, ev in self._event_buffer[key] if ts > cutoff
                ]
                if not self._event_buffer[key]:
                    del self._event_buffer[key]

    def start_cleanup_loop(self) -> None:
        """Start background buffer cleanup and rate monitoring."""
        self._running = True

        def _loop():
            while self._running:
                time.sleep(60)
                self.cleanup_buffer()

        t = threading.Thread(target=_loop, daemon=True, name="EngineCleanup")
        t.start()
        logger.info("Engine cleanup loop started")

        # Also start the 1-second rate monitor
        self.start_rate_monitor()

    def stop(self) -> None:
        self._running = False
        logger.info("Detection engine stopped")

    @property
    def threat_scorer(self) -> ThreatScorer:
        return self.scorer
