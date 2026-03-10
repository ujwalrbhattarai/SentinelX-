"""
SentinelX – Threat Scoring System
Aggregates and computes risk scores per IP / host activity.
"""

import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sentinelx.core.rules import Severity
from sentinelx.utils.logger import get_logger

logger = get_logger("threat_scoring")

SEVERITY_SCORES = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 70,
    Severity.CRITICAL: 100,
    "Low": 10,
    "Medium": 30,
    "High": 70,
    "Critical": 100,
}


class ThreatScorer:
    """Aggregates threat scores per entity (IP, hostname, user)."""

    def __init__(self):
        self._lock = threading.Lock()
        # entity -> list of (timestamp, score, description)
        self._scores: Dict[str, List[Tuple[datetime, int, str]]] = defaultdict(list)

    def add_score(self, entity: str, severity: str, description: str = "") -> int:
        """Add a score event for an entity. Returns new aggregate score."""
        score = SEVERITY_SCORES.get(severity, 10)
        now = datetime.utcnow()
        with self._lock:
            self._scores[entity].append((now, score, description))
            # Prune old entries (>24h)
            cutoff = now - timedelta(hours=24)
            self._scores[entity] = [
                (ts, sc, desc) for ts, sc, desc in self._scores[entity] if ts > cutoff
            ]
        total = self.get_score(entity)
        logger.debug("Entity %s score: %d (+%d for %s)", entity, total, score, description)
        return total

    def get_score(self, entity: str) -> int:
        """Get current aggregate score for an entity (capped at 1000)."""
        with self._lock:
            entries = self._scores.get(entity, [])
            total = sum(sc for _, sc, _ in entries)
        return min(total, 1000)

    def get_top_entities(self, limit: int = 10) -> List[Dict]:
        """Get top scored entities."""
        with self._lock:
            results = []
            for entity, entries in self._scores.items():
                total = min(sum(sc for _, sc, _ in entries), 1000)
                last_seen = max(ts for ts, _, _ in entries) if entries else None
                results.append({
                    "entity": entity,
                    "score": total,
                    "events": len(entries),
                    "last_seen": last_seen.isoformat() if last_seen else None,
                })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level label."""
        if score >= 200:
            return "Critical"
        elif score >= 100:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"

    def clear_entity(self, entity: str) -> None:
        with self._lock:
            self._scores.pop(entity, None)

    def clear_all(self) -> None:
        with self._lock:
            self._scores.clear()
