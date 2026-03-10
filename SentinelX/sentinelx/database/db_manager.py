"""
SentinelX – Database Manager
Handles database initialization, sessions, and CRUD operations.
"""

import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type

from sqlalchemy import create_engine, func, and_, desc
from sqlalchemy.orm import sessionmaker, Session

from sentinelx.database.models import (
    Base, Alert, NetworkEvent, SystemEvent, FileEvent, ProcessEvent, Setting, User
)
from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("database")


class DatabaseManager:
    """Thread-safe singleton database manager."""

    _instance: Optional["DatabaseManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DatabaseManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        config = Config()
        db_path = config.get("database.path")
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self._SessionFactory = sessionmaker(bind=self.engine)
        self._initialized = True
        logger.info("Database initialized at %s", db_path)

    def session(self) -> Session:
        """Create a new session."""
        return self._SessionFactory()

    # ── Alert CRUD ──────────────────────────────────────────

    def add_alert(self, **kwargs) -> Alert:
        with self.session() as s:
            alert = Alert(**kwargs)
            s.add(alert)
            s.commit()
            s.refresh(alert)
            logger.debug("Alert created: %s [%s]", alert.title, alert.severity)
            return alert

    def get_new_critical_alerts(self, after_id: int) -> List[dict]:
        """Return Critical/High alerts plus suspicious-IP alerts with id > after_id."""
        with self.session() as s:
            results = (
                s.query(Alert)
                .filter(Alert.id > after_id)
                .filter(
                    Alert.severity.in_(["Critical", "High"])
                    | Alert.title.like("%Suspicious%")
                    | Alert.title.like("%Port Scan%")
                    | Alert.title.like("%ARP Spoof%")
                )
                .order_by(Alert.id)
                .limit(5)
                .all()
            )
            return [a.to_dict() for a in results]

    def get_max_alert_id(self) -> int:
        """Return the highest alert ID in the database."""
        with self.session() as s:
            result = s.query(func.max(Alert.id)).scalar()
            return result or 0

    def get_alerts(
        self,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 500,
        search: Optional[str] = None,
    ) -> List[dict]:
        with self.session() as s:
            q = s.query(Alert)
            if severity:
                q = q.filter(Alert.severity == severity)
            if alert_type:
                q = q.filter(Alert.alert_type == alert_type)
            if since:
                q = q.filter(Alert.timestamp >= since)
            if until:
                q = q.filter(Alert.timestamp <= until)
            if search:
                pattern = f"%{search}%"
                q = q.filter(
                    (Alert.title.like(pattern))
                    | (Alert.description.like(pattern))
                    | (Alert.source.like(pattern))
                )
            results = q.order_by(desc(Alert.timestamp)).limit(limit).all()
            return [a.to_dict() for a in results]

    def get_alert_by_id(self, alert_id: int) -> Optional[dict]:
        with self.session() as s:
            alert = s.query(Alert).get(alert_id)
            return alert.to_dict() if alert else None

    def acknowledge_alert(self, alert_id: int) -> None:
        with self.session() as s:
            alert = s.query(Alert).get(alert_id)
            if alert:
                alert.acknowledged = True
                s.commit()

    def mark_false_positive(self, alert_id: int) -> None:
        with self.session() as s:
            alert = s.query(Alert).get(alert_id)
            if alert:
                alert.false_positive = True
                s.commit()

    def forward_alert(self, alert_id: int, department: str) -> None:
        with self.session() as s:
            alert = s.query(Alert).get(alert_id)
            if alert:
                alert.forwarded = True
                alert.forwarded_to = department
                s.commit()

    # ── Network Events ──────────────────────────────────────

    def add_network_event(self, **kwargs) -> NetworkEvent:
        with self.session() as s:
            event = NetworkEvent(**kwargs)
            s.add(event)
            s.commit()
            s.refresh(event)
            return event

    def get_network_events(self, since: Optional[datetime] = None, limit: int = 500) -> List[dict]:
        with self.session() as s:
            q = s.query(NetworkEvent)
            if since:
                q = q.filter(NetworkEvent.timestamp >= since)
            return [e.to_dict() for e in q.order_by(desc(NetworkEvent.timestamp)).limit(limit).all()]

    # ── System Events ───────────────────────────────────────

    def add_system_event(self, **kwargs) -> SystemEvent:
        with self.session() as s:
            event = SystemEvent(**kwargs)
            s.add(event)
            s.commit()
            s.refresh(event)
            return event

    def get_system_events(self, since: Optional[datetime] = None, limit: int = 500) -> List[dict]:
        with self.session() as s:
            q = s.query(SystemEvent)
            if since:
                q = q.filter(SystemEvent.timestamp >= since)
            return [e.to_dict() for e in q.order_by(desc(SystemEvent.timestamp)).limit(limit).all()]

    # ── File Events ─────────────────────────────────────────

    def add_file_event(self, **kwargs) -> FileEvent:
        with self.session() as s:
            event = FileEvent(**kwargs)
            s.add(event)
            s.commit()
            s.refresh(event)
            return event

    def get_file_events(self, since: Optional[datetime] = None, limit: int = 500) -> List[dict]:
        with self.session() as s:
            q = s.query(FileEvent)
            if since:
                q = q.filter(FileEvent.timestamp >= since)
            return [e.to_dict() for e in q.order_by(desc(FileEvent.timestamp)).limit(limit).all()]

    # ── Process Events ──────────────────────────────────────

    def add_process_event(self, **kwargs) -> ProcessEvent:
        with self.session() as s:
            event = ProcessEvent(**kwargs)
            s.add(event)
            s.commit()
            s.refresh(event)
            return event

    def get_process_events(self, since: Optional[datetime] = None, limit: int = 500) -> List[dict]:
        with self.session() as s:
            q = s.query(ProcessEvent)
            if since:
                q = q.filter(ProcessEvent.timestamp >= since)
            return [e.to_dict() for e in q.order_by(desc(ProcessEvent.timestamp)).limit(limit).all()]

    # ── Statistics ──────────────────────────────────────────

    def get_alert_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics for the dashboard."""
        since = datetime.utcnow() - timedelta(hours=hours)
        with self.session() as s:
            total = s.query(func.count(Alert.id)).filter(Alert.timestamp >= since).scalar() or 0
            critical = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.severity == "Critical"))
                .scalar()
                or 0
            )
            high = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.severity == "High"))
                .scalar()
                or 0
            )
            medium = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.severity == "Medium"))
                .scalar()
                or 0
            )
            low = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.severity == "Low"))
                .scalar()
                or 0
            )

            acknowledged = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.acknowledged == True))
                .scalar()
                or 0
            )
            false_positive = (
                s.query(func.count(Alert.id))
                .filter(and_(Alert.timestamp >= since, Alert.false_positive == True))
                .scalar()
                or 0
            )
            unacknowledged = total - acknowledged

            # Top suspicious IPs
            top_ips = (
                s.query(Alert.source, func.count(Alert.id).label("cnt"))
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .group_by(Alert.source)
                .order_by(desc("cnt"))
                .limit(10)
                .all()
            )

            return {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "acknowledged": acknowledged,
                "false_positive": false_positive,
                "unacknowledged": unacknowledged,
                "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            }

    def get_alert_timeline(self, since: Optional[datetime] = None, until: Optional[datetime] = None, bucket_minutes: int = 30) -> List[dict]:
        """Get alert counts bucketed by time for charting, for a custom time window."""
        if since is None:
            since = datetime.utcnow() - timedelta(hours=24)
        with self.session() as s:
            q = s.query(Alert.timestamp, Alert.severity).filter(Alert.timestamp >= since)
            if until:
                q = q.filter(Alert.timestamp <= until)
            alerts = q.order_by(Alert.timestamp).all()

        buckets: Dict[str, Dict[str, int]] = {}
        for ts, sev in alerts:
            bucket_key = ts.strftime("%Y-%m-%d %H:") + str((ts.minute // bucket_minutes) * bucket_minutes).zfill(2)
            if bucket_key not in buckets:
                buckets[bucket_key] = {"time": bucket_key, "Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            if sev in buckets[bucket_key]:
                buckets[bucket_key][sev] += 1
        return list(buckets.values())

    # ── User management ─────────────────────────────────────

    def add_user(self, username: str, password_hash: str, role: str = "viewer") -> User:
        with self.session() as s:
            user = User(username=username, password_hash=password_hash, role=role)
            s.add(user)
            s.commit()
            s.refresh(user)
            return user

    def get_user(self, username: str) -> Optional[User]:
        with self.session() as s:
            return s.query(User).filter(User.username == username).first()

    def update_last_login(self, username: str) -> None:
        with self.session() as s:
            user = s.query(User).filter(User.username == username).first()
            if user:
                user.last_login = datetime.utcnow()
                s.commit()

    # ── IP Analytics ────────────────────────────────────────

    def get_ip_analytics(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive IP analytics for the IP Analytics view."""
        since = datetime.utcnow() - timedelta(hours=hours)
        with self.session() as s:
            # Top source IPs by alert count
            top_sources = (
                s.query(Alert.source, func.count(Alert.id).label("cnt"))
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .group_by(Alert.source)
                .order_by(desc("cnt"))
                .limit(20)
                .all()
            )

            # Top destination IPs by alert count
            top_destinations = (
                s.query(Alert.destination, func.count(Alert.id).label("cnt"))
                .filter(and_(Alert.timestamp >= since, Alert.destination.isnot(None)))
                .group_by(Alert.destination)
                .order_by(desc("cnt"))
                .limit(20)
                .all()
            )

            # Per-IP severity breakdown
            ip_severity = (
                s.query(Alert.source, Alert.severity, func.count(Alert.id).label("cnt"))
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .group_by(Alert.source, Alert.severity)
                .all()
            )

            # Per-IP alert type breakdown
            ip_types = (
                s.query(Alert.source, Alert.alert_type, func.count(Alert.id).label("cnt"))
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .group_by(Alert.source, Alert.alert_type)
                .all()
            )

            # Per-IP max risk score
            ip_max_risk = (
                s.query(Alert.source, func.max(Alert.risk_score).label("max_risk"))
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .group_by(Alert.source)
                .all()
            )

            # All alerts for detail table
            all_alerts = (
                s.query(Alert)
                .filter(and_(Alert.timestamp >= since, Alert.source.isnot(None)))
                .order_by(desc(Alert.timestamp))
                .limit(500)
                .all()
            )

            # Build severity map: {ip: {Critical: n, High: n, ...}}
            sev_map: Dict[str, Dict[str, int]] = {}
            for ip, sev, cnt in ip_severity:
                sev_map.setdefault(ip, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
                sev_map[ip][sev] = cnt

            type_map: Dict[str, Dict[str, int]] = {}
            for ip, atype, cnt in ip_types:
                type_map.setdefault(ip, {})
                type_map[ip][atype] = cnt

            risk_map = {ip: score for ip, score in ip_max_risk}

            return {
                "top_sources": [{"ip": ip, "count": cnt} for ip, cnt in top_sources],
                "top_destinations": [{"ip": ip, "count": cnt} for ip, cnt in top_destinations],
                "severity_map": sev_map,
                "type_map": type_map,
                "risk_map": risk_map,
                "alerts": [a.to_dict() for a in all_alerts],
            }
