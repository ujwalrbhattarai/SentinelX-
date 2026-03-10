"""
SentinelX – Database Models
SQLAlchemy ORM models for all persistent data.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, Index, create_engine
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    alert_type = Column(String(64), nullable=False, index=True)  # network, host, file, process
    severity = Column(String(16), nullable=False, index=True)     # Low, Medium, High, Critical
    risk_score = Column(Integer, nullable=False, default=0)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(256), nullable=True)
    destination = Column(String(256), nullable=True)
    module = Column(String(64), nullable=True)
    acknowledged = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    forwarded = Column(Boolean, default=False)
    forwarded_to = Column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "destination": self.destination,
            "module": self.module,
            "acknowledged": self.acknowledged,
            "false_positive": self.false_positive,
            "forwarded": self.forwarded,
            "forwarded_to": self.forwarded_to,
        }


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)
    packet_size = Column(Integer, nullable=True)
    threat_type = Column(String(64), nullable=True)
    severity = Column(String(16), nullable=True)
    risk_score = Column(Integer, default=0)
    raw_summary = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
        }


class SystemEvent(Base):
    __tablename__ = "system_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_id = Column(Integer, nullable=False, index=True)
    event_source = Column(String(128), nullable=True)
    category = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    user = Column(String(128), nullable=True)
    severity = Column(String(16), nullable=True)
    risk_score = Column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_id": self.event_id,
            "event_source": self.event_source,
            "category": self.category,
            "description": self.description,
            "user": self.user,
            "severity": self.severity,
            "risk_score": self.risk_score,
        }


class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    file_path = Column(String(512), nullable=False)
    event_type = Column(String(32), nullable=False)  # created, modified, deleted
    old_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=True)
    severity = Column(String(16), nullable=True)
    risk_score = Column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "file_path": self.file_path,
            "event_type": self.event_type,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "severity": self.severity,
            "risk_score": self.risk_score,
        }


class ProcessEvent(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    pid = Column(Integer, nullable=False)
    name = Column(String(256), nullable=False, index=True)
    exe_path = Column(String(512), nullable=True)
    parent_pid = Column(Integer, nullable=True)
    parent_name = Column(String(256), nullable=True)
    cpu_percent = Column(Float, nullable=True)
    memory_mb = Column(Float, nullable=True)
    threat_type = Column(String(64), nullable=True)
    severity = Column(String(16), nullable=True)
    risk_score = Column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
        }


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(16), nullable=False, default="viewer")  # admin / viewer
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
