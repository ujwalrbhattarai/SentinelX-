"""
SentinelX – Configuration Manager
Handles loading, saving, and encrypting application configuration.
"""

import json
import os
import base64
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet

# Default application directories
APP_DIR = Path(os.environ.get("APPDATA", ".")) / "SentinelX"
CONFIG_DIR = APP_DIR / "config"
DATA_DIR = APP_DIR / "data"
LOG_DIR = APP_DIR / "logs"
DB_DIR = APP_DIR / "db"
REPORT_DIR = APP_DIR / "reports"

for d in (APP_DIR, CONFIG_DIR, DATA_DIR, LOG_DIR, DB_DIR, REPORT_DIR):
    d.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = CONFIG_DIR / "sentinelx.conf"
KEY_FILE = CONFIG_DIR / ".keyfile"

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0.0",
    "modules": {
        "network_monitor": True,
        "event_log_monitor": True,
        "file_integrity_monitor": True,
        "process_monitor": True,
    },
    "network": {
        "enabled": True,
        "interface": "auto",
        "port_scan_threshold": 15,
        "port_scan_window": 10,
        "syn_flood_threshold": 100,
        "syn_flood_window": 5,
        "dns_request_threshold": 50,
        "dns_request_window": 10,
        "whitelist_ips": [],
    },
    "event_log": {
        "enabled": True,
        "failed_login_threshold": 5,
        "failed_login_window": 60,
        "monitored_event_ids": [4625, 4720, 4688, 4672],
    },
    "file_integrity": {
        "enabled": True,
        "monitored_directories": [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32\\drivers\\etc"),
        ],
        "ransomware_threshold": 50,
        "ransomware_window": 30,
        "baseline_file": str(DATA_DIR / "file_baseline.json"),
    },
    "process_monitor": {
        "enabled": True,
        "cpu_threshold": 80,
        "cpu_sustained_seconds": 30,
        "suspicious_patterns": [
            "powershell.exe->cmd.exe",
            "cmd.exe->powershell.exe",
            "svchost.exe->cmd.exe",
        ],
    },
    "alerting": {
        "severity_scores": {
            "Low": 10,
            "Medium": 30,
            "High": 70,
            "Critical": 100,
        },
        "notification_popup": True,
        "notification_sound": True,
    },
    "database": {
        "path": str(DB_DIR / "sentinelx.db"),
    },
    "gui": {
        "theme": "dark",
        "refresh_interval_ms": 2000,
    },
    "licensing": {
        "edition": "free",
        "license_key": "",
        "features_pro": [
            "pdf_reports",
            "threat_intelligence",
            "remote_agents",
            "api_access",
        ],
    },
    "auto_start": False,
}


def _get_or_create_key() -> bytes:
    """Get or create encryption key for config file protection."""
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key


def _encrypt(data: str) -> str:
    key = _get_or_create_key()
    f = Fernet(key)
    return base64.b64encode(f.encrypt(data.encode())).decode()


def _decrypt(data: str) -> str:
    key = _get_or_create_key()
    f = Fernet(key)
    return f.decrypt(base64.b64decode(data.encode())).decode()


class Config:
    """Thread-safe singleton configuration manager."""

    _instance: Optional["Config"] = None
    _data: Dict[str, Any] = {}

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        """Load configuration from encrypted file, or create default."""
        if CONFIG_FILE.exists():
            try:
                raw = CONFIG_FILE.read_text(encoding="utf-8")
                decrypted = _decrypt(raw)
                self._data = json.loads(decrypted)
                # Merge any new default keys
                self._data = self._deep_merge(DEFAULT_CONFIG, self._data)
            except Exception:
                self._data = DEFAULT_CONFIG.copy()
                self.save()
        else:
            self._data = DEFAULT_CONFIG.copy()
            self.save()

    @staticmethod
    def _deep_merge(default: dict, override: dict) -> dict:
        """Deep merge override into default, keeping all default keys."""
        result = default.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def save(self) -> None:
        """Save configuration to encrypted file."""
        raw = json.dumps(self._data, indent=2)
        encrypted = _encrypt(raw)
        CONFIG_FILE.write_text(encrypted, encoding="utf-8")

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get config value by dot-separated path (e.g. 'network.enabled')."""
        keys = key_path.split(".")
        val = self._data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
            if val is None:
                return default
        return val

    def set(self, key_path: str, value: Any) -> None:
        """Set config value by dot-separated path."""
        keys = key_path.split(".")
        d = self._data
        for k in keys[:-1]:
            if k not in d or not isinstance(d[k], dict):
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value
        self.save()

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def reset(self) -> None:
        """Reset to default configuration."""
        self._data = DEFAULT_CONFIG.copy()
        self.save()
