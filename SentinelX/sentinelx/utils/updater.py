"""
SentinelX – Update Checker & Version Management
Checks for application updates and manages version info.
"""

import json
import threading
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple
from urllib import request, error

from sentinelx.utils.logger import get_logger

logger = get_logger("updater")

# Current version
CURRENT_VERSION = "1.0.0"
VERSION_TUPLE = (1, 0, 0)

# Update check endpoint (placeholder – would be a real server in production)
UPDATE_URL = "https://api.sentinelx.io/version/latest"


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string like '1.2.3' into a tuple (1, 2, 3)."""
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0, 0, 0)


def compare_versions(current: str, latest: str) -> int:
    """
    Compare two version strings.
    Returns: -1 if current < latest, 0 if equal, 1 if current > latest.
    """
    c = parse_version(current)
    l = parse_version(latest)
    if c < l:
        return -1
    elif c > l:
        return 1
    return 0


class UpdateChecker:
    """Asynchronous update checker for SentinelX."""

    def __init__(self):
        self._latest_version: Optional[str] = None
        self._update_url: Optional[str] = None
        self._changelog: Optional[str] = None
        self._last_check: Optional[datetime] = None
        self._checking = False

    def check_for_updates(self, callback: Optional[Callable] = None) -> None:
        """
        Check for updates asynchronously.
        callback receives (update_available: bool, info: dict).
        """
        if self._checking:
            return

        self._checking = True

        def _check():
            try:
                result = self._do_check()
                if callback:
                    callback(result.get("update_available", False), result)
            except Exception as e:
                logger.debug("Update check failed: %s", e)
                if callback:
                    callback(False, {"error": str(e)})
            finally:
                self._checking = False

        thread = threading.Thread(target=_check, daemon=True, name="UpdateChecker")
        thread.start()

    def _do_check(self) -> Dict[str, Any]:
        """Perform the actual update check."""
        try:
            req = request.Request(
                UPDATE_URL,
                headers={"User-Agent": f"SentinelX/{CURRENT_VERSION}"},
            )
            with request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())

            self._latest_version = data.get("version", CURRENT_VERSION)
            self._update_url = data.get("download_url")
            self._changelog = data.get("changelog", "")
            self._last_check = datetime.utcnow()

            update_available = compare_versions(CURRENT_VERSION, self._latest_version) < 0

            result = {
                "update_available": update_available,
                "current_version": CURRENT_VERSION,
                "latest_version": self._latest_version,
                "download_url": self._update_url,
                "changelog": self._changelog,
            }

            if update_available:
                logger.info(
                    "Update available: %s -> %s",
                    CURRENT_VERSION,
                    self._latest_version,
                )
            else:
                logger.debug("SentinelX is up to date (v%s)", CURRENT_VERSION)

            return result

        except error.URLError:
            logger.debug("Cannot reach update server (offline or unavailable)")
            return {
                "update_available": False,
                "current_version": CURRENT_VERSION,
                "error": "Cannot reach update server",
            }
        except Exception as e:
            logger.debug("Update check error: %s", e)
            return {
                "update_available": False,
                "current_version": CURRENT_VERSION,
                "error": str(e),
            }

    @property
    def current_version(self) -> str:
        return CURRENT_VERSION

    @property
    def latest_version(self) -> Optional[str]:
        return self._latest_version

    @property
    def is_update_available(self) -> bool:
        if self._latest_version is None:
            return False
        return compare_versions(CURRENT_VERSION, self._latest_version) < 0


class LicenseValidator:
    """
    License validation system for Free vs Pro feature gating.
    In production, this would validate against a license server.
    """

    # Features available only in Pro edition
    PRO_FEATURES = {
        "pdf_reports",
        "threat_intelligence",
        "remote_agents",
        "api_access",
        "advanced_rules",
        "email_alerts",
    }

    def __init__(self):
        from sentinelx.utils.config import Config
        self.config = Config()

    @property
    def edition(self) -> str:
        return self.config.get("licensing.edition", "free")

    @property
    def is_pro(self) -> bool:
        return self.edition.lower() == "pro"

    def has_feature(self, feature: str) -> bool:
        """Check if a feature is available in the current edition."""
        if feature not in self.PRO_FEATURES:
            return True  # Free features are always available
        return self.is_pro

    def validate_license_key(self, key: str) -> Tuple[bool, str]:
        """
        Validate a license key.
        In production: would call a license server API.
        For now: simple format check.
        """
        if not key or len(key) < 16:
            return False, "Invalid license key format."

        parts = key.split("-")
        if len(parts) < 4:
            return False, "Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX"

        # In production: verify against server, check expiration, etc.
        # For now: accept any properly formatted key
        self.config.set("licensing.edition", "pro")
        self.config.set("licensing.license_key", key)
        logger.info("License activated: Pro edition")
        return True, "Pro license activated successfully!"

    def deactivate(self) -> None:
        """Deactivate license (revert to free)."""
        self.config.set("licensing.edition", "free")
        self.config.set("licensing.license_key", "")
        logger.info("License deactivated: reverted to Free edition")
