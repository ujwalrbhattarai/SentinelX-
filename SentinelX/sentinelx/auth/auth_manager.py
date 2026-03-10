"""
SentinelX – Authentication System
Role-based local authentication with bcrypt password hashing.
"""

import threading
from datetime import datetime
from typing import Optional, Tuple

import bcrypt

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.logger import get_logger

logger = get_logger("auth")


class AuthManager:
    """
    Local authentication manager.
    Roles: 'admin' (full access) and 'viewer' (read-only).
    """

    _instance: Optional["AuthManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "AuthManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.db = DatabaseManager()
        self._current_user: Optional[str] = None
        self._current_role: Optional[str] = None
        self._ensure_default_admin()

    def _ensure_default_admin(self) -> None:
        """Create default admin account if no users exist."""
        user = self.db.get_user("admin")
        if not user:
            hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
            self.db.add_user("admin", hashed, "admin")
            logger.info("Default admin account created (username: admin, password: admin)")
            logger.warning("CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY!")

    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate a user.
        Returns (success: bool, message: str).
        """
        user = self.db.get_user(username)
        if not user:
            logger.warning("Login attempt for non-existent user: %s", username)
            return False, "Invalid username or password."

        if not user.is_active:
            logger.warning("Login attempt for disabled user: %s", username)
            return False, "Account is disabled."

        try:
            if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                self._current_user = username
                self._current_role = user.role
                self.db.update_last_login(username)
                logger.info("User '%s' logged in (role: %s)", username, user.role)
                return True, f"Welcome, {username}!"
            else:
                logger.warning("Failed login for user: %s", username)
                return False, "Invalid username or password."
        except Exception as e:
            logger.error("Auth error: %s", e)
            return False, "Authentication error."

    def create_user(self, username: str, password: str, role: str = "viewer") -> Tuple[bool, str]:
        """Create a new user account (admin only)."""
        if self._current_role != "admin":
            return False, "Only administrators can create users."

        if self.db.get_user(username):
            return False, f"User '{username}' already exists."

        if role not in ("admin", "viewer"):
            return False, "Role must be 'admin' or 'viewer'."

        if len(password) < 6:
            return False, "Password must be at least 6 characters."

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.db.add_user(username, hashed, role)
        logger.info("User '%s' created with role '%s'", username, role)
        return True, f"User '{username}' created."

    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password."""
        user = self.db.get_user(username)
        if not user:
            return False, "User not found."

        if not bcrypt.checkpw(old_password.encode(), user.password_hash.encode()):
            return False, "Current password is incorrect."

        if len(new_password) < 6:
            return False, "New password must be at least 6 characters."

        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        with self.db.session() as s:
            from sentinelx.database.models import User as UserModel
            u = s.query(UserModel).filter(UserModel.username == username).first()
            if u:
                u.password_hash = new_hash
                s.commit()

        logger.info("Password changed for user '%s'", username)
        return True, "Password changed successfully."

    @property
    def current_user(self) -> Optional[str]:
        return self._current_user

    @property
    def current_role(self) -> Optional[str]:
        return self._current_role

    @property
    def is_admin(self) -> bool:
        return self._current_role == "admin"

    def logout(self) -> None:
        logger.info("User '%s' logged out", self._current_user)
        self._current_user = None
        self._current_role = None
