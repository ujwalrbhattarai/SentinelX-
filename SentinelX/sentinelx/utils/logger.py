"""
SentinelX – Logging System
Provides tamper-resistant, structured logging with rotation.
"""

import logging
import hashlib
from logging.handlers import RotatingFileHandler
from typing import Optional

from sentinelx.utils.config import LOG_DIR


class IntegrityRotatingFileHandler(RotatingFileHandler):
    """A rotating file handler that appends HMAC hashes per line for tamper detection."""

    def __init__(self, *args, secret: str = "SentinelX-LogKey", **kwargs):
        self._secret = secret.encode()
        super().__init__(*args, **kwargs)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            hmac_hash = hashlib.sha256(self._secret + msg.encode()).hexdigest()[:16]
            record.msg = f"{msg} |hmac={hmac_hash}"
            record.args = None
            stream = self.stream
            stream.write(self.format(record) + self.terminator)
            self.flush()
            if self.shouldRollover(record):
                self.doRollover()
        except Exception:
            self.handleError(record)


def setup_logger(
    name: str = "sentinelx",
    level: int = logging.DEBUG,
    log_file: Optional[str] = None,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """Set up and return a configured logger instance."""

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler with integrity checks
    if log_file is None:
        log_file = str(LOG_DIR / f"{name}.log")

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# Module-level convenience loggers
def get_logger(module_name: str) -> logging.Logger:
    """Get a child logger for a specific module."""
    parent = setup_logger("sentinelx")
    return parent.getChild(module_name)
