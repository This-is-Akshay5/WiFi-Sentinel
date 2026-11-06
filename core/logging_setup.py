"""Structured application logging for WiFiSentinel.

Design goals
------------
* One rotating log file next to the application directory (``logs/wifisentinel.log``).
* Consistent ``key=value`` style records so the file stays greppable for a reviewer.
* Secrets are never written. Every record passes through a redaction filter that masks
  anything that looks like an API key, bearer token or password.
* The UI never receives tracebacks; it receives short messages. Full detail stays here.
"""
from __future__ import annotations

import logging
import os
import re
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOCK = threading.Lock()
_CONFIGURED = False

#: Environment variables whose values must never reach a log record or the database.
SECRET_ENV_KEYS = (
    "OPENAI_API_KEY",
    "WIFISENTINEL_CONNECTOR_TOKEN",
)

_REDACT_PATTERNS = (
    (re.compile(r"sk-[A-Za-z0-9_\-]{6,}"), "sk-***REDACTED***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{6,}", re.I), r"\1***REDACTED***"),
    (re.compile(r"((?:api[_-]?key|access[_-]?token|token|password|secret)\"?\s*[=:]\s*\"?)([^\s\",}]+)", re.I), r"\1***REDACTED***"),
)


def redact(value):
    """Return ``value`` with anything that looks like a credential masked."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Final safety net applied to every record before it reaches a handler."""

    def filter(self, record):  # noqa: D401 - logging API
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            record.msg = redact(str(record.msg))
        return True


class KeyValueFormatter(logging.Formatter):
    """``2026-01-01T00:00:00Z level logger event key=value`` — compact and greppable."""

    def format(self, record):
        base = super().format(record)
        extras = getattr(record, "context", None) or {}
        if not extras:
            return base
        tail = " ".join(f"{k}={redact(v)}" for k, v in extras.items() if v is not None)
        return f"{base} | {tail}" if tail else base


def configure(app_dir, level: str = "INFO") -> Path:
    """Configure root logging once. Returns the active log file path."""
    global _CONFIGURED, LOG_PATH
    with _LOCK:
        if _CONFIGURED:
            return LOG_PATH
        log_dir = Path(app_dir) / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            log_dir = Path.cwd()
        LOG_PATH = log_dir / "wifisentinel.log"
        root = logging.getLogger("wifisentinel")
        root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
        root.propagate = False
        formatter = KeyValueFormatter("%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
        redactor = RedactingFilter()
        try:
            handler = RotatingFileHandler(LOG_PATH, maxBytes=1_500_000, backupCount=3, encoding="utf-8")
            handler.addFilter(redactor)
            handler.setFormatter(formatter)
            root.addHandler(handler)
        except OSError:
            pass
        stream = logging.StreamHandler(sys.stderr)
        stream.addFilter(redactor)
        stream.setFormatter(formatter)
        root.addHandler(stream)
        _CONFIGURED = True
        root.info(
            "logger_initialised",
            extra={"context": {"log_file": str(LOG_PATH), "pid": os.getpid(), "python": sys.version.split()[0]}},
        )
        return LOG_PATH


LOG_PATH = Path("logs/wifisentinel.log")


def get_logger(name: str) -> logging.Logger:
    """Return a child logger. Usable before :func:`configure` without extra work."""
    return logging.getLogger("wifisentinel." + name)


def log_event(logger, level, event, **context):
    """Log a structured event with keyword context and automatic redaction."""
    logger.log(getattr(logging, level.upper(), logging.INFO), event, extra={"context": context})


def secret_fingerprint(value: str) -> str:
    """Return a non-reversible marker so Settings can show *that* a key is present."""
    if not value:
        return "absent"
    return f"present(len={len(value)})"