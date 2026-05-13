"""Structured JSON logger.

All modules must obtain their logger via `get_logger(__name__)`. Output is
emitted as JSON Lines on stdout, ready for ingestion into a SIEM during
real-world operation and consistent across components.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging import Logger
from typing import Any

from marine_log_sentinel.config import SETTINGS

_RESERVED_RECORD_KEYS: frozenset[str] = frozenset({
    "args", "msg", "exc_info", "exc_text", "stack_info", "levelname",
    "name", "pathname", "filename", "module", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "levelno",
})


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_KEYS:
                continue
            payload.setdefault(key, value)
        return json.dumps(payload, ensure_ascii=False, default=str)


_CONFIGURED = False


def _configure_root_logger() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger()
    root.setLevel(SETTINGS.log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root.handlers = [handler]
    _CONFIGURED = True


def get_logger(name: str) -> Logger:
    _configure_root_logger()
    return logging.getLogger(name)
