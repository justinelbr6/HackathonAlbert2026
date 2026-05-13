"""Shared low-level helpers for parsers."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, accepting the legacy trailing 'Z' suffix."""

    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError("empty timestamp")
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
