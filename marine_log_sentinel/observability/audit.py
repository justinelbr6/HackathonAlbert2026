"""Tamper-evident audit log.

Every important action (TI snapshot used, analysis run, report generated)
writes a JSON line that embeds the SHA-256 of the previous entry. The
entries thus form a hash chain: any retroactive tampering breaks the chain
and is detected by `verify_chain`. This is the minimum traceability
required for a defensible military-grade tool.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from marine_log_sentinel.config import SETTINGS

_GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()


@dataclass(frozen=True)
class AuditEntry:
    timestamp_utc: str
    actor: str
    action: str
    payload_digest: str
    prev_hash: str
    this_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _digest(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _entry_hash(
    *,
    prev_hash: str,
    timestamp_utc: str,
    actor: str,
    action: str,
    payload_digest: str,
    metadata: dict[str, Any],
) -> str:
    return _digest({
        "prev_hash": prev_hash,
        "timestamp_utc": timestamp_utc,
        "actor": actor,
        "action": action,
        "payload_digest": payload_digest,
        "metadata": metadata,
    })


def _read_last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return _GENESIS_HASH
    last_line: str | None = None
    with path.open("rb") as handle:
        for raw in handle:
            stripped = raw.strip()
            if stripped:
                last_line = stripped.decode("utf-8")
    if not last_line:
        return _GENESIS_HASH
    return json.loads(last_line)["this_hash"]


def record(
    action: str,
    *,
    actor: str = "system",
    payload: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    audit_log_path: Path | None = None,
) -> AuditEntry:
    """Append a hash-chained entry to the audit log and return it."""

    payload = payload or {}
    metadata = metadata or {}
    path = Path(audit_log_path or SETTINGS.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    payload_digest = _digest(payload)
    with _LOCK:
        prev_hash = _read_last_hash(path)
        this_hash = _entry_hash(
            prev_hash=prev_hash,
            timestamp_utc=timestamp_utc,
            actor=actor,
            action=action,
            payload_digest=payload_digest,
            metadata=metadata,
        )
        entry = AuditEntry(
            timestamp_utc=timestamp_utc,
            actor=actor,
            action=action,
            payload_digest=payload_digest,
            prev_hash=prev_hash,
            this_hash=this_hash,
            metadata=metadata,
        )
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
    return entry


def verify_chain(audit_log_path: Path | None = None) -> tuple[bool, int, str | None]:
    """Verify the integrity of the audit log.

    Returns (is_valid, entries_checked, broken_at_or_None).
    An empty or non-existent log is considered valid with 0 entries.
    """

    path = Path(audit_log_path or SETTINGS.audit_log_path)
    if not path.exists():
        return True, 0, None
    prev_hash = _GENESIS_HASH
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            entry = json.loads(stripped)
            if entry["prev_hash"] != prev_hash:
                return False, count, f"line {line_number}: prev_hash mismatch"
            expected = _entry_hash(
                prev_hash=entry["prev_hash"],
                timestamp_utc=entry["timestamp_utc"],
                actor=entry["actor"],
                action=entry["action"],
                payload_digest=entry["payload_digest"],
                metadata=entry.get("metadata", {}),
            )
            if entry["this_hash"] != expected:
                return False, count, f"line {line_number}: this_hash mismatch"
            prev_hash = entry["this_hash"]
            count += 1
    return True, count, None
