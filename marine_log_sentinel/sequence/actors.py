"""Derive a stable actor key from a prediction (same operator / same session)."""

from __future__ import annotations

from pathlib import Path

from marine_log_sentinel.ml.models import LogPrediction


def derive_actor_key(pred: LogPrediction) -> str:
    """Best-effort identity for correlating successive logs.

    Priority:
      1. ``user`` + ``host`` (ideal: interactive account on a named system)
      2. ``user`` alone
      3. ``host`` alone
      4. ``src_ip`` (client-centric network events)
      5. ``dst_ip``
      6. fallback to source file stem (weak — many events may collapse together)
    """

    u = (pred.user or "").strip()
    h = (pred.host or "").strip()
    if u and h:
        return f"u:{u.lower()}|h:{h.lower()}"
    if u:
        return f"u:{u.lower()}"
    if h:
        return f"h:{h.lower()}"
    sip = (pred.src_ip or "").strip()
    if sip:
        return f"src:{sip}"
    dip = (pred.dst_ip or "").strip()
    if dip:
        return f"dst:{dip}"
    return f"file:{Path(pred.source_file).name}"
