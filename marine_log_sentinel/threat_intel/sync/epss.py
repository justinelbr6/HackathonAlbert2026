"""EPSS (Exploit Prediction Scoring System) sync.

EPSS produces a probability in [0, 1] that a CVE will be exploited in
the next 30 days. It is calibrated against real-world exploitation data
and serves as a forward-looking complement to CVSS (which is static)
and CISA KEV (which is binary).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from marine_log_sentinel.threat_intel.sync.cache import (
    CacheEntry,
    HttpGet,
    fetch_with_cache,
    read_cache,
)

EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_SOURCE = "epss"


def _build_url(cve_ids: Iterable[str]) -> str:
    cves = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not cves:
        return EPSS_API
    return f"{EPSS_API}?cve={','.join(cves)}"


def sync_epss_for_cves(
    cve_ids: Iterable[str],
    *,
    force: bool = False,
    http_get: HttpGet | None = None,
    base_dir: Path | None = None,
    air_gap: bool | None = None,
    url: str | None = None,
) -> CacheEntry:
    target_url = url if url is not None else _build_url(cve_ids)
    return fetch_with_cache(
        EPSS_SOURCE,
        target_url,
        force=force,
        http_get=http_get,
        base_dir=base_dir,
        air_gap=air_gap,
    )


def load_cached_epss(*, base_dir: Path | None = None) -> dict[str, float]:
    entry = read_cache(EPSS_SOURCE, base_dir=base_dir)
    if entry is None:
        return {}
    try:
        data = json.loads(entry.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    scores: dict[str, float] = {}
    for item in data.get("data", []):
        cve = item.get("cve")
        raw = item.get("epss")
        if not cve or raw is None:
            continue
        try:
            scores[str(cve).strip().upper()] = float(raw)
        except (TypeError, ValueError):
            continue
    return scores
