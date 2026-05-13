"""CISA Known Exploited Vulnerabilities (KEV) sync.

A CVE listed in the KEV catalog is a strong "actively exploited in the
wild" signal and is one of the heaviest weights in the Étape 4 scorer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from marine_log_sentinel.threat_intel.sync.cache import (
    CacheEntry,
    HttpGet,
    fetch_with_cache,
    read_cache,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_SOURCE = "cisa_kev"


def sync_cisa_kev(
    *,
    force: bool = False,
    http_get: HttpGet | None = None,
    base_dir: Path | None = None,
    air_gap: bool | None = None,
    url: str = KEV_URL,
) -> CacheEntry:
    return fetch_with_cache(
        KEV_SOURCE,
        url,
        force=force,
        http_get=http_get,
        base_dir=base_dir,
        air_gap=air_gap,
    )


def load_cached_kev_cves(*, base_dir: Path | None = None) -> set[str]:
    """Return the set of CVE ids present in the cached KEV feed (empty if missing)."""

    entry = read_cache(KEV_SOURCE, base_dir=base_dir)
    if entry is None:
        return set()
    try:
        data = json.loads(entry.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return set()
    cves: set[str] = set()
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID") or item.get("cve_id") or item.get("cve")
        if cve_id:
            cves.add(str(cve_id).strip().upper())
    return cves
