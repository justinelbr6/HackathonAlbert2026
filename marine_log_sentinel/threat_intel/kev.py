"""CISA Known Exploited Vulnerabilities (KEV) catalog loader.

The KEV catalog is the strongest *operational* signal we can attach to a
CVE: it means "this vulnerability is being exploited in the wild right
now, and CISA officially mandates patching it". Any log we can link to a
KEV-listed CVE is automatically a top-priority finding for the Marine.

Source:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Schema (the fields we keep):
    {
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-44228",
          "dateAdded": "2021-12-10",
          "knownRansomwareCampaignUse": "Known" | "Unknown",
          ...
        }, ...
      ]
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from marine_log_sentinel.threat_intel.cache import CacheEntry, fetch, read_cached

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_NAME = "kev"
KEV_CACHE_FILE = "known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: date | None
    known_ransomware: bool | None
    vendor: str | None = None
    product: str | None = None
    required_action: str | None = None


def _to_bool(ransomware: Any) -> bool | None:
    if not ransomware:
        return None
    text = str(ransomware).strip().lower()
    if text == "known":
        return True
    if text == "unknown":
        return False
    return None


def _to_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def parse_kev_file(path: Path) -> dict[str, KevEntry]:
    """Parse a CISA KEV JSON file into a {cve_id: KevEntry} mapping."""

    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    entries: dict[str, KevEntry] = {}
    for raw in bundle.get("vulnerabilities", []) or []:
        cve_id = str(raw.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=_to_date(raw.get("dateAdded")),
            known_ransomware=_to_bool(raw.get("knownRansomwareCampaignUse")),
            vendor=raw.get("vendorProject"),
            product=raw.get("product"),
            required_action=raw.get("requiredAction"),
        )
    return entries


def load_kev(
    *,
    refresh: bool = False,
    cache_dir: Path | None = None,
) -> tuple[dict[str, KevEntry], CacheEntry]:
    """Load the CISA KEV catalog from cache (or fetch it once with cache+audit)."""

    entry = fetch(
        KEV_URL,
        name=KEV_CACHE_NAME,
        filename=KEV_CACHE_FILE,
        refresh=refresh,
        cache_dir=cache_dir,
    )
    return parse_kev_file(entry.path), entry


def load_kev_offline(*, cache_dir: Path | None = None) -> tuple[dict[str, KevEntry], CacheEntry]:
    """Strict offline load: never reach for the network. Used in air-gap mode."""

    entry = read_cached(KEV_CACHE_NAME, KEV_CACHE_FILE, cache_dir=cache_dir)
    return parse_kev_file(entry.path), entry
