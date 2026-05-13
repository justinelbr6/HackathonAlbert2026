"""Online Threat Intelligence sync layer.

All fetchers in this package share the same air-gap contract:

  - If `SETTINGS.air_gap_mode` is ON, no outbound HTTP call is allowed.
    The fetcher returns the cached entry if it exists, otherwise raises
    `NetworkBlockedError` so the caller can degrade gracefully.
  - Every successful fetch writes a tamper-checked cache entry
    (payload + SHA-256 + fetched_at_utc metadata) and records a
    `ti.sync` entry in the tamper-evident audit log.
  - HTTP and TAXII clients are *injectable* so unit tests stay fully
    offline.
"""

from marine_log_sentinel.threat_intel.sync.cache import (
    CacheEntry,
    NetworkBlockedError,
    cache_dir_for,
    fetch_with_cache,
    read_cache,
    write_cache,
)
from marine_log_sentinel.threat_intel.sync.epss import (
    EPSS_SOURCE,
    load_cached_epss,
    sync_epss_for_cves,
)
from marine_log_sentinel.threat_intel.sync.kev import (
    KEV_SOURCE,
    load_cached_kev_cves,
    sync_cisa_kev,
)
from marine_log_sentinel.threat_intel.sync.taxii import (
    MITRE_TAXII_SOURCE,
    sync_mitre_enterprise,
)

__all__ = [
    "CacheEntry",
    "EPSS_SOURCE",
    "KEV_SOURCE",
    "MITRE_TAXII_SOURCE",
    "NetworkBlockedError",
    "cache_dir_for",
    "fetch_with_cache",
    "load_cached_epss",
    "load_cached_kev_cves",
    "read_cache",
    "sync_cisa_kev",
    "sync_epss_for_cves",
    "sync_mitre_enterprise",
    "write_cache",
]
