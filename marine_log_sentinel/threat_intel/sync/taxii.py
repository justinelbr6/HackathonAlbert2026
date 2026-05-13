"""MITRE ATT&CK Enterprise sync over TAXII 2.1.

The shipped `enterprise-attack.json.zip` remains the default offline
source. This module is the on-demand refresh path: when the operator
explicitly runs `ti sync --source mitre`, we fetch the latest STIX
bundle through TAXII, cache it locally, and the next snapshot load will
prefer that fresher cache if requested.

The TAXII client is injectable so unit tests stay fully offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel.sync.cache import (
    CacheEntry,
    NetworkBlockedError,
    cache_dir_for,
    read_cache,
    write_cache,
)

LOGGER = get_logger(__name__)

MITRE_TAXII_URL = "https://attack-taxii.mitre.org/api/v21/"
MITRE_TAXII_SOURCE = "mitre_enterprise_taxii"
ENTERPRISE_COLLECTION_PREFIX = "enterprise"

TaxiiClientFactory = Callable[[str], Any]


def _default_taxii_factory(server_url: str) -> Any:
    from taxii2client.v21 import Server  # noqa: PLC0415 - lazy network-ish dep

    return Server(server_url)


def _fetch_bundle(server: Any) -> dict[str, Any]:
    api_roots = list(getattr(server, "api_roots", []) or [])
    if not api_roots:
        raise RuntimeError("MITRE TAXII server exposes no API roots.")
    collection = None
    for api_root in api_roots:
        for candidate in getattr(api_root, "collections", []) or []:
            title = (getattr(candidate, "title", "") or "").lower()
            if title.startswith(ENTERPRISE_COLLECTION_PREFIX):
                collection = candidate
                break
        if collection is not None:
            break
    if collection is None:
        raise RuntimeError(
            "MITRE TAXII server does not expose an 'enterprise' collection."
        )
    bundle = collection.get_objects()
    if not isinstance(bundle, dict) or "objects" not in bundle:
        raise RuntimeError(
            "Unexpected payload from MITRE TAXII: missing top-level 'objects'."
        )
    return bundle


def sync_mitre_enterprise(
    *,
    force: bool = False,
    base_dir: Path | None = None,
    air_gap: bool | None = None,
    server_url: str = MITRE_TAXII_URL,
    taxii_client_factory: TaxiiClientFactory | None = None,
) -> CacheEntry:
    air_gap_on = SETTINGS.air_gap_mode if air_gap is None else air_gap

    if not force:
        existing = read_cache(MITRE_TAXII_SOURCE, base_dir=base_dir)
        if existing is not None:
            return existing

    if air_gap_on:
        raise NetworkBlockedError(
            f"Air-gap mode is ON: '{MITRE_TAXII_SOURCE}' is not in local cache "
            f"({cache_dir_for(MITRE_TAXII_SOURCE, base_dir=base_dir)})."
        )

    factory = taxii_client_factory if taxii_client_factory is not None else _default_taxii_factory
    server = factory(server_url)
    bundle = _fetch_bundle(server)
    body = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    entry = write_cache(
        MITRE_TAXII_SOURCE,
        body,
        url=server_url,
        content_type="application/stix+json;version=2.1",
        base_dir=base_dir,
    )
    audit_record(
        "ti.sync",
        payload={
            "source": MITRE_TAXII_SOURCE,
            "url": server_url,
            "sha256": entry.sha256,
            "bytes": entry.meta["bytes"],
            "stix_objects": len(bundle.get("objects", [])),
        },
    )
    LOGGER.info(
        "ti.sync.ok",
        extra={
            "source": MITRE_TAXII_SOURCE,
            "sha256": entry.sha256[:12],
            "stix_objects": len(bundle.get("objects", [])),
        },
    )
    return entry
