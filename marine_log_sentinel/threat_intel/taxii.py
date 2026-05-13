"""MITRE ATT&CK TAXII 2.1 client.

Wraps the imposed `taxii2-client` library to refresh the Enterprise
ATT&CK STIX bundle from MITRE's official TAXII 2.1 server, with the same
air-gap discipline as KEV/EPSS:

  - In air-gap mode, the function raises `AirGapError` immediately.
  - In connected mode, the bundle is written atomically to the cache,
    fingerprinted with SHA-256, and the operation is recorded in the
    tamper-evident audit log.

The cached bundle is intentionally written as plain `enterprise-attack.json`
(NOT zipped) so the MITRE loader (`mitre.load_mitre_entities`) can be
pointed at it directly without an unzip step.

Reference:
    https://attack-taxii.mitre.org/

We use the well-known collection id for Enterprise ATT&CK rather than
discovering it dynamically, to keep behavior deterministic for an audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel.cache import (
    AirGapError,
    CacheEntry,
    _cache_root,
    _entry_paths,
    read_cached,
)

LOGGER = get_logger(__name__)

MITRE_TAXII_URL = "https://attack-taxii.mitre.org/api/v21/"
MITRE_ENTERPRISE_COLLECTION_ID = "1f5f1533-f617-4ca8-9ab4-6a02367fa019"
TAXII_CACHE_NAME = "taxii_enterprise"
TAXII_CACHE_FILE = "enterprise-attack.json"


def sync_mitre_from_taxii(
    *,
    refresh: bool = True,
    cache_dir: Path | None = None,
    page_size: int = 5000,
) -> CacheEntry:
    """Pull the MITRE Enterprise ATT&CK bundle from TAXII into the local cache.

    Returns a `CacheEntry` pointing at the newly-cached `enterprise-attack.json`.
    """

    payload_path, metadata_path = _entry_paths(TAXII_CACHE_NAME, TAXII_CACHE_FILE, cache_dir)
    if not refresh and payload_path.exists() and metadata_path.exists():
        return read_cached(TAXII_CACHE_NAME, TAXII_CACHE_FILE, cache_dir=cache_dir)

    if SETTINGS.air_gap_mode:
        raise AirGapError(
            "TAXII fetch is forbidden in air-gap mode. Sync the bundle from a "
            "connected host then copy it under "
            f"{_cache_root(cache_dir) / TAXII_CACHE_NAME}/ and rerun."
        )

    from taxii2client.v21 import Collection

    collection_url = f"{MITRE_TAXII_URL}collections/{MITRE_ENTERPRISE_COLLECTION_ID}/"
    LOGGER.info("ti.taxii.sync.start", extra={"collection_url": collection_url})
    collection = Collection(collection_url)

    objects: list[dict] = []
    response = collection.get_objects(limit=page_size)
    objects.extend(response.get("objects", []))
    while response.get("more"):
        next_page = response.get("next")
        if next_page is None:
            break
        response = collection.get_objects(limit=page_size, next=next_page)
        objects.extend(response.get("objects", []))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "spec_version": "2.1",
        "objects": objects,
    }
    payload = json.dumps(bundle, ensure_ascii=False).encode("utf-8")

    payload_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=str(payload_path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp, payload_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    digest = hashlib.sha256(payload).hexdigest()
    entry = CacheEntry(
        name=TAXII_CACHE_NAME,
        path=payload_path,
        sha256=digest,
        size_bytes=len(payload),
        source_url=collection_url,
        fetched_at_utc=datetime.now(timezone.utc),
    )
    metadata_path.write_text(
        json.dumps(entry.to_metadata(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    audit_record(
        "ti.taxii.sync",
        payload={
            "collection_url": collection_url,
            "objects": len(objects),
            "sha256": digest,
            "size_bytes": len(payload),
        },
    )
    LOGGER.info(
        "ti.taxii.sync.ok",
        extra={"objects": len(objects), "sha256": digest[:12], "size_bytes": len(payload)},
    )
    return entry
