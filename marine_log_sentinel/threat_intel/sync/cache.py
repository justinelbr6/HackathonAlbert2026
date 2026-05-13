"""Cache primitives and air-gap policy enforcement for TI fetchers.

A cache entry for a logical source `SOURCE` is laid out under
``<cache_dir>/<SOURCE>/`` with two files:
  - ``payload.bin``   the raw bytes returned by the upstream feed
  - ``meta.json``     SHA-256, byte size, URL, fetched_at_utc, content-type

Reading verifies the SHA-256 stored in ``meta.json`` against the actual
payload bytes, so a tampered cache file is detected at load time and the
caller can refuse to use it (defense in depth on top of the audit log).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger

LOGGER = get_logger(__name__)

HttpGet = Callable[[str], "tuple[int, bytes, Optional[str]]"]


class NetworkBlockedError(RuntimeError):
    """Raised when an online fetch is required but air-gap mode is ON."""


class CacheCorruptedError(RuntimeError):
    """Raised when a cache payload no longer matches its recorded SHA-256."""


@dataclass(frozen=True)
class CacheEntry:
    source: str
    path: Path
    meta_path: Path
    meta: dict[str, Any]
    payload: bytes

    @property
    def sha256(self) -> str:
        return str(self.meta.get("sha256", ""))

    @property
    def fetched_at_utc(self) -> str:
        return str(self.meta.get("fetched_at_utc", ""))


def cache_dir_for(source: str, *, base_dir: Path | None = None) -> Path:
    base = Path(base_dir) if base_dir is not None else SETTINGS.cache_dir
    return base / source


def _paths(source: str, base_dir: Path | None = None) -> tuple[Path, Path]:
    folder = cache_dir_for(source, base_dir=base_dir)
    return folder / "payload.bin", folder / "meta.json"


def write_cache(
    source: str,
    payload: bytes,
    *,
    url: str,
    content_type: str | None = None,
    base_dir: Path | None = None,
) -> CacheEntry:
    payload_path, meta_path = _paths(source, base_dir=base_dir)
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    meta = {
        "source": source,
        "url": url,
        "sha256": digest,
        "bytes": len(payload),
        "content_type": content_type,
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return CacheEntry(
        source=source,
        path=payload_path,
        meta_path=meta_path,
        meta=meta,
        payload=payload,
    )


def read_cache(source: str, *, base_dir: Path | None = None) -> CacheEntry | None:
    payload_path, meta_path = _paths(source, base_dir=base_dir)
    if not payload_path.exists() or not meta_path.exists():
        return None
    payload = payload_path.read_bytes()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    expected = meta.get("sha256")
    actual = hashlib.sha256(payload).hexdigest()
    if expected and expected != actual:
        raise CacheCorruptedError(
            f"Cache entry '{source}' is corrupted: "
            f"sha256 mismatch (recorded={expected[:12]}..., actual={actual[:12]}...)"
        )
    return CacheEntry(
        source=source,
        path=payload_path,
        meta_path=meta_path,
        meta=meta,
        payload=payload,
    )


def _default_http_get(url: str) -> tuple[int, bytes, str | None]:
    import requests

    response = requests.get(url, timeout=30, headers={"User-Agent": "MarineLogSentinel/0.1"})
    return response.status_code, response.content, response.headers.get("Content-Type")


def fetch_with_cache(
    source: str,
    url: str,
    *,
    force: bool = False,
    http_get: HttpGet | None = None,
    base_dir: Path | None = None,
    air_gap: bool | None = None,
) -> CacheEntry:
    """Fetch and cache the bytes from `url` for logical source `source`.

    Cache-first by default: returns the existing cache entry untouched
    if one is present. Pass ``force=True`` to require an upstream fetch.
    `air_gap` overrides ``SETTINGS.air_gap_mode`` for tests.
    """

    air_gap_on = SETTINGS.air_gap_mode if air_gap is None else air_gap

    if not force:
        existing = read_cache(source, base_dir=base_dir)
        if existing is not None:
            return existing

    if air_gap_on:
        raise NetworkBlockedError(
            f"Air-gap mode is ON: '{source}' is not in local cache "
            f"({cache_dir_for(source, base_dir=base_dir)}). "
            f"Disable MLS_AIR_GAP and run `ti sync` to refresh the cache."
        )

    fetcher = http_get if http_get is not None else _default_http_get
    status, body, content_type = fetcher(url)
    if status != 200 or not body:
        audit_record(
            "ti.sync.failed",
            payload={"source": source, "url": url, "status": status, "bytes": len(body)},
        )
        raise RuntimeError(f"Failed to fetch '{source}' from {url}: HTTP {status}")

    entry = write_cache(
        source,
        body,
        url=url,
        content_type=content_type,
        base_dir=base_dir,
    )
    audit_record(
        "ti.sync",
        payload={
            "source": source,
            "url": url,
            "sha256": entry.sha256,
            "bytes": entry.meta["bytes"],
        },
    )
    LOGGER.info(
        "ti.sync.ok",
        extra={"source": source, "sha256": entry.sha256[:12], "bytes": entry.meta["bytes"]},
    )
    return entry
