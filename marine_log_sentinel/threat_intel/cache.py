"""Disk cache for remote Threat Intelligence feeds with air-gap discipline.

This module is the single funnel through which all outbound HTTP(S) calls
of the project pass. It enforces the following invariants:

1. Air-gap posture (`MLS_AIR_GAP=1`) **forbids any network egress**.
   If the cache is missing, the caller is told exactly what to do
   (run `ti sync` from a connected box, then move the cache file).

2. Every fetch is:
   - performed over HTTPS only,
   - written atomically (tmp file + os.replace) so a crash can never
     leave a half-downloaded file in cache,
   - fingerprinted with SHA-256, size, source URL and UTC timestamp
     in a sidecar `metadata.json`,
   - recorded in the tamper-evident audit log via `ti.cache.fetch`.

3. Caches live under `SETTINGS.cache_dir / <name> / <basename>` so each
   feed is isolated and easy to rotate.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger

LOGGER = get_logger(__name__)

_HTTPS_ONLY = True
_USER_AGENT = "MarineLogSentinel/0.1 (+air-gap-aware)"


class AirGapError(RuntimeError):
    """Raised when an online fetch is attempted while air-gap mode is on."""


class CacheMissError(FileNotFoundError):
    """Raised when an offline read is attempted but no cache is available."""


@dataclass(frozen=True)
class CacheEntry:
    """Pointer to a cached payload + provenance information."""

    name: str
    path: Path
    sha256: str
    size_bytes: int
    source_url: str
    fetched_at_utc: datetime

    def to_metadata(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": str(self.path),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_url": self.source_url,
            "fetched_at_utc": self.fetched_at_utc.isoformat(),
        }


def _cache_root(cache_dir: Path | None = None) -> Path:
    root = Path(cache_dir) if cache_dir else SETTINGS.cache_dir
    root.mkdir(parents=True, exist_ok=True)
    return root


def _entry_paths(name: str, filename: str, cache_dir: Path | None = None) -> tuple[Path, Path]:
    root = _cache_root(cache_dir) / name
    root.mkdir(parents=True, exist_ok=True)
    return root / filename, root / "metadata.json"


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(target: Path, payload: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_cached(
    name: str,
    filename: str,
    *,
    cache_dir: Path | None = None,
) -> CacheEntry:
    """Return the CacheEntry for a previously-stored payload, or raise."""

    payload_path, metadata_path = _entry_paths(name, filename, cache_dir)
    if not payload_path.exists() or not metadata_path.exists():
        raise CacheMissError(
            f"No cached entry for '{name}/{filename}'. "
            f"Run `python -m marine_log_sentinel ti sync` on a connected host first."
        )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    fetched_at = datetime.fromisoformat(metadata["fetched_at_utc"])
    return CacheEntry(
        name=name,
        path=payload_path,
        sha256=metadata["sha256"],
        size_bytes=int(metadata["size_bytes"]),
        source_url=metadata["source_url"],
        fetched_at_utc=fetched_at,
    )


def fetch(
    url: str,
    *,
    name: str,
    filename: str,
    refresh: bool = False,
    timeout: int = 30,
    cache_dir: Path | None = None,
) -> CacheEntry:
    """Fetch a remote payload with cache + air-gap discipline.

    - If a cache exists and `refresh` is False, the cached entry is returned
      verbatim (no network call).
    - If `refresh` is True or no cache exists, a new HTTPS download is
      attempted, unless `SETTINGS.air_gap_mode` is True (then we raise).
    """

    if _HTTPS_ONLY and not url.startswith("https://"):
        raise ValueError(f"Only HTTPS URLs are allowed (got: {url[:32]}...).")

    payload_path, metadata_path = _entry_paths(name, filename, cache_dir)
    if not refresh and payload_path.exists() and metadata_path.exists():
        return read_cached(name, filename, cache_dir=cache_dir)

    if SETTINGS.air_gap_mode:
        raise AirGapError(
            f"Refusing to fetch '{url}' (cache: '{name}/{filename}') because air-gap "
            f"mode is ON. Sync the cache from a connected host then copy it under "
            f"{_cache_root(cache_dir)/name}/ and rerun."
        )

    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    LOGGER.info("ti.cache.fetch.start", extra={"feed": name, "url": url})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            payload = response.read()
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        LOGGER.error("ti.cache.fetch.error", extra={"feed": name, "url": url, "error": str(exc)})
        raise

    _atomic_write(payload_path, payload)
    digest = hashlib.sha256(payload).hexdigest()
    entry = CacheEntry(
        name=name,
        path=payload_path,
        sha256=digest,
        size_bytes=len(payload),
        source_url=url,
        fetched_at_utc=datetime.now(timezone.utc),
    )
    _atomic_write(
        metadata_path,
        json.dumps(entry.to_metadata(), ensure_ascii=False, indent=2).encode("utf-8"),
    )

    audit_record(
        "ti.cache.fetch",
        payload={
            "name": entry.name,
            "url": entry.source_url,
            "sha256": entry.sha256,
            "size_bytes": entry.size_bytes,
        },
    )
    LOGGER.info(
        "ti.cache.fetch.ok",
        extra={"feed": name, "size_bytes": entry.size_bytes, "sha256": digest[:12]},
    )
    return entry


def clear_cache_entry(name: str, *, cache_dir: Path | None = None) -> None:
    """Remove a cached feed directory (used in tests and for forced refresh)."""

    target = _cache_root(cache_dir) / name
    if target.exists():
        shutil.rmtree(target)
