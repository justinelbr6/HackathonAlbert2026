"""EPSS (Exploit Prediction Scoring System) loader.

EPSS provides, for each CVE, a probability of exploitation within the
next 30 days and the corresponding percentile in the global distribution.
Combined with CVSS (severity if exploited) and KEV (currently exploited
in the wild), it gives our scoring engine three orthogonal angles on a
vulnerability.

Source (daily snapshot, ~5 MB gz):
    https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

Format (after the gz):
    # model_version: ...
    cve,epss,percentile
    CVE-1999-0001,0.000400000,0.094200000
    ...
"""

from __future__ import annotations

import csv
import gzip
import io
from dataclasses import dataclass
from pathlib import Path

from marine_log_sentinel.threat_intel.cache import CacheEntry, fetch, read_cached

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_CACHE_NAME = "epss"
EPSS_CACHE_FILE = "epss_scores-current.csv.gz"


@dataclass(frozen=True)
class EpssEntry:
    cve_id: str
    score: float
    percentile: float


def _open_payload(path: Path) -> io.TextIOWrapper:
    raw = Path(path).read_bytes()
    if path.suffix.lower() == ".gz" or raw[:2] == b"\x1f\x8b":
        decompressed = gzip.decompress(raw)
        return io.StringIO(decompressed.decode("utf-8", errors="replace"))
    return io.StringIO(raw.decode("utf-8", errors="replace"))


def parse_epss_file(path: Path) -> dict[str, EpssEntry]:
    """Parse an EPSS CSV(.gz) into a {cve_id: EpssEntry} mapping."""

    handle = _open_payload(Path(path))
    while True:
        position = handle.tell()
        line = handle.readline()
        if not line:
            return {}
        if line.startswith("#"):
            continue
        handle.seek(position)
        break

    reader = csv.DictReader(handle)
    entries: dict[str, EpssEntry] = {}
    for row in reader:
        cve_id = str(row.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        try:
            score = float(row.get("epss") or 0.0)
            percentile = float(row.get("percentile") or 0.0)
        except ValueError:
            continue
        entries[cve_id] = EpssEntry(cve_id=cve_id, score=score, percentile=percentile)
    return entries


def load_epss(
    *,
    refresh: bool = False,
    cache_dir: Path | None = None,
) -> tuple[dict[str, EpssEntry], CacheEntry]:
    entry = fetch(
        EPSS_URL,
        name=EPSS_CACHE_NAME,
        filename=EPSS_CACHE_FILE,
        refresh=refresh,
        cache_dir=cache_dir,
    )
    return parse_epss_file(entry.path), entry


def load_epss_offline(
    *, cache_dir: Path | None = None
) -> tuple[dict[str, EpssEntry], CacheEntry]:
    entry = read_cached(EPSS_CACHE_NAME, EPSS_CACHE_FILE, cache_dir=cache_dir)
    return parse_epss_file(entry.path), entry
