"""Central configuration for Marine Log Sentinel.

Single source of truth for paths and runtime flags. Components MUST NOT
hardcode paths or feature flags elsewhere: every certified run can be
reproduced by inspecting `SETTINGS` and the audit log.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings.

    `air_gap_mode` is the master security switch. When True, no component is
    allowed to perform outbound network I/O; the threat intelligence layer
    must read from the local cache only.
    """

    project_root: Path = PROJECT_ROOT
    data_dir: Path = PROJECT_ROOT / "data"
    cache_dir: Path = PROJECT_ROOT / "data" / "cache"
    snapshots_dir: Path = PROJECT_ROOT / "data" / "snapshots"
    audit_log_path: Path = PROJECT_ROOT / "data" / "audit" / "audit.log.jsonl"
    runtime_log_dir: Path = PROJECT_ROOT / "data" / "runtime"
    reports_dir: Path = PROJECT_ROOT / "data" / "reports"
    air_gap_mode: bool = field(default_factory=lambda: _env_bool("MLS_AIR_GAP", False))
    log_level: str = field(default_factory=lambda: os.environ.get("MLS_LOG_LEVEL", "INFO"))
    # Same-actor sequential memory (SQLite), see marine_log_sentinel/sequence/
    sequence_db_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "data" / "runtime" / "sequence.sqlite"
    )

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.cache_dir,
            self.snapshots_dir,
            self.audit_log_path.parent,
            self.runtime_log_dir,
            self.reports_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


SETTINGS = Settings()
