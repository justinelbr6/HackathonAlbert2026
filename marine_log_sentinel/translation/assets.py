"""Marine asset inventory: maps hosts / IPs to criticality multipliers.

JSON schema (stdlib `json`, no PyYAML dependency)::

    {
      "default_criticality": "medium",
      "hosts": {
        "192.168.1.10": {"criticality": "high", "designation": "Serveur X"},
        "HOSTNAME": {"criticality": "mission_critical", "designation": "..."}
      }
    }

Allowed criticality tokens: ``low``, ``medium``, ``high``, ``mission_critical``.
Factors are clamped later by ``ScoringWeights.asset_factor_*``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from marine_log_sentinel.ml.models import LogPrediction

_CRITICALITY_TO_FACTOR: dict[str, float] = {
    "low": 0.85,
    "medium": 1.0,
    "high": 1.35,
    "mission_critical": 1.85,
}


def _norm_key(value: str) -> str:
    return value.strip().lower()


@dataclass(frozen=True)
class AssetHit:
    """Result of resolving one normalized log against the inventory."""

    factor: float
    designation_fr: str | None
    matched_key: str | None


@dataclass(frozen=True)
class AssetInventory:
    """Host/IP keyed inventory loaded from JSON."""

    hosts: dict[str, dict[str, Any]]
    default_factor: float

    @classmethod
    def load(cls, path: Path) -> AssetInventory:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("asset inventory root must be a JSON object")
        hosts_raw = raw.get("hosts") or {}
        if not isinstance(hosts_raw, dict):
            raise ValueError("'hosts' must be an object")
        hosts: dict[str, dict[str, Any]] = {}
        for key, meta in hosts_raw.items():
            if not isinstance(meta, dict):
                continue
            hosts[_norm_key(str(key))] = meta
        default_crit = str(raw.get("default_criticality") or "medium").strip().lower()
        default_factor = _CRITICALITY_TO_FACTOR.get(default_crit, 1.0)
        return cls(hosts=hosts, default_factor=default_factor)

    def resolve(self, prediction: LogPrediction) -> AssetHit:
        candidates: list[str] = []
        if prediction.host:
            candidates.append(prediction.host)
        if prediction.src_ip:
            candidates.append(prediction.src_ip)
        if prediction.dst_ip:
            candidates.append(prediction.dst_ip)

        for cand in candidates:
            meta = self.hosts.get(_norm_key(cand))
            if meta is None:
                continue
            crit = str(meta.get("criticality") or "medium").strip().lower()
            factor = _CRITICALITY_TO_FACTOR.get(crit, self.default_factor)
            designation = meta.get("designation")
            label = str(designation).strip() if designation else None
            return AssetHit(factor=factor, designation_fr=label, matched_key=cand)

        return AssetHit(factor=self.default_factor, designation_fr=None, matched_key=None)


def try_load_inventory(path: Path | None) -> AssetInventory | None:
    if path is None or not path.exists():
        return None
    return AssetInventory.load(path)
