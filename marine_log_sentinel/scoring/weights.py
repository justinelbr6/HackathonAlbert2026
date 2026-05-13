"""Scoring weights — auditable, ajustable, versioned.

Centralizing every numeric parameter here makes the scoring engine
**defensible**: an analyst can inspect, justify and tune the values
without touching engine code, and the SHA-256 of this file is recorded
in the audit log every time the engine runs.

Each weight is bounded and the sum of the four signal weights is 1.0,
so before any KEV boost the *base* score lies in [0, 1] by construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScoringWeights:
    """Weighted parameters of the priority score formula.

    Invariants enforced at construction:
      - all signal weights are in [0, 1];
      - the four signal weights (anomaly, ttp_match, cve_severity,
        suspicious_tokens) sum to 1.0 (so `base` is bounded);
      - the kev_boost is in [0, 0.3] and applies *additively* on top of
        `base` to express CISA's "patch immediately" urgency;
      - asset_factor is multiplicative and constrained to [0.5, 2.0]
        so an officer-defined asset weighting cannot blow up the score.
    """

    anomaly: float = 0.30
    ttp_match: float = 0.25
    cve_severity: float = 0.35
    suspicious_tokens: float = 0.10
    kev_boost: float = 0.10
    ttp_score_scaling: float = 3.0
    cvss_weight_in_risk: float = 0.6
    epss_weight_in_risk: float = 0.4
    asset_factor_min: float = 0.5
    asset_factor_max: float = 2.0

    def __post_init__(self) -> None:
        signals = (
            self.anomaly,
            self.ttp_match,
            self.cve_severity,
            self.suspicious_tokens,
        )
        for value in signals:
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"Signal weight out of [0,1]: {value}")
        signal_sum = sum(signals)
        if not abs(signal_sum - 1.0) < 1e-6:
            raise ValueError(
                f"Signal weights must sum to 1.0, got {signal_sum:.4f}: "
                f"anomaly={self.anomaly}, ttp_match={self.ttp_match}, "
                f"cve_severity={self.cve_severity}, suspicious_tokens={self.suspicious_tokens}"
            )
        if not 0.0 <= self.kev_boost <= 0.3:
            raise ValueError(f"kev_boost must be in [0, 0.3], got {self.kev_boost}")
        if not abs(self.cvss_weight_in_risk + self.epss_weight_in_risk - 1.0) < 1e-6:
            raise ValueError("cvss_weight_in_risk + epss_weight_in_risk must equal 1.0")

    def fingerprint(self) -> str:
        """Stable SHA-256 of the weight set, recorded in the audit log."""

        payload = json.dumps(asdict(self), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class SeverityBands:
    """Score thresholds for the four operational severity bands.

    Reading: any score >= `critical` belongs to CRITICAL, etc. The bands
    are inclusive on the lower bound.
    """

    critical: float = 70.0
    high: float = 50.0
    medium: float = 30.0

    def classify(self, score: float) -> str:
        if score >= self.critical:
            return "CRITICAL"
        if score >= self.high:
            return "HIGH"
        if score >= self.medium:
            return "MEDIUM"
        return "LOW"

    def fingerprint(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


DEFAULT_WEIGHTS = ScoringWeights()
DEFAULT_BANDS = SeverityBands()


def file_fingerprint() -> str:
    """SHA-256 of this module file. Recorded so the audit can prove which
    version of the weight code was actually loaded at run time.
    """

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
