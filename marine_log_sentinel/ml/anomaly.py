"""Per-source-format anomaly detection.

We deliberately train **one IsolationForest per `source_format`** rather
than a single global model. The reason is dimensional:

  - A "long payload" is normal for Apache (URL parameters, query strings)
    but very suspicious for an authentication line in a Linux syslog.
  - A "high entropy" payload is the rule for network traffic (encoded
    PCAP data) but the exception for a process command line.
  - An IP-port pair is meaningless for a Sysmon process-create event.

Mixing them in a single model lets one format's normal swamp the other's
anomalies. The per-format approach also matches the way analysts triage:
"is this Sysmon event unusual *for Sysmon*?".

Cold-start protection
---------------------
If a `source_format` has fewer than `MIN_SAMPLES_FOR_FOREST` (5) records
in the fit batch, we fall back to a deterministic **heuristic** that
combines entropy and suspicious-token count. This keeps the pipeline
robust on tiny datasets (e.g., a single Suricata alert from the
challenge sample) without ever crashing or returning silently wrong
scores.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from marine_log_sentinel.ingestion.schema import NormalizedLog
from marine_log_sentinel.ml.features import (
    FEATURE_NAMES,
    build_feature_matrix,
    extract_features,
)
from marine_log_sentinel.ml.models import AnomalyScore
from marine_log_sentinel.observability.logger import get_logger

LOGGER = get_logger(__name__)

MIN_SAMPLES_FOR_FOREST = 5
DEFAULT_RANDOM_STATE = 42
DEFAULT_CONTAMINATION = "auto"
DEFAULT_N_ESTIMATORS = 200


def _sigmoid(x: float, *, slope: float = 8.0) -> float:
    """Map a decision_function value (~[-0.3, +0.3]) to an anomaly score in [0,1].

    `decision_function` is *positive* for normal points and negative for
    anomalies. We flip the sign so higher = more anomalous, then apply a
    sigmoid with a steep slope so the score is well-separated.
    """

    try:
        return 1.0 / (1.0 + math.exp(slope * x))
    except OverflowError:
        return 0.0 if x > 0 else 1.0


_NETWORK_ALERT_CATEGORY = "network_alert"
_SIGNATURE_SEVERITY_FLOOR = {
    "MAJOR": 0.6,
    "HIGH": 0.6,
    "CRITICAL": 0.75,
    "MEDIUM": 0.4,
    "MINOR": 0.3,
    "LOW": 0.25,
    "INFO": 0.15,
}


def _heuristic_score(log: NormalizedLog) -> float:
    """Fallback used when too few samples for an IsolationForest.

    Combines five orthogonal observations:
      - **entropy**: high (>4.5) ⇒ likely encoded payload (base64, hex...).
      - **suspicious_token_count**: even one match is a strong signal.
      - **merged_text_length**: very long lines often carry obfuscation.
      - **non_ascii_ratio**: > 5% non-ASCII in raw text is unusual.
      - **signature pre-judgement**: if the log carries a Suricata/IDS
        signature, we float the score to a category-dependent floor.
        Reason: an IDS alert was already pre-vetted as suspicious by a
        domain-specific engine, so it must never sit at 0.
    """

    features = extract_features(log)
    score = 0.0
    if features.entropy > 4.5:
        score += min(0.45, (features.entropy - 4.5) * 0.25)
    if features.suspicious_token_count > 0:
        score += min(0.4, 0.2 * features.suspicious_token_count)
    if features.merged_text_length > 2000:
        score += 0.1
    if features.non_ascii_ratio > 0.05:
        score += 0.05

    severity_floor = 0.0
    if log.signature_severity:
        severity_floor = _SIGNATURE_SEVERITY_FLOOR.get(log.signature_severity.upper(), 0.3)
    elif log.signature:
        severity_floor = 0.3
    elif log.event_category.value == _NETWORK_ALERT_CATEGORY:
        severity_floor = 0.35

    return min(1.0, max(score, severity_floor))


@dataclass
class _FormatModel:
    """Per-format trained state.

    Either `forest is not None` (we trained an IsolationForest and store
    the train-time decision range for clean normalization), or we kept
    the format in heuristic mode because we did not have enough samples.
    """

    source_format: str
    forest: IsolationForest | None = None
    feature_names: tuple[str, ...] = FEATURE_NAMES
    raw_min: float = 0.0
    raw_max: float = 0.0
    fit_size: int = 0
    method: str = "heuristic"


@dataclass
class AnomalyDetector:
    """Manages one IsolationForest per `source_format`."""

    n_estimators: int = DEFAULT_N_ESTIMATORS
    random_state: int = DEFAULT_RANDOM_STATE
    contamination: str | float = DEFAULT_CONTAMINATION
    models: dict[str, _FormatModel] = field(default_factory=dict)

    def fit(self, logs: Iterable[NormalizedLog]) -> "AnomalyDetector":
        """Train one IsolationForest per source_format from a flat log batch."""

        by_format: dict[str, list[NormalizedLog]] = {}
        for log in logs:
            by_format.setdefault(log.source_format.value, []).append(log)

        for source_format, batch in by_format.items():
            model = _FormatModel(source_format=source_format, fit_size=len(batch))
            if len(batch) >= MIN_SAMPLES_FOR_FOREST:
                matrix = build_feature_matrix(batch)
                forest = IsolationForest(
                    n_estimators=self.n_estimators,
                    contamination=self.contamination,
                    random_state=self.random_state,
                    bootstrap=False,
                )
                forest.fit(matrix)
                model.forest = forest
                decisions = forest.decision_function(matrix)
                model.raw_min = float(decisions.min())
                model.raw_max = float(decisions.max())
                model.method = "isolation_forest"
                LOGGER.info(
                    "ml.anomaly.fit.forest",
                    extra={
                        "source_format": source_format,
                        "n_samples": len(batch),
                        "decision_min": model.raw_min,
                        "decision_max": model.raw_max,
                    },
                )
            else:
                LOGGER.info(
                    "ml.anomaly.fit.heuristic",
                    extra={"source_format": source_format, "n_samples": len(batch)},
                )
            self.models[source_format] = model
        return self

    def predict(self, log: NormalizedLog) -> AnomalyScore:
        """Score a single log. Falls back to the heuristic if no forest was fit."""

        model = self.models.get(log.source_format.value)
        if model is None or model.forest is None:
            return AnomalyScore(
                score=_heuristic_score(log),
                method="heuristic",
                model_id=log.source_format.value,
                features_used=list(FEATURE_NAMES),
            )

        vector = extract_features(log).to_array().reshape(1, -1)
        raw = float(model.forest.decision_function(vector)[0])
        return AnomalyScore(
            score=_sigmoid(raw),
            method=model.method,
            model_id=f"{model.source_format}|n={model.fit_size}",
            features_used=list(model.feature_names),
        )

    def predict_batch(self, logs: Iterable[NormalizedLog]) -> list[AnomalyScore]:
        """Batch variant that groups by `source_format` for efficiency."""

        logs_list = list(logs)
        by_format: dict[str, list[tuple[int, NormalizedLog]]] = {}
        for index, log in enumerate(logs_list):
            by_format.setdefault(log.source_format.value, []).append((index, log))

        scores: list[AnomalyScore | None] = [None] * len(logs_list)
        for source_format, indexed_batch in by_format.items():
            model = self.models.get(source_format)
            if model is None or model.forest is None:
                for index, log in indexed_batch:
                    scores[index] = AnomalyScore(
                        score=_heuristic_score(log),
                        method="heuristic",
                        model_id=source_format,
                        features_used=list(FEATURE_NAMES),
                    )
                continue
            matrix = np.vstack(
                [extract_features(log).to_array() for _, log in indexed_batch]
            )
            decisions = model.forest.decision_function(matrix)
            for (index, _), raw in zip(indexed_batch, decisions, strict=True):
                scores[index] = AnomalyScore(
                    score=_sigmoid(float(raw)),
                    method=model.method,
                    model_id=f"{model.source_format}|n={model.fit_size}",
                    features_used=list(model.feature_names),
                )

        return [score for score in scores if score is not None]

    def fit_summary(self) -> dict[str, dict[str, object]]:
        """A compact recap used by the orchestration audit entry."""

        return {
            source_format: {
                "method": model.method,
                "fit_size": model.fit_size,
                "decision_min": model.raw_min,
                "decision_max": model.raw_max,
            }
            for source_format, model in self.models.items()
        }
