"""Scoring & correlation layer (Étape 4): composite, auditable risk score."""

from marine_log_sentinel.scoring.engine import (
    ScoringEngine,
    build_default_engine,
    score_predictions_file,
)
from marine_log_sentinel.scoring.models import (
    CveContext,
    EvidenceChain,
    LogSourceRef,
    MitigationRef,
    ScoreBreakdown,
    ScoredLog,
    SequenceContext,
)
from marine_log_sentinel.scoring.weights import (
    DEFAULT_BANDS,
    DEFAULT_WEIGHTS,
    ScoringWeights,
    SeverityBands,
)

__all__ = [
    "CveContext",
    "DEFAULT_BANDS",
    "DEFAULT_WEIGHTS",
    "EvidenceChain",
    "LogSourceRef",
    "MitigationRef",
    "ScoreBreakdown",
    "ScoredLog",
    "SequenceContext",
    "ScoringEngine",
    "ScoringWeights",
    "SeverityBands",
    "build_default_engine",
    "score_predictions_file",
]
