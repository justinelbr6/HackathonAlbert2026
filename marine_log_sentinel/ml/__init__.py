"""Machine Learning layer (TTP tagging via TF-IDF, anomaly detection)."""

from marine_log_sentinel.ml.anomaly import AnomalyDetector
from marine_log_sentinel.ml.features import FEATURE_NAMES, build_feature_matrix, extract_features
from marine_log_sentinel.ml.models import AnomalyScore, LogPrediction, TtpHit
from marine_log_sentinel.ml.pipeline import PipelineResult, analyze_logs, analyze_path
from marine_log_sentinel.ml.tagging import MitreTtpTagger, expand_query_text

__all__ = [
    "AnomalyDetector",
    "AnomalyScore",
    "FEATURE_NAMES",
    "LogPrediction",
    "MitreTtpTagger",
    "PipelineResult",
    "TtpHit",
    "analyze_logs",
    "analyze_path",
    "build_feature_matrix",
    "expand_query_text",
    "extract_features",
]
