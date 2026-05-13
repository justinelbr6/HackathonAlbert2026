"""ML pipeline orchestration.

The pipeline reads `.normalized.jsonl` files produced by the ingestion
layer, fits the per-format `AnomalyDetector` on the whole batch, runs
the TF-IDF `MitreTtpTagger` on every log, and emits one `LogPrediction`
per log so the downstream scoring engine (Étape 4) has everything it
needs to produce an explainable priority score.

Audit hooks:
  - `ml.pipeline.start` with the input count and source files.
  - `ml.anomaly.fit.{forest,heuristic}` per source_format (from detector).
  - `ml.tagger.fit.ok` (from tagger).
  - `ml.pipeline.done` with output count, top-N anomaly scores summary,
    and the SHA-256 of the prediction file.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from marine_log_sentinel.ingestion.schema import NormalizedLog
from marine_log_sentinel.ml.anomaly import AnomalyDetector
from marine_log_sentinel.ml.models import LogPrediction
from marine_log_sentinel.ml.tagging import MitreTtpTagger, expand_query_text
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel import ThreatIntelSnapshot, load_threat_intel

LOGGER = get_logger(__name__)

_RAW_EXCERPT_MAX = 200


@dataclass
class PipelineResult:
    predictions: list[LogPrediction]
    output_path: Path | None
    output_sha256: str | None
    tagger_vocab_size: int
    anomaly_summary: dict[str, dict[str, object]]


def _truncate_raw(raw: str, *, limit: int = _RAW_EXCERPT_MAX) -> str:
    if len(raw) <= limit:
        return raw
    return raw[:limit] + " ... [truncated]"


def _read_normalized_files(paths: Iterable[Path]) -> list[NormalizedLog]:
    logs: list[NormalizedLog] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                logs.append(NormalizedLog.model_validate_json(line))
    return logs


def _resolve_input_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    return sorted(input_path.glob("*.jsonl"))


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_logs(
    logs: list[NormalizedLog],
    *,
    snapshot: ThreatIntelSnapshot | None = None,
    tagger: MitreTtpTagger | None = None,
    detector: AnomalyDetector | None = None,
    top_k_ttps: int = 5,
    min_ttp_score: float = 0.04,
) -> tuple[list[LogPrediction], MitreTtpTagger, AnomalyDetector]:
    """Run the ML pipeline on a list of normalized logs (no I/O).

    `snapshot`, `tagger` and `detector` are injectable so the pipeline
    is testable and reusable in tighter loops (e.g., one-shot scoring of
    a single log in Étape 4).
    """

    if not logs:
        return (
            [],
            tagger if tagger is not None else MitreTtpTagger(),
            detector if detector is not None else AnomalyDetector(),
        )

    if tagger is None:
        if snapshot is None:
            snapshot = load_threat_intel()
        tagger = MitreTtpTagger().fit(snapshot)
    if detector is None:
        detector = AnomalyDetector().fit(logs)

    anomaly_scores = detector.predict_batch(logs)
    boosted_texts = [expand_query_text(log.merged_text()) for log in logs]
    ttp_hits_per_log = tagger.batch_predict_top_k(
        boosted_texts,
        k=top_k_ttps,
        min_score=min_ttp_score,
    )

    predictions: list[LogPrediction] = []
    for log, anomaly, ttps in zip(logs, anomaly_scores, ttp_hits_per_log, strict=True):
        predictions.append(
            LogPrediction(
                timestamp_utc=log.timestamp_utc,
                source_format=log.source_format.value,
                event_category=log.event_category.value,
                source_file=log.source_file,
                raw_excerpt=_truncate_raw(log.raw),
                host=log.host,
                user=log.user,
                src_ip=log.src_ip,
                dst_ip=log.dst_ip,
                anomaly=anomaly,
                top_ttps=ttps,
            )
        )
    return predictions, tagger, detector


def analyze_path(
    input_path: Path,
    output_path: Path | None = None,
    *,
    top_k_ttps: int = 5,
    snapshot: ThreatIntelSnapshot | None = None,
) -> PipelineResult:
    """Read normalized JSONL files, run the ML pipeline, write predictions.

    Records two audit entries (`ml.pipeline.start`, `ml.pipeline.done`)
    framing the run so any decision later can be traced to this exact
    batch of predictions.
    """

    files = _resolve_input_files(input_path)
    if not files:
        raise FileNotFoundError(f"No .jsonl files found under {input_path}")

    logs = _read_normalized_files(files)
    audit_record(
        "ml.pipeline.start",
        payload={
            "input_path": str(input_path),
            "files": [str(f) for f in files],
            "n_logs": len(logs),
        },
    )

    if not logs:
        output_sha = None
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("", encoding="utf-8")
            output_sha = _sha256_of_file(output_path)
        audit_record(
            "ml.pipeline.done",
            payload={
                "n_predictions": 0,
                "tagger_vocab_size": 0,
                "tagger_signature": "",
                "anomaly_summary": {},
                "top_anomalies": [],
                "output_path": str(output_path) if output_path else None,
                "output_sha256": output_sha,
                "note": "empty_normalized_batch",
            },
        )
        LOGGER.info(
            "ml.pipeline.ok",
            extra={
                "n_predictions": 0,
                "tagger_vocab_size": 0,
                "output_path": str(output_path) if output_path else "",
                "output_sha256": (output_sha or "")[:12],
            },
        )
        return PipelineResult(
            predictions=[],
            output_path=output_path,
            output_sha256=output_sha,
            tagger_vocab_size=0,
            anomaly_summary={},
        )

    predictions, tagger, detector = analyze_logs(
        logs,
        snapshot=snapshot,
        top_k_ttps=top_k_ttps,
    )

    output_sha = None
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for pred in predictions:
                handle.write(pred.model_dump_json() + "\n")
        output_sha = _sha256_of_file(output_path)

    artifacts = tagger._ensure_fitted()
    summary = detector.fit_summary()
    top_n_preview = sorted(
        ({"score": p.anomaly.score, "source_file": p.source_file, "raw": p.raw_excerpt[:80]} for p in predictions),
        key=lambda x: -float(x["score"]),
    )[:5]

    audit_record(
        "ml.pipeline.done",
        payload={
            "n_predictions": len(predictions),
            "tagger_vocab_size": len(artifacts.vectorizer.vocabulary_),
            "tagger_signature": artifacts.snapshot_signature,
            "anomaly_summary": summary,
            "top_anomalies": top_n_preview,
            "output_path": str(output_path) if output_path else None,
            "output_sha256": output_sha,
        },
    )

    LOGGER.info(
        "ml.pipeline.ok",
        extra={
            "n_predictions": len(predictions),
            "tagger_vocab_size": len(artifacts.vectorizer.vocabulary_),
            "output_path": str(output_path) if output_path else "",
            "output_sha256": (output_sha or "")[:12],
        },
    )

    return PipelineResult(
        predictions=predictions,
        output_path=output_path,
        output_sha256=output_sha,
        tagger_vocab_size=len(artifacts.vectorizer.vocabulary_),
        anomaly_summary=summary,
    )
