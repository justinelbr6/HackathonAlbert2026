"""Pydantic models for the ML layer outputs.

`TtpHit` is the unit produced by the tagger.
`AnomalyScore` is the unit produced by the per-format anomaly detector.
`LogPrediction` is what the orchestration pipeline emits for each log:
a single record that downstream layers (scoring, reporting) consume.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TtpHit(BaseModel):
    """One MITRE technique attributed to a log by the tagger."""

    model_config = ConfigDict(extra="forbid")
    technique_id: str
    technique_name: str
    score: float = Field(..., ge=0.0, le=1.0)
    tactics: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_external_id: Optional[str] = None
    rationale_terms: list[str] = Field(
        default_factory=list,
        description="Top contributing terms from the log text, for auditability.",
    )


class AnomalyScore(BaseModel):
    """Output of the per-source-format anomaly detector for one log."""

    model_config = ConfigDict(extra="forbid")
    score: float = Field(..., ge=0.0, le=1.0)
    method: str
    model_id: Optional[str] = None
    features_used: list[str] = Field(default_factory=list)


class LogPrediction(BaseModel):
    """The ML pipeline's verdict on a single normalized log."""

    model_config = ConfigDict(extra="forbid")
    timestamp_utc: datetime
    source_format: str
    event_category: str
    source_file: str
    raw_excerpt: str
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    anomaly: AnomalyScore
    top_ttps: list[TtpHit] = Field(default_factory=list)
