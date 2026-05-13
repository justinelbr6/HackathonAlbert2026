"""Pydantic models for the scoring layer outputs.

`ScoredLog` is the unit the reporting layer (Étape 5+6) consumes.
`EvidenceChain` is the *defensible* part: the sequence of facts that
justifies the final score, expressed as concrete TTPs, CVEs and
mitigations rather than opaque numbers.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from marine_log_sentinel.ml.models import LogPrediction, TtpHit


class CveContext(BaseModel):
    """Snapshot-time facts about a CVE that is reachable from our log."""

    model_config = ConfigDict(extra="forbid")
    cve_id: str
    via_ttp: str
    cvss_score: Optional[float] = None
    kev_listed: bool = False
    kev_known_ransomware: Optional[bool] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    description_excerpt: Optional[str] = None


class MitigationRef(BaseModel):
    """One MITRE mitigation we can suggest as a defensive action."""

    model_config = ConfigDict(extra="forbid")
    mitigation_id: str
    name: str
    via_ttp: str


class LogSourceRef(BaseModel):
    """A log source that *would have* detected the suspected technique.

    Surfacing these in the report is the *"Log as Code"* deliverable
    from the original challenge: 'collect this exact log channel'.
    """

    model_config = ConfigDict(extra="forbid")
    name: str
    channel: Optional[str] = None
    via_ttp: str


class ScoreBreakdown(BaseModel):
    """Each weighted term of the formula, exposed for audit and UI."""

    model_config = ConfigDict(extra="forbid")
    anomaly_term: float
    ttp_term: float
    cve_term: float
    suspicious_term: float
    kev_boost_applied: float
    asset_factor: float
    base_score: float
    final_score: float


class EvidenceChain(BaseModel):
    """All the explainable facts that produced the score."""

    model_config = ConfigDict(extra="forbid")
    top_ttp: Optional[TtpHit] = None
    related_cves: list[CveContext] = Field(default_factory=list)
    mitigations: list[MitigationRef] = Field(default_factory=list)
    detection_log_sources: list[LogSourceRef] = Field(default_factory=list)
    cvss_risk_value: float = 0.0
    epss_risk_value: float = 0.0
    any_kev_listed: bool = False
    rationale_terms: list[str] = Field(default_factory=list)


class SequenceContext(BaseModel):
    """Same-actor time chain: point-in-time vs effective merged risk."""

    model_config = ConfigDict(extra="forbid")
    actor_key: str
    chain_index: int = Field(..., ge=1)
    point_in_time_score: float = Field(..., ge=0.0, le=100.0)
    point_in_time_band: str
    effective_score: float = Field(..., ge=0.0, le=100.0)
    effective_band: str
    days_since_actor_first_event: float = 0.0
    days_since_previous_event: Optional[float] = None
    decayed_peak_carry_in: float = 0.0
    ttp_repeat_bonus: float = 0.0
    policy_fingerprint: str = ""
    rationale_fr: str = ""


class ScoredLog(BaseModel):
    """A log + its priority score + its full chain of explainable evidence."""

    model_config = ConfigDict(extra="forbid")
    prediction: LogPrediction
    score: float = Field(..., ge=0.0, le=100.0)
    severity_band: str
    breakdown: ScoreBreakdown
    evidence: EvidenceChain
    weights_fingerprint: str
    bands_fingerprint: str
    sequence: Optional[SequenceContext] = None
