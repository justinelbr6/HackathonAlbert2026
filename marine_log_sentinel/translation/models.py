"""Operational briefing models for non-cyber Marine officers (French).

These structures deliberately avoid jargon where possible while preserving
technical anchors (`ancres_techniques`) for SOC follow-up and audit.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TechnicalAnchors(BaseModel):
    """Pointers back to ATT&CK / CVE — kept separate from narrative text."""

    model_config = ConfigDict(extra="forbid")
    technique_ids: list[str] = Field(default_factory=list)
    tactic_short_labels: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    score_numerique: float = 0.0
    bande_securite: str = ""
    kev_signale: bool = False


class OperationalBriefFr(BaseModel):
    """One-page operational view derived from a `ScoredLog`."""

    model_config = ConfigDict(extra="forbid")
    titre: str
    niveau_operationnel_fr: str
    resume_pour_commandement: str
    impacts_operationnels: list[str] = Field(default_factory=list)
    actions_prioritaires: list[str] = Field(default_factory=list)
    journaux_et_traces_a_collecter: list[str] = Field(default_factory=list)
    actif_identifie: Optional[str] = None
    facteur_actif: Optional[float] = None
    ancres_techniques: TechnicalAnchors = Field(default_factory=TechnicalAnchors)
