"""Pydantic models for the local Threat Intelligence snapshot.

Each model corresponds to a concept from MITRE ATT&CK or CVE/NVD. They are
intentionally narrow: only the fields the downstream pipeline needs to
build a defensible risk score and a defensible logging policy are kept.
"""

from __future__ import annotations

from datetime import date
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class MitreLogSource(BaseModel):
    """Concrete log source pointer.

    Example: {"name": "WinEventLog:Security", "channel": "EventCode=4625"}.
    Critical for the *Log as Code* angle of the project: this is the
    direct contract between a detection strategy and a log to collect.
    """

    model_config = ConfigDict(extra="ignore")
    name: str
    channel: Optional[str] = None


class MitreAnalytic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    name: str
    description: Optional[str] = None
    platforms: list[str] = Field(default_factory=list)
    log_sources: list[MitreLogSource] = Field(default_factory=list)
    data_component_stix_ids: list[str] = Field(default_factory=list)


class MitreDataComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    name: str
    description: Optional[str] = None
    log_sources: list[MitreLogSource] = Field(default_factory=list)


class MitreDataSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    external_id: Optional[str] = None
    name: str
    description: Optional[str] = None


class MitreDetectionStrategy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    name: str
    description: Optional[str] = None
    analytic_stix_ids: list[str] = Field(default_factory=list)
    detects_technique_external_ids: list[str] = Field(default_factory=list)


class MitreMitigation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    external_id: str
    name: str
    description: Optional[str] = None
    mitigates_technique_external_ids: list[str] = Field(default_factory=list)


class MitreTactic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    external_id: str
    name: str
    shortname: str
    description: Optional[str] = None


class MitreTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stix_id: str
    external_id: str
    name: str
    description: Optional[str] = None
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_external_id: Optional[str] = None
    sub_technique_external_ids: list[str] = Field(default_factory=list)
    mitigation_external_ids: list[str] = Field(default_factory=list)
    detection_strategy_stix_ids: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)


class CveRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[date] = None
    last_modified_date: Optional[date] = None
    exploitability: Optional[str] = None
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    affected_software: list[str] = Field(default_factory=list)
    patches: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    kev_listed: Optional[bool] = None
    kev_date_added: Optional[date] = None
    kev_known_ransomware: Optional[bool] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
