"""MITRE ATT&CK STIX bundle loader (offline, no network).

Walks the official MITRE ATT&CK Enterprise STIX 2.1 bundle and resolves
all relationships we care about:
  - `subtechnique-of` -> parent/child link between techniques
  - `mitigates`       -> course-of-action linked to attack-pattern
  - `detects`         -> x-mitre-detection-strategy linked to attack-pattern

The result is a set of strongly-typed pydantic objects (cf. `.models`)
ready to be cross-linked with CVE data by the snapshot orchestrator.

Deprecated and revoked objects are filtered out, so consumers always see
the current MITRE state from the input bundle.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from marine_log_sentinel.threat_intel.models import (
    MitreAnalytic,
    MitreDataComponent,
    MitreDataSource,
    MitreDetectionStrategy,
    MitreLogSource,
    MitreMitigation,
    MitreTactic,
    MitreTechnique,
)


def _external_id(stix_object: dict[str, Any]) -> str:
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id") or "")
    return ""


def _clean_channel(value: Any) -> str | None:
    """Normalize log-source channels.

    The MITRE bundle occasionally carries the literal string `"None"` (or
    blank/whitespace) for channels, which would render confusingly in
    every officer-facing report.
    """

    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a", "na"}:
        return None
    return text


def _is_active(stix_object: dict[str, Any]) -> bool:
    return not stix_object.get("revoked") and not stix_object.get("x_mitre_deprecated")


def _read_bundle(zip_path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(zip_path) as archive:
        member = next(
            (name for name in archive.namelist() if name.endswith("enterprise-attack.json")),
            "enterprise-attack.json",
        )
        with archive.open(member) as handle:
            return json.load(handle)


def load_mitre_entities(zip_path: Path) -> dict[str, Any]:
    """Parse the MITRE STIX bundle and return its resolved entities.

    Output dict keys:
      - techniques            : dict[external_id, MitreTechnique]
      - tactics               : dict[shortname, MitreTactic]
      - data_components       : dict[stix_id, MitreDataComponent]
      - data_sources          : dict[stix_id, MitreDataSource]
      - detection_strategies  : dict[stix_id, MitreDetectionStrategy]
      - analytics             : dict[stix_id, MitreAnalytic]
      - mitigations           : dict[external_id, MitreMitigation]
    """

    bundle = _read_bundle(Path(zip_path))
    objects = bundle.get("objects", [])

    technique_by_stix: dict[str, MitreTechnique] = {}
    techniques: dict[str, MitreTechnique] = {}
    tactics: dict[str, MitreTactic] = {}
    data_components: dict[str, MitreDataComponent] = {}
    data_sources: dict[str, MitreDataSource] = {}
    detection_strategies: dict[str, MitreDetectionStrategy] = {}
    analytics: dict[str, MitreAnalytic] = {}
    mitigations: dict[str, MitreMitigation] = {}
    mitigation_external_by_stix: dict[str, str] = {}

    for obj in objects:
        if not _is_active(obj):
            continue
        kind = obj.get("type")

        if kind == "attack-pattern":
            ext_id = _external_id(obj)
            if not ext_id:
                continue
            tech = MitreTechnique(
                stix_id=obj["id"],
                external_id=ext_id,
                name=obj.get("name", ""),
                description=obj.get("description"),
                tactics=[
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
                ],
                platforms=list(obj.get("x_mitre_platforms", []) or []),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
            )
            technique_by_stix[obj["id"]] = tech
            techniques[ext_id] = tech

        elif kind == "x-mitre-tactic":
            ext_id = _external_id(obj)
            shortname = obj.get("x_mitre_shortname", "")
            if not shortname:
                continue
            tactics[shortname] = MitreTactic(
                stix_id=obj["id"],
                external_id=ext_id or obj["id"],
                name=obj.get("name", ""),
                shortname=shortname,
                description=obj.get("description"),
            )

        elif kind == "x-mitre-data-component":
            log_sources = [
                MitreLogSource(name=ls.get("name", ""), channel=_clean_channel(ls.get("channel")))
                for ls in obj.get("x_mitre_log_sources", [])
                if ls.get("name")
            ]
            data_components[obj["id"]] = MitreDataComponent(
                stix_id=obj["id"],
                name=obj.get("name", ""),
                description=obj.get("description"),
                log_sources=log_sources,
            )

        elif kind == "x-mitre-data-source":
            data_sources[obj["id"]] = MitreDataSource(
                stix_id=obj["id"],
                external_id=_external_id(obj) or None,
                name=obj.get("name", ""),
                description=obj.get("description"),
            )

        elif kind == "x-mitre-detection-strategy":
            detection_strategies[obj["id"]] = MitreDetectionStrategy(
                stix_id=obj["id"],
                name=obj.get("name", ""),
                description=obj.get("description"),
                analytic_stix_ids=list(obj.get("x_mitre_analytic_refs", []) or []),
            )

        elif kind == "x-mitre-analytic":
            log_sources: list[MitreLogSource] = []
            data_component_refs: list[str] = []
            for ls in obj.get("x_mitre_log_source_references", []) or []:
                name = ls.get("name")
                if name:
                    log_sources.append(MitreLogSource(name=name, channel=_clean_channel(ls.get("channel"))))
                ref = ls.get("x_mitre_data_component_ref")
                if ref and ref not in data_component_refs:
                    data_component_refs.append(ref)
            analytics[obj["id"]] = MitreAnalytic(
                stix_id=obj["id"],
                name=obj.get("name", ""),
                description=obj.get("description"),
                platforms=list(obj.get("x_mitre_platforms", []) or []),
                log_sources=log_sources,
                data_component_stix_ids=data_component_refs,
            )

        elif kind == "course-of-action":
            ext_id = _external_id(obj)
            if not ext_id:
                continue
            mitigation = MitreMitigation(
                stix_id=obj["id"],
                external_id=ext_id,
                name=obj.get("name", ""),
                description=obj.get("description"),
            )
            mitigations[ext_id] = mitigation
            mitigation_external_by_stix[obj["id"]] = ext_id

    for obj in objects:
        if obj.get("type") != "relationship" or not _is_active(obj):
            continue
        rel_type = obj.get("relationship_type")
        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")

        if rel_type == "subtechnique-of":
            sub = technique_by_stix.get(source_ref)
            parent = technique_by_stix.get(target_ref)
            if sub and parent:
                sub.parent_external_id = parent.external_id
                if sub.external_id not in parent.sub_technique_external_ids:
                    parent.sub_technique_external_ids.append(sub.external_id)

        elif rel_type == "mitigates":
            mitigation_ext = mitigation_external_by_stix.get(source_ref)
            tech = technique_by_stix.get(target_ref)
            if not (mitigation_ext and tech):
                continue
            if mitigation_ext not in tech.mitigation_external_ids:
                tech.mitigation_external_ids.append(mitigation_ext)
            mitigation = mitigations.get(mitigation_ext)
            if mitigation and tech.external_id not in mitigation.mitigates_technique_external_ids:
                mitigation.mitigates_technique_external_ids.append(tech.external_id)

        elif rel_type == "detects":
            strategy = detection_strategies.get(source_ref)
            tech = technique_by_stix.get(target_ref)
            if not (strategy and tech):
                continue
            if strategy.stix_id not in tech.detection_strategy_stix_ids:
                tech.detection_strategy_stix_ids.append(strategy.stix_id)
            if tech.external_id not in strategy.detects_technique_external_ids:
                strategy.detects_technique_external_ids.append(tech.external_id)

    return {
        "techniques": techniques,
        "tactics": tactics,
        "data_components": data_components,
        "data_sources": data_sources,
        "detection_strategies": detection_strategies,
        "analytics": analytics,
        "mitigations": mitigations,
    }
