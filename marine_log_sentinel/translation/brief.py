"""Build French operational briefs from scored predictions."""

from __future__ import annotations

from pathlib import Path

from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.scoring.models import ScoredLog
from marine_log_sentinel.translation.assets import AssetHit, try_load_inventory
from marine_log_sentinel.translation.impacts import (
    headline_fr,
    mitigation_to_action_fr,
    niveau_operationnel_fr,
    operational_impacts_fr,
    summarize_for_command_fr,
)
from marine_log_sentinel.translation.models import OperationalBriefFr, TechnicalAnchors

LOGGER = get_logger(__name__)


def _collect_log_lines_fr(scored: ScoredLog, limit: int = 8) -> list[str]:
    lines: list[str] = []
    for ref in scored.evidence.detection_log_sources[:limit]:
        chan = f" (canal : {ref.channel})" if ref.channel else ""
        lines.append(
            f"Collecter les traces « {ref.name} »{chan} pour corréler avec la technique {ref.via_ttp}."
        )
    if not lines:
        lines.append(
            "Conserver les journaux sources déjà disponibles sur la passerelle SIEM "
            "et transmettre l'extrait brut associé à cet événement au SOC."
        )
    return lines


def build_operational_brief_fr(
    scored: ScoredLog,
    *,
    asset_hit: AssetHit | None = None,
) -> OperationalBriefFr:
    """Produce one French-language operational brief."""

    ev = scored.evidence
    ttp = ev.top_ttp
    cves = [c.cve_id for c in ev.related_cves]

    asset_line = None
    actif_identifie = None
    facteur_actif = None
    if asset_hit is not None:
        facteur_actif = asset_hit.factor
        if asset_hit.designation_fr and asset_hit.matched_key:
            actif_identifie = f"{asset_hit.designation_fr} ({asset_hit.matched_key})"
            asset_line = (
                f"L'actif concerné est identifié comme : {asset_hit.designation_fr} "
                f"(criticité reflétée dans le score)."
            )
        elif asset_hit.matched_key:
            actif_identifie = asset_hit.matched_key

    titre = headline_fr(ttp, scored.severity_band)
    niveau = niveau_operationnel_fr(scored.severity_band)

    impacts = list(operational_impacts_fr(ttp))

    actions: list[str] = []
    for mit in ev.mitigations[:6]:
        actions.append(mitigation_to_action_fr(mit.name, mit.mitigation_id))
    if not actions:
        actions.append(
            "Isoler ou restreindre l'accès réseau du système concerné dans la mesure compatible avec la mission."
        )
        actions.append(
            "Notifier le SOC interne ; ne pas détruire les journaux avant analyse."
        )

    journaux = _collect_log_lines_fr(scored)

    resume = summarize_for_command_fr(
        severity_band=scored.severity_band,
        ttp=ttp,
        cve_labels=cves,
        kev=ev.any_kev_listed,
        asset_line=asset_line,
    )

    tactic_labels = []
    if ttp:
        tactic_labels = list(ttp.tactics[:6])

    anchors = TechnicalAnchors(
        technique_ids=[ttp.technique_id] if ttp else [],
        tactic_short_labels=tactic_labels,
        cve_ids=cves[:8],
        score_numerique=scored.score,
        bande_securite=scored.severity_band,
        kev_signale=ev.any_kev_listed,
    )

    return OperationalBriefFr(
        titre=titre,
        niveau_operationnel_fr=niveau,
        resume_pour_commandement=resume,
        impacts_operationnels=impacts,
        actions_prioritaires=actions[:8],
        journaux_et_traces_a_collecter=journaux,
        actif_identifie=actif_identifie,
        facteur_actif=facteur_actif,
        ancres_techniques=anchors,
    )


def briefs_from_scored_file(
    scored_path: Path,
    *,
    inventory_path: Path | None = None,
    output_path: Path | None = None,
    top_n: int | None = None,
) -> list[OperationalBriefFr]:
    """Read scored JSONL, attach optional inventory context, emit briefs."""

    inventory = try_load_inventory(inventory_path)

    with scored_path.open(encoding="utf-8") as handle:
        scored_logs = [
            ScoredLog.model_validate_json(line)
            for line in handle
            if line.strip()
        ]

    scored_logs.sort(key=lambda s: -s.score)
    if top_n is not None:
        scored_logs = scored_logs[:top_n]

    briefs: list[OperationalBriefFr] = []
    for entry in scored_logs:
        hit = inventory.resolve(entry.prediction) if inventory else None
        briefs.append(build_operational_brief_fr(entry, asset_hit=hit))

    output_sha = None
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for brief in briefs:
                handle.write(brief.model_dump_json() + "\n")
        import hashlib

        digest = hashlib.sha256()
        with output_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        output_sha = digest.hexdigest()

    audit_record(
        "translation.brief.run",
        payload={
            "input_scored_path": str(scored_path),
            "inventory_path": str(inventory_path) if inventory_path else None,
            "output_path": str(output_path) if output_path else None,
            "output_sha256": output_sha,
            "n_briefs": len(briefs),
        },
    )
    LOGGER.info(
        "translation.brief.ok",
        extra={"n_briefs": len(briefs), "inventory": bool(inventory)},
    )
    return briefs

