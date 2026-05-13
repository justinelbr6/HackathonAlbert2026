"""Aggregate scored logs into *attack narratives* expressed as phased goals.

Each **phase** is a MITRE ATT&CK *tactic* (the abstract step: reconnaissance,
accès initial, exécution, …).  Under an phase we attach every **means**
observed across logs (techniques Txxxx), analogous to alternate ways of
performing that step (the user metaphor: jumping the fence vs digging —
different techniques, same objective captured by the tactic).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from marine_log_sentinel.ml.models import TtpHit
from marine_log_sentinel.scoring.models import ScoredLog
from marine_log_sentinel.threat_intel.snapshot import ThreatIntelSnapshot

_UNKNOWN_TACTIC = "__unknown__"


# Typical Enterprise ATT&CK ordering (shortnames, MITRE convention).
MITRE_KILL_CHAIN_TAC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


def _tactic_sort_key(short: str) -> int:
    try:
        return MITRE_KILL_CHAIN_TAC_ORDER.index(short)
    except ValueError:
        return len(MITRE_KILL_CHAIN_TAC_ORDER) + 42


def _resolve_tactics_for_hit(hit: TtpHit, snapshot: ThreatIntelSnapshot) -> list[str]:
    out: list[str] = []
    for t in hit.tactics:
        if t not in out:
            out.append(t)
    if out:
        return out
    tech = snapshot.lookup_technique(hit.technique_id.strip().upper())
    if tech and tech.tactics:
        return list(tech.tactics)
    return [_UNKNOWN_TACTIC]


def _display_tactic(snapshot: ThreatIntelSnapshot, tac_short: str) -> tuple[str, str]:
    if tac_short == _UNKNOWN_TACTIC:
        return _UNKNOWN_TACTIC, "(Phase ATT&CK indéterminée — technique sans tactique résolue)"
    tac = snapshot.tactics.get(tac_short)
    if tac is None:
        return tac_short, tac_short.replace("-", " ").title()
    return tac.shortname, tac.name


def _actor_partition_key(sl: ScoredLog) -> str:
    seq = sl.sequence
    if seq is not None and seq.actor_key and str(seq.actor_key).strip():
        return str(seq.actor_key).strip()
    return "__sans_attribution_acteur__"


def _actor_label(actor_key: str) -> str:
    if actor_key == "__sans_attribution_acteur__":
        return "Ensemble · sans attribution acteur (logs non corrélés)"
    return actor_key


@dataclass
class MeansObservation:
    """One concrete attribution (means) underpinning an abstract tactical goal."""

    timestamp_utc: datetime
    technique_id: str
    technique_name: str
    anomaly_score: float
    log_final_score: float
    severity_band: str
    source_format: str


@dataclass
class AttackCampaignStep:
    """One abstract phase (tactical goal), with alternate concrete means."""

    tactic_shortname: str
    tactic_display_name: str
    chronological_index: int
    narrative_fr: str
    means_observed: list[MeansObservation] = field(default_factory=list)


@dataclass
class AttackCampaignPath:
    """Ordered phases for one actor-or-none partition."""

    actor_internal_key: str
    actor_label_fr: str
    phases: list[AttackCampaignStep] = field(default_factory=list)


@dataclass
class AttackMapBuildResult:
    campaigns: list[AttackCampaignPath]
    rows_skipped_low_score: int
    rows_without_ttp: int


def build_attack_map_from_scored(
    rows: list[ScoredLog],
    snapshot: ThreatIntelSnapshot,
    *,
    min_log_score: float = 0.0,
    max_ttps_per_event: int = 5,
    merge_repeat_tactic_into_same_step_if_consecutive: bool = True,
) -> AttackMapBuildResult:
    """Build phased attack timelines from chronological scored logs."""

    sorted_rows = sorted(rows, key=lambda r: r.prediction.timestamp_utc)
    buckets: dict[str, AttackCampaignPath] = {}

    skipped = 0
    no_ttp = 0

    for sl in sorted_rows:
        score = float(sl.score)
        if score < min_log_score:
            skipped += 1
            continue

        hits = list(sl.prediction.top_ttps[: max(0, max_ttps_per_event)])
        if not hits and sl.evidence.top_ttp:
            hits = [sl.evidence.top_ttp]
        if not hits:
            no_ttp += 1
            continue

        actor_k = _actor_partition_key(sl)
        path = buckets.setdefault(
            actor_k,
            AttackCampaignPath(
                actor_internal_key=actor_k,
                actor_label_fr=_actor_label(actor_k),
            ),
        )

        anomaly = float(sl.prediction.anomaly.score)

        batch: list[tuple[str, str, MeansObservation]] = []
        seen_event_tactics: set[tuple[str, str]] = set()
        for hit in hits:
            for tac in sorted(
                _resolve_tactics_for_hit(hit, snapshot),
                key=_tactic_sort_key,
            ):
                tac_key = tac.strip().lower()
                pair = (tac_key, hit.technique_id.upper())
                if pair in seen_event_tactics:
                    continue
                seen_event_tactics.add(pair)
                _, tac_name = _display_tactic(snapshot, tac_key)
                mob = MeansObservation(
                    timestamp_utc=sl.prediction.timestamp_utc,
                    technique_id=hit.technique_id.upper(),
                    technique_name=hit.technique_name,
                    anomaly_score=anomaly,
                    log_final_score=score,
                    severity_band=sl.severity_band,
                    source_format=sl.prediction.source_format,
                )
                batch.append((tac_key, tac_name, mob))

        batch.sort(key=lambda row: (_tactic_sort_key(row[0]), row[2].timestamp_utc))

        for tac_key, tac_display, mob in batch:
            phases = path.phases
            if (
                merge_repeat_tactic_into_same_step_if_consecutive
                and phases
                and phases[-1].tactic_shortname == tac_key
            ):
                step = phases[-1]
                step.means_observed.append(mob)
                continue

            narrative = (
                f"Réaliser la phase « {tac_display} » au sens ATT&CK (objectif commun), "
                f"avec en moyenne observées les techniques décrites comme *moyens* ci-dessous."
            )
            new_step = AttackCampaignStep(
                tactic_shortname=tac_key,
                tactic_display_name=tac_display,
                chronological_index=len(phases) + 1,
                narrative_fr=narrative,
                means_observed=[mob],
            )
            phases.append(new_step)

    return AttackMapBuildResult(
        campaigns=sorted(buckets.values(), key=lambda c: c.actor_internal_key),
        rows_skipped_low_score=skipped,
        rows_without_ttp=no_ttp,
    )


def attack_map_flat_frame(build: AttackMapBuildResult) -> pd.DataFrame:
    """Flatten campaigns for tabular dashboards / exports."""

    out: list[dict[str, object]] = []
    for camp in build.campaigns:
        for ph in camp.phases:
            for m in ph.means_observed:
                out.append(
                    {
                        "acteur": camp.actor_label_fr,
                        "etape_ordre": ph.chronological_index,
                        "tactique_short": ph.tactic_shortname,
                        "tactique_libelle": ph.tactic_display_name,
                        "instant_utc": m.timestamp_utc,
                        "technique_id": m.technique_id,
                        "technique_nom": m.technique_name,
                        "score_log": round(m.log_final_score, 2),
                        "bande": m.severity_band,
                        "format_source": m.source_format,
                        "score_anomalie": round(m.anomaly_score, 4),
                    }
                )
    if not out:
        return pd.DataFrame(
            columns=[
                "acteur",
                "etape_ordre",
                "tactique_short",
                "tactique_libelle",
                "instant_utc",
                "technique_id",
                "technique_nom",
                "score_log",
                "bande",
                "format_source",
                "score_anomalie",
            ]
        )
    return pd.DataFrame(out)


def format_attack_campaigns_markdown_fr(build: AttackMapBuildResult) -> str:
    """Human-readable synopsis for Markdown / rapport."""

    chunks: list[str] = []
    for camp in build.campaigns:
        lines = [
            f"### {camp.actor_label_fr}",
            "",
            "**Chemin plausible reconstitué** (phase = intention tactique commune ; sous-points = moyens / techniques observés) :",
            "",
        ]
        for ph in camp.phases:
            lines.append(
                f"{ph.chronological_index}. **{ph.tactic_display_name}** "
                f"(`{ph.tactic_shortname}`) — objectif hors du « comment » précis.",
            )
            if ph.means_observed:
                for m in ph.means_observed:
                    ts = m.timestamp_utc.strftime("%Y-%m-%d %H:%MZ")
                    lines.append(
                        f"   - `{m.technique_id}` · {m.technique_name} · "
                        f"score={m.log_final_score:.1f} ({m.severity_band}) · `{ts}`"
                    )
            lines.append("")
        chunks.append("\n".join(lines).rstrip())

    footer = []
    footer.append("")
    footer.append(f"*Éléments exclus (score seuil ou sans TTP) : skips={build.rows_skipped_low_score}, sans TTP={build.rows_without_ttp}.*")
    return "\n\n".join(chunks) + "\n".join(footer)
