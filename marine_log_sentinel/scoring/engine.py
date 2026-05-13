"""Scoring engine: a `LogPrediction` + the TI snapshot/graph → a `ScoredLog`.

How the final score is computed
================================

The score is a weighted sum of four orthogonal signals, with a single
**additive boost** when CISA has listed any linked CVE as currently
exploited (KEV), and a multiplicative **asset factor** that will be
populated by the Marine asset inventory in Étape 5:

    base   = w_anomaly   * anomaly_score
           + w_ttp       * normalize(top_ttp_score)
           + w_cve       * cve_risk
           + w_susp      * normalize(suspicious_token_count)

    if any related CVE is KEV listed:
        base += w_kev_boost

    final  = clamp(base, 0, 1) * asset_factor * 100

where ``cve_risk = max_over_linked_cves( 0.6*CVSS/10 + 0.4*EPSS )``.

Why a transparent linear formula instead of a learned model?
============================================================

We deliberately avoid a learned scorer here, for three reasons:

1. **No ground truth.** We don't have a labelled dataset of Marine logs
   with a `danger` flag. Training would either fabricate labels or
   import biases from another organization's incident history.

2. **Defendability.** A linear sum of named factors can be checked by
   an officer or an auditor: every point of the score can be traced
   back to one CVE, one TTP or one anomaly observation. The weights
   themselves are versioned (their SHA-256 is stored in the audit log
   alongside the score).

3. **Tunability without retraining.** Weights live in
   `weights.py` and can be hot-swapped at any time. A trained model
   would force a full retrain to change the trade-off.

The trade-off is that the formula is necessarily *coarse*. Étape 7
(robustness) will explore confidence intervals and a learning-to-rank
upgrade once we have labelled feedback from the analyst loop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from pydantic import ValidationError

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.ml.models import LogPrediction, TtpHit
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.scoring.models import (
    CveContext,
    EvidenceChain,
    LogSourceRef,
    MitigationRef,
    ScoreBreakdown,
    ScoredLog,
)
from marine_log_sentinel.scoring.weights import (
    DEFAULT_BANDS,
    DEFAULT_WEIGHTS,
    ScoringWeights,
    SeverityBands,
    file_fingerprint,
)
from marine_log_sentinel.threat_intel import (
    ThreatGraph,
    ThreatIntelSnapshot,
    build_threat_graph,
    load_threat_intel,
)
from marine_log_sentinel.translation.assets import try_load_inventory
from marine_log_sentinel.sequence.engine import (
    apply_sequential_scoring,
    sort_by_priority,
    sort_chronological,
)
from marine_log_sentinel.sequence.policy import DEFAULT_SEQUENCE_POLICY
from marine_log_sentinel.sequence.store import SequenceStore

LOGGER = get_logger(__name__)

_SUSPICIOUS_TOKEN_NORMALIZATION = 5.0
_DESCRIPTION_EXCERPT_LEN = 160
_MAX_CVES_PER_EVIDENCE = 5
_MAX_MITIGATIONS_PER_EVIDENCE = 5
_MAX_LOG_SOURCES_PER_EVIDENCE = 8

_SUSPICIOUS_TOKEN_RE = re.compile(
    r"(?ix) "
    r"(?:powershell|cmd\.exe|whoami|net\suser|wmic|mimikatz|rundll32|"
    r"regsvr32|certutil|bitsadmin|psexec|net\sview|netstat|nmap|"
    r"jndi:|ldap://|rmi://|nslookup|getcurrentdir|wget|curl\s|"
    r"base64|invoke-expression|iex|downloadstring|encodedcommand|"
    r"\.\./|/etc/passwd|/etc/shadow|select\s.+\sfrom|union\s+select)"
)


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _description_excerpt(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    if len(text) <= _DESCRIPTION_EXCERPT_LEN:
        return text
    return text[:_DESCRIPTION_EXCERPT_LEN].rstrip() + "..."


def _select_top_ttp(prediction: LogPrediction) -> Optional[TtpHit]:
    if not prediction.top_ttps:
        return None
    return prediction.top_ttps[0]


@dataclass
class ScoringEngine:
    """Combines a `LogPrediction` with the TI snapshot/graph into a `ScoredLog`."""

    snapshot: ThreatIntelSnapshot
    graph: ThreatGraph
    weights: ScoringWeights = DEFAULT_WEIGHTS
    bands: SeverityBands = DEFAULT_BANDS

    def score(
        self,
        prediction: LogPrediction,
        *,
        asset_factor: float = 1.0,
    ) -> ScoredLog:
        asset_factor = _clamp(
            asset_factor, self.weights.asset_factor_min, self.weights.asset_factor_max
        )

        evidence = self._collect_evidence(prediction)
        breakdown = self._compute_score(prediction, evidence, asset_factor)
        band = self.bands.classify(breakdown.final_score)

        return ScoredLog(
            prediction=prediction,
            score=breakdown.final_score,
            severity_band=band,
            breakdown=breakdown,
            evidence=evidence,
            weights_fingerprint=self.weights.fingerprint(),
            bands_fingerprint=self.bands.fingerprint(),
        )

    def score_batch(
        self,
        predictions: Iterable[LogPrediction],
        *,
        asset_factor: float = 1.0,
    ) -> list[ScoredLog]:
        return [self.score(p, asset_factor=asset_factor) for p in predictions]

    def _collect_evidence(self, prediction: LogPrediction) -> EvidenceChain:
        top_ttp = _select_top_ttp(prediction)
        evidence = EvidenceChain(top_ttp=top_ttp)
        if top_ttp is None:
            return evidence

        evidence.rationale_terms = list(top_ttp.rationale_terms[:5])

        cves_seen: set[str] = set()
        max_cvss_part = 0.0
        max_epss_part = 0.0
        any_kev = False

        for ttp_hit in prediction.top_ttps[:3]:
            ttp_id = ttp_hit.technique_id
            for cve_id in self.graph.cves_for_technique(ttp_id):
                if cve_id in cves_seen or len(evidence.related_cves) >= _MAX_CVES_PER_EVIDENCE:
                    continue
                cves_seen.add(cve_id)
                cve = self.snapshot.lookup_cve(cve_id)
                if cve is None:
                    continue
                cvss_norm = (cve.cvss_score or 0.0) / 10.0
                epss = cve.epss_score or 0.0
                if cvss_norm > max_cvss_part:
                    max_cvss_part = cvss_norm
                if epss > max_epss_part:
                    max_epss_part = epss
                if cve.kev_listed:
                    any_kev = True
                evidence.related_cves.append(
                    CveContext(
                        cve_id=cve.cve_id,
                        via_ttp=ttp_id,
                        cvss_score=cve.cvss_score,
                        kev_listed=bool(cve.kev_listed),
                        kev_known_ransomware=cve.kev_known_ransomware,
                        epss_score=cve.epss_score,
                        epss_percentile=cve.epss_percentile,
                        description_excerpt=_description_excerpt(cve.description),
                    )
                )

            for mitigation_id in self.graph.mitigations_for_technique(ttp_id):
                if len(evidence.mitigations) >= _MAX_MITIGATIONS_PER_EVIDENCE:
                    break
                if any(m.mitigation_id == mitigation_id for m in evidence.mitigations):
                    continue
                mitigation = self.snapshot.mitigations.get(mitigation_id)
                if mitigation is None:
                    continue
                evidence.mitigations.append(
                    MitigationRef(
                        mitigation_id=mitigation_id,
                        name=mitigation.name,
                        via_ttp=ttp_id,
                    )
                )

            for log_source in self.graph.log_sources_for_technique(ttp_id):
                if len(evidence.detection_log_sources) >= _MAX_LOG_SOURCES_PER_EVIDENCE:
                    break
                key = (log_source.name, log_source.channel)
                if any(
                    (ref.name, ref.channel) == key
                    for ref in evidence.detection_log_sources
                ):
                    continue
                evidence.detection_log_sources.append(
                    LogSourceRef(
                        name=log_source.name,
                        channel=log_source.channel,
                        via_ttp=ttp_id,
                    )
                )

        evidence.cvss_risk_value = max_cvss_part
        evidence.epss_risk_value = max_epss_part
        evidence.any_kev_listed = any_kev
        return evidence

    def _compute_score(
        self,
        prediction: LogPrediction,
        evidence: EvidenceChain,
        asset_factor: float,
    ) -> ScoreBreakdown:
        anomaly = _clamp(prediction.anomaly.score)
        top_ttp_score = (
            prediction.top_ttps[0].score if prediction.top_ttps else 0.0
        )
        ttp_norm = _clamp(top_ttp_score * self.weights.ttp_score_scaling)

        cve_risk = _clamp(
            self.weights.cvss_weight_in_risk * evidence.cvss_risk_value
            + self.weights.epss_weight_in_risk * evidence.epss_risk_value
        )

        suspicious_count = len(_SUSPICIOUS_TOKEN_RE.findall(prediction.raw_excerpt))
        suspicious_norm = _clamp(suspicious_count / _SUSPICIOUS_TOKEN_NORMALIZATION)

        anomaly_term = self.weights.anomaly * anomaly
        ttp_term = self.weights.ttp_match * ttp_norm
        cve_term = self.weights.cve_severity * cve_risk
        suspicious_term = self.weights.suspicious_tokens * suspicious_norm

        base = anomaly_term + ttp_term + cve_term + suspicious_term
        kev_boost_applied = self.weights.kev_boost if evidence.any_kev_listed else 0.0
        base = _clamp(base + kev_boost_applied)

        final_normalized = _clamp(base * asset_factor)
        return ScoreBreakdown(
            anomaly_term=anomaly_term,
            ttp_term=ttp_term,
            cve_term=cve_term,
            suspicious_term=suspicious_term,
            kev_boost_applied=kev_boost_applied,
            asset_factor=asset_factor,
            base_score=base,
            final_score=round(final_normalized * 100.0, 2),
        )


def build_default_engine(
    snapshot: ThreatIntelSnapshot | None = None,
) -> ScoringEngine:
    """Convenience constructor for the CLI and the integration tests."""

    if snapshot is None:
        snapshot = load_threat_intel()
    graph = build_threat_graph(snapshot)
    return ScoringEngine(snapshot=snapshot, graph=graph)


def score_predictions_file(
    input_path: Path,
    output_path: Path | None = None,
    *,
    snapshot: ThreatIntelSnapshot | None = None,
    asset_inventory_path: Path | None = None,
    sequential: bool = False,
    sequence_db_path: Path | None = None,
) -> list[ScoredLog]:
    """Score every line of a `predictions.jsonl` and optionally persist it."""

    if not input_path.exists():
        raise FileNotFoundError(input_path)

    engine = build_default_engine(snapshot=snapshot)
    inventory = try_load_inventory(asset_inventory_path)

    with input_path.open(encoding="utf-8") as handle:
        predictions: list[LogPrediction] = []
        for lineno, line in enumerate(handle, start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                predictions.append(LogPrediction.model_validate_json(line_stripped))
            except ValidationError as exc:
                raise ValueError(
                    f"Invalid prediction JSON at {input_path!s} line {lineno}: {exc}"
                ) from exc

    if inventory is None:
        point_scored = engine.score_batch(predictions)
    else:
        point_scored = [
            engine.score(prediction=p, asset_factor=inventory.resolve(p).factor)
            for p in predictions
        ]

    if sequential:
        SETTINGS.ensure_directories()
        db_path = sequence_db_path or SETTINGS.sequence_db_path
        store = SequenceStore(db_path)
        chron = sort_chronological(point_scored)
        merged = apply_sequential_scoring(chron, store)
        scored = sort_by_priority(merged)
    else:
        point_scored.sort(key=lambda s: -s.score)
        scored = point_scored

    output_sha = None
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for entry in scored:
                handle.write(entry.model_dump_json() + "\n")
        import hashlib

        digest = hashlib.sha256()
        with output_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        output_sha = digest.hexdigest()

    bands_count: dict[str, int] = {}
    for entry in scored:
        bands_count[entry.severity_band] = bands_count.get(entry.severity_band, 0) + 1

    audit_record(
        "scoring.run",
        payload={
            "input_path": str(input_path),
            "output_path": str(output_path) if output_path else None,
            "output_sha256": output_sha,
            "n_predictions": len(predictions),
            "bands_count": bands_count,
            "weights_fingerprint": engine.weights.fingerprint(),
            "bands_fingerprint": engine.bands.fingerprint(),
            "weights_file_sha256": file_fingerprint(),
            "asset_inventory_path": str(asset_inventory_path)
            if asset_inventory_path
            else None,
            "asset_inventory_applied": inventory is not None,
            "sequential_same_actor": sequential,
            "sequence_db_path": str(sequence_db_path or SETTINGS.sequence_db_path)
            if sequential
            else None,
            "sequence_policy_fingerprint": DEFAULT_SEQUENCE_POLICY.fingerprint()
            if sequential
            else None,
        },
    )
    LOGGER.info(
        "scoring.ok",
        extra={
            "n_predictions": len(predictions),
            "bands_count": bands_count,
            "weights_fp": engine.weights.fingerprint()[:12],
        },
    )
    return scored
