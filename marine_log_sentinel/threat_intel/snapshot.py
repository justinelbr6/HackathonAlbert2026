"""Snapshot orchestrator: load all local TI sources and cross-link them.

`ThreatIntelSnapshot` is the immutable view of MITRE + CVE used by every
downstream layer (ML retrieval, scoring, reporting). Each snapshot embeds
the SHA-256 of every source artefact that produced it and is referenced
by a `ti.load` entry in the tamper-evident audit log, so any downstream
decision can be traced back to a specific set of inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.ingestion import file_sha256
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel.cache import CacheMissError
from marine_log_sentinel.threat_intel.cve import load_local_cves
from marine_log_sentinel.threat_intel.epss import (
    EpssEntry,
    load_epss,
    load_epss_offline,
)
from marine_log_sentinel.threat_intel.kev import (
    KevEntry,
    load_kev,
    load_kev_offline,
)
from marine_log_sentinel.threat_intel.mitre import load_mitre_entities
from marine_log_sentinel.threat_intel.models import (
    CveRecord,
    MitreAnalytic,
    MitreDataComponent,
    MitreDataSource,
    MitreDetectionStrategy,
    MitreLogSource,
    MitreMitigation,
    MitreTactic,
    MitreTechnique,
)

LOGGER = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MITRE_ZIP = (
    PROJECT_ROOT
    / "SujetsHackathon2026"
    / "Sujet1"
    / "Généralisation"
    / "enterprise-attack.json.zip"
)
DEFAULT_CVE_JSON = (
    PROJECT_ROOT
    / "SujetsHackathon2026"
    / "Sujet1"
    / "MiseEnJambe"
    / "Extrait_cve_data.JSON"
)
DEFAULT_CVE_CSV = (
    PROJECT_ROOT
    / "SujetsHackathon2026"
    / "Sujet1"
    / "MiseEnJambe"
    / "cve_data_with_cvss_and_mitre.csv"
)


@dataclass
class SourceFingerprint:
    path: str
    sha256: str


@dataclass
class ThreatIntelSnapshot:
    techniques: dict[str, MitreTechnique]
    tactics: dict[str, MitreTactic]
    data_components: dict[str, MitreDataComponent]
    data_sources: dict[str, MitreDataSource]
    detection_strategies: dict[str, MitreDetectionStrategy]
    analytics: dict[str, MitreAnalytic]
    mitigations: dict[str, MitreMitigation]
    cves: dict[str, CveRecord]
    mitre_source: SourceFingerprint
    cve_sources: list[SourceFingerprint] = field(default_factory=list)
    loaded_at_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def lookup_technique(self, ttp_id: str) -> MitreTechnique | None:
        return self.techniques.get(ttp_id.strip().upper())

    def lookup_cve(self, cve_id: str) -> CveRecord | None:
        return self.cves.get(cve_id.strip().upper())

    def log_sources_for_technique(self, ttp_id: str) -> list[MitreLogSource]:
        """Return the concrete log sources required to detect a technique.

        Walks the detection chain: technique <- detection-strategy ->
        analytics -> log_source_references / data_components.
        Deduplicates on the (name, channel) pair.
        """

        tech = self.lookup_technique(ttp_id)
        if tech is None:
            return []
        seen: set[tuple[str, str | None]] = set()
        log_sources: list[MitreLogSource] = []
        for strategy_id in tech.detection_strategy_stix_ids:
            strategy = self.detection_strategies.get(strategy_id)
            if strategy is None:
                continue
            for analytic_id in strategy.analytic_stix_ids:
                analytic = self.analytics.get(analytic_id)
                if analytic is None:
                    continue
                for ls in analytic.log_sources:
                    key = (ls.name, ls.channel)
                    if key not in seen:
                        seen.add(key)
                        log_sources.append(ls)
                for dc_id in analytic.data_component_stix_ids:
                    component = self.data_components.get(dc_id)
                    if component is None:
                        continue
                    for ls in component.log_sources:
                        key = (ls.name, ls.channel)
                        if key not in seen:
                            seen.add(key)
                            log_sources.append(ls)
        return log_sources


def _enrich_cves_with_kev(cves: dict[str, CveRecord], kev: dict[str, KevEntry]) -> int:
    matched = 0
    for cve in cves.values():
        entry = kev.get(cve.cve_id)
        if entry is None:
            cve.kev_listed = False
            continue
        cve.kev_listed = True
        cve.kev_date_added = entry.date_added
        cve.kev_known_ransomware = entry.known_ransomware
        matched += 1
    return matched


def _enrich_cves_with_epss(cves: dict[str, CveRecord], epss: dict[str, EpssEntry]) -> int:
    matched = 0
    for cve in cves.values():
        entry = epss.get(cve.cve_id)
        if entry is None:
            continue
        cve.epss_score = entry.score
        cve.epss_percentile = entry.percentile
        matched += 1
    return matched


def _try_load_kev() -> dict[str, KevEntry] | None:
    """Read KEV from local cache only. Never reaches the network here.

    Network fetches happen exclusively through `sync_threat_intel()`.
    """

    try:
        data, _ = load_kev_offline()
    except CacheMissError as exc:
        LOGGER.info("ti.kev.skip", extra={"reason": str(exc)[:120]})
        return None
    return data


def _try_load_epss() -> dict[str, EpssEntry] | None:
    try:
        data, _ = load_epss_offline()
    except CacheMissError as exc:
        LOGGER.info("ti.epss.skip", extra={"reason": str(exc)[:120]})
        return None
    return data


def load_threat_intel(
    mitre_zip: Path = DEFAULT_MITRE_ZIP,
    cve_json: Path | None = DEFAULT_CVE_JSON,
    cve_csv: Path | None = DEFAULT_CVE_CSV,
    *,
    include_kev: bool = True,
    include_epss: bool = True,
) -> ThreatIntelSnapshot:
    """Load MITRE + local CVE (+ KEV/EPSS if cached) and cross-link them.

    KEV and EPSS enrichments are *opportunistic*: if their caches are
    absent (typical first run before `ti sync`), the snapshot still loads
    cleanly and the corresponding fields stay `None`. This keeps the
    pipeline operational on a freshly cloned air-gapped box and lets the
    operator add intel later by syncing on a connected host.
    """

    mitre = load_mitre_entities(Path(mitre_zip))
    cves = load_local_cves(cve_json, cve_csv)

    for cve in cves.values():
        for ttp in cve.mitre_attack_techniques:
            tech = mitre["techniques"].get(ttp.strip().upper())
            if tech is None:
                continue
            if cve.cve_id not in tech.related_cves:
                tech.related_cves.append(cve.cve_id)

    kev_matched = 0
    if include_kev:
        kev_data = _try_load_kev()
        if kev_data is not None:
            kev_matched = _enrich_cves_with_kev(cves, kev_data)

    epss_matched = 0
    if include_epss:
        epss_data = _try_load_epss()
        if epss_data is not None:
            epss_matched = _enrich_cves_with_epss(cves, epss_data)

    mitre_fingerprint = SourceFingerprint(path=str(mitre_zip), sha256=file_sha256(Path(mitre_zip)))
    cve_fingerprints: list[SourceFingerprint] = []
    for candidate in (cve_json, cve_csv):
        if candidate is None:
            continue
        path = Path(candidate)
        if path.exists():
            cve_fingerprints.append(SourceFingerprint(path=str(path), sha256=file_sha256(path)))

    snapshot = ThreatIntelSnapshot(
        techniques=mitre["techniques"],
        tactics=mitre["tactics"],
        data_components=mitre["data_components"],
        data_sources=mitre["data_sources"],
        detection_strategies=mitre["detection_strategies"],
        analytics=mitre["analytics"],
        mitigations=mitre["mitigations"],
        cves=cves,
        mitre_source=mitre_fingerprint,
        cve_sources=cve_fingerprints,
    )

    audit_record(
        "ti.load",
        payload={
            "mitre": {"path": mitre_fingerprint.path, "sha256": mitre_fingerprint.sha256},
            "cve_sources": [{"path": f.path, "sha256": f.sha256} for f in cve_fingerprints],
            "counts": {
                "techniques": len(snapshot.techniques),
                "tactics": len(snapshot.tactics),
                "data_components": len(snapshot.data_components),
                "data_sources": len(snapshot.data_sources),
                "detection_strategies": len(snapshot.detection_strategies),
                "analytics": len(snapshot.analytics),
                "mitigations": len(snapshot.mitigations),
                "cves": len(snapshot.cves),
            },
            "enrichments": {
                "kev_matched": kev_matched,
                "epss_matched": epss_matched,
                "air_gap": SETTINGS.air_gap_mode,
            },
        },
    )

    LOGGER.info(
        "ti.loaded",
        extra={
            "techniques": len(snapshot.techniques),
            "cves": len(snapshot.cves),
            "kev_matched": kev_matched,
            "epss_matched": epss_matched,
            "mitre_sha256": mitre_fingerprint.sha256[:12],
        },
    )
    return snapshot


def sync_threat_intel(
    *,
    refresh_kev: bool = True,
    refresh_epss: bool = True,
    refresh_taxii: bool = False,
) -> dict[str, object]:
    """Refresh online TI feeds (forbidden in air-gap mode)."""

    if SETTINGS.air_gap_mode:
        raise RuntimeError(
            "ti sync refused: air-gap mode is ON. Run sync on a connected host, "
            "then copy the contents of data/cache/ onto this box."
        )

    summary: dict[str, object] = {}
    if refresh_kev:
        kev_data, kev_entry = load_kev(refresh=True)
        summary["kev"] = {
            "cves": len(kev_data),
            "sha256": kev_entry.sha256,
            "size_bytes": kev_entry.size_bytes,
            "path": str(kev_entry.path),
        }
    if refresh_epss:
        epss_data, epss_entry = load_epss(refresh=True)
        summary["epss"] = {
            "cves": len(epss_data),
            "sha256": epss_entry.sha256,
            "size_bytes": epss_entry.size_bytes,
            "path": str(epss_entry.path),
        }
    if refresh_taxii:
        from marine_log_sentinel.threat_intel.taxii import sync_mitre_from_taxii

        taxii_entry = sync_mitre_from_taxii(refresh=True)
        summary["taxii"] = {
            "sha256": taxii_entry.sha256,
            "size_bytes": taxii_entry.size_bytes,
            "path": str(taxii_entry.path),
        }
    return summary
