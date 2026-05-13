"""Threat Intelligence layer.

Étape 2.A — offline loading of MITRE ATT&CK + local CVE + cross-linking.
Étape 2.B (next) — TAXII, CISA KEV, EPSS, knowledge graph.
"""

from marine_log_sentinel.threat_intel.cache import (
    AirGapError,
    CacheEntry,
    CacheMissError,
)
from marine_log_sentinel.threat_intel.cve import load_local_cves
from marine_log_sentinel.threat_intel.epss import (
    EpssEntry,
    load_epss,
    load_epss_offline,
    parse_epss_file,
)
from marine_log_sentinel.threat_intel.graph import ThreatGraph, build_threat_graph
from marine_log_sentinel.threat_intel.kev import (
    KevEntry,
    load_kev,
    load_kev_offline,
    parse_kev_file,
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
from marine_log_sentinel.threat_intel.snapshot import (
    DEFAULT_CVE_CSV,
    DEFAULT_CVE_JSON,
    DEFAULT_MITRE_ZIP,
    SourceFingerprint,
    ThreatIntelSnapshot,
    load_threat_intel,
    sync_threat_intel,
)

__all__ = [
    "AirGapError",
    "CacheEntry",
    "CacheMissError",
    "CveRecord",
    "DEFAULT_CVE_CSV",
    "DEFAULT_CVE_JSON",
    "DEFAULT_MITRE_ZIP",
    "EpssEntry",
    "KevEntry",
    "MitreAnalytic",
    "MitreDataComponent",
    "MitreDataSource",
    "MitreDetectionStrategy",
    "MitreLogSource",
    "MitreMitigation",
    "MitreTactic",
    "MitreTechnique",
    "SourceFingerprint",
    "ThreatGraph",
    "ThreatIntelSnapshot",
    "build_threat_graph",
    "load_epss",
    "load_epss_offline",
    "load_kev",
    "load_kev_offline",
    "load_local_cves",
    "load_mitre_entities",
    "load_threat_intel",
    "parse_epss_file",
    "parse_kev_file",
    "sync_threat_intel",
]
