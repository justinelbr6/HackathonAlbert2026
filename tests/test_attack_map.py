"""Attack map phased narratives from scored logs."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import unittest

from marine_log_sentinel.analysis.attack_map import (  # noqa: E402
    attack_map_flat_frame,
    build_attack_map_from_scored,
)
from marine_log_sentinel.ml.models import AnomalyScore, LogPrediction, TtpHit  # noqa: E402
from marine_log_sentinel.scoring.models import (  # noqa: E402
    EvidenceChain,
    ScoreBreakdown,
    ScoredLog,
    SequenceContext,
)
from marine_log_sentinel.threat_intel.models import MitreTactic, MitreTechnique  # noqa: E402
from marine_log_sentinel.threat_intel.snapshot import (  # noqa: E402
    SourceFingerprint,
    ThreatIntelSnapshot,
)


def _minimal_snapshot() -> ThreatIntelSnapshot:
    fp = SourceFingerprint(path="test", sha256="0" * 64)
    tac_ia = MitreTactic(
        stix_id="x",
        external_id="TA0001",
        name="Initial Access",
        shortname="initial-access",
    )
    tac_ex = MitreTactic(
        stix_id="y",
        external_id="TA0002",
        name="Execution",
        shortname="execution",
    )
    return ThreatIntelSnapshot(
        techniques={
            "T1190": MitreTechnique(
                stix_id="z1",
                external_id="T1190",
                name="Exploit Public-Facing Application",
                tactics=["initial-access"],
            ),
            "T1059": MitreTechnique(
                stix_id="z2",
                external_id="T1059",
                name="Command and Scripting Interpreter",
                tactics=["execution"],
            ),
        },
        tactics={"initial-access": tac_ia, "execution": tac_ex},
        data_components={},
        data_sources={},
        detection_strategies={},
        analytics={},
        mitigations={},
        cves={},
        mitre_source=fp,
    )


def _scored(ts_h: int, ttp_id: str, ttp_name: str, tac: list[str], score: float, actor: str | None):
    seq = (
        SequenceContext(
            actor_key=actor,
            chain_index=1,
            point_in_time_score=min(score, 100.0),
            point_in_time_band="HIGH",
            effective_score=score,
            effective_band="HIGH",
        )
        if actor
        else None
    )
    hit = TtpHit(
        technique_id=ttp_id,
        technique_name=ttp_name,
        score=0.5,
        tactics=tac,
    )
    lp = LogPrediction(
        timestamp_utc=datetime(2026, 5, 12, ts_h, 0, tzinfo=timezone.utc),
        source_format="test",
        event_category="evt",
        source_file="f.jsonl",
        raw_excerpt="x",
        anomaly=AnomalyScore(score=0.2, method="t"),
        top_ttps=[hit],
    )
    eb = EvidenceChain(top_ttp=hit)
    br = ScoreBreakdown(
        anomaly_term=1.0,
        ttp_term=1.0,
        cve_term=0.0,
        suspicious_term=0.0,
        kev_boost_applied=0.0,
        asset_factor=1.0,
        base_score=40.0,
        final_score=score,
    )
    return ScoredLog(
        prediction=lp,
        score=score,
        severity_band="HIGH",
        breakdown=br,
        evidence=eb,
        weights_fingerprint="w",
        bands_fingerprint="b",
        sequence=seq,
    )


class AttackMapTest(unittest.TestCase):
    def test_merges_consecutive_same_tactic(self):
        snap = _minimal_snapshot()
        rows = [
            _scored(10, "T1190", "Exploit", ["initial-access"], 50.0, None),
            _scored(11, "T1190", "Exploit", ["initial-access"], 55.0, None),
        ]
        build = build_attack_map_from_scored(rows, snap, min_log_score=0.0)
        self.assertEqual(len(build.campaigns), 1)
        self.assertEqual(len(build.campaigns[0].phases), 1)
        self.assertEqual(len(build.campaigns[0].phases[0].means_observed), 2)

    def test_separate_paths_per_actor_and_phase_order(self):
        snap = _minimal_snapshot()
        rows = [
            _scored(10, "T1190", "Exploit", ["initial-access"], 50.0, "alice"),
            _scored(10, "T1059", "Script", ["execution"], 50.0, "bob"),
            _scored(11, "T1059", "Script", ["execution"], 40.0, "alice"),
        ]
        build = build_attack_map_from_scored(rows, snap)
        camps = {c.actor_internal_key: c for c in build.campaigns}
        self.assertEqual(set(camps.keys()), {"alice", "bob"})
        self.assertEqual(camps["bob"].phases[0].tactic_shortname, "execution")
        self.assertEqual(camps["alice"].phases[0].tactic_shortname, "initial-access")
        self.assertEqual(camps["alice"].phases[1].tactic_shortname, "execution")

    def test_flat_frame_nonempty(self):
        snap = _minimal_snapshot()
        build = build_attack_map_from_scored([_scored(1, "T1190", "E", ["initial-access"], 30.0, None)], snap)
        df = attack_map_flat_frame(build)
        self.assertGreaterEqual(len(df), 1)
        self.assertIn("technique_id", df.columns)


if __name__ == "__main__":
    unittest.main()
