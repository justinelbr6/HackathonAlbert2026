"""Same-actor sequential scoring + SQLite persistence."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml.models import AnomalyScore, LogPrediction, TtpHit  # noqa: E402
from marine_log_sentinel.scoring.models import EvidenceChain, ScoreBreakdown, ScoredLog  # noqa: E402
from marine_log_sentinel.sequence.engine import apply_sequential_scoring, sort_chronological  # noqa: E402
from marine_log_sentinel.sequence.store import SequenceStore  # noqa: E402


def _ttp_hit(tid: str) -> TtpHit:
    return TtpHit(
        technique_id=tid,
        technique_name="Technique",
        score=0.1,
        tactics=["execution"],
    )


def _scored_at(
    *,
    ts: datetime,
    static: float,
    band: str,
    ttp: str,
    user: str,
    host: str,
) -> ScoredLog:
    pred = LogPrediction(
        timestamp_utc=ts,
        source_format="windows_sysmon",
        event_category="process_execution",
        source_file="u.jsonl",
        raw_excerpt="cmd.exe",
        user=user,
        host=host,
        anomaly=AnomalyScore(score=0.2, method="test"),
        top_ttps=[_ttp_hit(ttp)],
    )
    ev = EvidenceChain(top_ttp=_ttp_hit(ttp))
    bd = ScoreBreakdown(
        anomaly_term=0.1,
        ttp_term=0.1,
        cve_term=0.0,
        suspicious_term=0.0,
        kev_boost_applied=0.0,
        asset_factor=1.0,
        base_score=static / 100.0,
        final_score=static,
    )
    return ScoredLog(
        prediction=pred,
        score=static,
        severity_band=band,
        breakdown=bd,
        evidence=ev,
        weights_fingerprint="w" * 64,
        bands_fingerprint="b" * 64,
    )


class SequentialMergeTest(unittest.TestCase):
    def test_second_event_inherits_decayed_peak_from_first(self):
        t0 = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=30)
        s0 = _scored_at(ts=t0, static=42.0, band="MEDIUM", ttp="T1059", user="alice", host="srv-a")
        s1 = _scored_at(ts=t1, static=24.0, band="LOW", ttp="T1059", user="alice", host="srv-a")

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            path = Path(tmp.name)
        try:
            store = SequenceStore(path)
            out = apply_sequential_scoring(sort_chronological([s0, s1]), store)
            self.assertIsNotNone(out[1].sequence)
            self.assertGreater(out[1].score, s1.score)
            st = store.stats()
            self.assertEqual(st["actors"], 1)
            self.assertEqual(st["events"], 2)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
