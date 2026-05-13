"""Tests for HTML officer report (Étape 6)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml.models import AnomalyScore, LogPrediction, TtpHit  # noqa: E402
from marine_log_sentinel.reporting.html_report import (  # noqa: E402
    build_officer_html_document,
    write_officer_html_report,
)
from marine_log_sentinel.scoring.models import EvidenceChain, ScoreBreakdown, ScoredLog  # noqa: E402
from marine_log_sentinel.translation.brief import build_operational_brief_fr  # noqa: E402


def _scored_with_raw(raw: str) -> ScoredLog:
    ttp = TtpHit(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        score=0.15,
        tactics=["initial-access"],
    )
    pred = LogPrediction(
        timestamp_utc=datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc),
        source_format="apache_access",
        event_category="web_request",
        source_file="Apache.JSON",
        raw_excerpt=raw,
        anomaly=AnomalyScore(score=0.4, method="test"),
        top_ttps=[ttp],
    )
    ev = EvidenceChain(top_ttp=ttp)
    bd = ScoreBreakdown(
        anomaly_term=0.1,
        ttp_term=0.05,
        cve_term=0.1,
        suspicious_term=0.02,
        kev_boost_applied=0.0,
        asset_factor=1.0,
        base_score=0.27,
        final_score=27.0,
    )
    return ScoredLog(
        prediction=pred,
        score=72.0,
        severity_band="HIGH",
        breakdown=bd,
        evidence=ev,
        weights_fingerprint="w" * 64,
        bands_fingerprint="b" * 64,
    )


class HtmlEscapeTest(unittest.TestCase):
    def test_script_payload_is_escaped(self):
        malicious = '<script>alert("x")</script> GET /'
        scored = _scored_with_raw(malicious)
        brief = build_operational_brief_fr(scored)
        html = build_officer_html_document(
            scored_sorted=[scored],
            detail_rows=[(scored, brief)],
        )
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


class WriteReportTest(unittest.TestCase):
    def test_writes_file_and_returns_sha256(self):
        scored = _scored_with_raw("GET / HTTP/1.1")
        brief = build_operational_brief_fr(scored)
        line = scored.model_dump_json()

        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "scored.jsonl"
            outp = Path(tmp) / "out.html"
            inp.write_text(line + "\n", encoding="utf-8")
            digest, summary = write_officer_html_report(inp, outp, top_n=5)
            self.assertEqual(len(digest), 64)
            self.assertTrue(outp.exists())
            self.assertGreater(len(outp.read_text(encoding="utf-8")), 500)
            self.assertEqual(summary["total_events"], 1)
            self.assertEqual(summary["detail_cards"], 1)


if __name__ == "__main__":
    unittest.main()
