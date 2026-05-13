"""Étape 7 — edge cases and failure clarity."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml.pipeline import analyze_path  # noqa: E402
from marine_log_sentinel.reporting.html_report import write_officer_html_report  # noqa: E402
from marine_log_sentinel.scoring.engine import score_predictions_file  # noqa: E402


class EmptyBatchPipelineTest(unittest.TestCase):
    def test_analyze_path_handles_only_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "empty.normalized.jsonl"
            inp.write_text("\n\n  \n", encoding="utf-8")
            out = Path(tmp) / "predictions.jsonl"
            result = analyze_path(inp, out)
            self.assertEqual(result.predictions, [])
            self.assertEqual(result.tagger_vocab_size, 0)
            self.assertEqual(out.read_text(encoding="utf-8"), "")
            self.assertIsNotNone(result.output_sha256)


class ScoringRobustnessTest(unittest.TestCase):
    def test_empty_predictions_file_scores_empty_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "pred.jsonl"
            inp.write_text("", encoding="utf-8")
            scored = score_predictions_file(inp, output_path=None)
            self.assertEqual(scored, [])

    def test_malformed_jsonl_raises_value_error_with_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "bad.jsonl"
            inp.write_text('{"timestamp_utc": "not-a-valid-prediction"}\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                score_predictions_file(inp, output_path=None)
            msg = str(ctx.exception)
            self.assertIn("line 1", msg)


class ReportingRobustnessTest(unittest.TestCase):
    def test_html_report_survives_empty_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "empty.jsonl"
            outp = Path(tmp) / "r.html"
            inp.write_text("", encoding="utf-8")
            digest, summary = write_officer_html_report(inp, outp, top_n=10)
            self.assertEqual(len(digest), 64)
            html = outp.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", html)
            self.assertEqual(summary["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
