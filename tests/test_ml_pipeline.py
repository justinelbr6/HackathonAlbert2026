"""Integration tests for the ML pipeline (Étape 3.C).

Validates that the orchestrator (`analyze_logs` / `analyze_path`):
  - reads the real `.normalized.jsonl` produced by the ingestion layer,
  - produces a `LogPrediction` per log with both signals (anomaly + TTPs),
  - correctly cross-uses the Étape 2 TI snapshot to surface T1190 for
    the Log4Shell Apache log.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ingestion.schema import NormalizedLog  # noqa: E402
from marine_log_sentinel.ml import analyze_logs, analyze_path  # noqa: E402

NORMALIZED_DIR = PROJECT_ROOT / "data" / "normalized"


def _load_challenge_logs() -> list[NormalizedLog]:
    logs: list[NormalizedLog] = []
    for jsonl_path in sorted(NORMALIZED_DIR.glob("*.jsonl")):
        with jsonl_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    logs.append(NormalizedLog.model_validate_json(line))
    return logs


class PipelineEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not NORMALIZED_DIR.exists() or not list(NORMALIZED_DIR.glob("*.jsonl")):
            raise unittest.SkipTest(
                "Run `python -m marine_log_sentinel ingest --input "
                "SujetsHackathon2026/Sujet1/MiseEnJambe` first."
            )
        cls.logs = _load_challenge_logs()
        cls.predictions, cls.tagger, cls.detector = analyze_logs(cls.logs)

    def test_one_prediction_per_log_in_order(self):
        self.assertEqual(len(self.predictions), len(self.logs))
        for log, pred in zip(self.logs, self.predictions, strict=True):
            self.assertEqual(pred.source_file, log.source_file)
            self.assertEqual(pred.source_format, log.source_format.value)
            self.assertEqual(pred.event_category, log.event_category.value)

    def test_every_prediction_has_anomaly_score(self):
        for pred in self.predictions:
            self.assertGreaterEqual(pred.anomaly.score, 0.0)
            self.assertLessEqual(pred.anomaly.score, 1.0)
            self.assertIn(pred.anomaly.method, {"isolation_forest", "heuristic"})

    def test_log4shell_apache_is_tagged_with_t1190(self):
        apache = [p for p in self.predictions if p.source_format == "apache_access"]
        self.assertTrue(apache, "Apache.JSON should have produced at least one log.")
        top_ttps = [hit.technique_id for hit in apache[0].top_ttps]
        self.assertIn("T1190", top_ttps[:3])

    def test_pipeline_returns_at_least_one_critical_anomaly(self):
        max_score = max(p.anomaly.score for p in self.predictions)
        self.assertGreaterEqual(max_score, 0.6)


class PipelineRoundtripTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not NORMALIZED_DIR.exists() or not list(NORMALIZED_DIR.glob("*.jsonl")):
            raise unittest.SkipTest("Normalized dataset missing.")

    def test_analyze_path_writes_a_jsonl_we_can_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "predictions.jsonl"
            result = analyze_path(NORMALIZED_DIR, output, top_k_ttps=3)
            self.assertTrue(output.exists())
            self.assertIsNotNone(result.output_sha256)
            self.assertEqual(len(result.output_sha256 or ""), 64)
            with output.open(encoding="utf-8") as handle:
                lines = [line for line in handle if line.strip()]
            self.assertEqual(len(lines), len(result.predictions))
            decoded = json.loads(lines[0])
            self.assertIn("anomaly", decoded)
            self.assertIn("top_ttps", decoded)


if __name__ == "__main__":
    unittest.main()
