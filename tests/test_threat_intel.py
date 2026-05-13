"""Tests for Étape 2.A — Threat Intelligence local snapshot."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.threat_intel import load_threat_intel  # noqa: E402

_SNAPSHOT = None


def _snapshot():
    """Cache the snapshot at module level: parsing the bundle costs ~1s."""

    global _SNAPSHOT
    if _SNAPSHOT is None:
        _SNAPSHOT = load_threat_intel()
    return _SNAPSHOT


class MitreSnapshotTest(unittest.TestCase):
    def test_loads_a_large_number_of_active_techniques(self):
        snap = _snapshot()
        self.assertGreaterEqual(len(snap.techniques), 600)
        self.assertGreaterEqual(len(snap.detection_strategies), 500)
        self.assertGreaterEqual(len(snap.analytics), 1000)
        self.assertGreaterEqual(len(snap.mitigations), 30)
        self.assertGreaterEqual(len(snap.tactics), 14)

    def test_t1059_top_level_metadata(self):
        snap = _snapshot()
        tech = snap.lookup_technique("T1059")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.name, "Command and Scripting Interpreter")
        self.assertIn("execution", tech.tactics)
        self.assertFalse(tech.is_subtechnique)
        self.assertIsNone(tech.parent_external_id)

    def test_subtechnique_is_linked_to_parent_and_back(self):
        snap = _snapshot()
        sub = snap.lookup_technique("T1059.001")
        parent = snap.lookup_technique("T1059")
        self.assertIsNotNone(sub)
        self.assertIsNotNone(parent)
        self.assertTrue(sub.is_subtechnique)
        self.assertEqual(sub.parent_external_id, "T1059")
        self.assertIn("T1059.001", parent.sub_technique_external_ids)

    def test_lookup_is_case_insensitive(self):
        snap = _snapshot()
        self.assertIsNotNone(snap.lookup_technique("t1059"))
        self.assertIsNotNone(snap.lookup_technique(" T1190 "))

    def test_mitigations_are_linked_to_techniques(self):
        snap = _snapshot()
        techniques_with_mitigations = [
            t for t in snap.techniques.values() if t.mitigation_external_ids
        ]
        self.assertGreater(len(techniques_with_mitigations), 100)
        sample = techniques_with_mitigations[0]
        mitigation_id = sample.mitigation_external_ids[0]
        mitigation = snap.mitigations.get(mitigation_id)
        self.assertIsNotNone(mitigation)
        self.assertIn(sample.external_id, mitigation.mitigates_technique_external_ids)

    def test_log_sources_are_recovered_via_detection_strategies(self):
        snap = _snapshot()
        found_with_sources = 0
        for technique in list(snap.techniques.values())[:200]:
            if snap.log_sources_for_technique(technique.external_id):
                found_with_sources += 1
                if found_with_sources >= 5:
                    break
        self.assertGreaterEqual(found_with_sources, 5)


class CveSnapshotTest(unittest.TestCase):
    def test_local_cves_loaded(self):
        snap = _snapshot()
        self.assertGreaterEqual(len(snap.cves), 5)
        self.assertIsNotNone(snap.lookup_cve("CVE-2021-44228"))
        self.assertIsNotNone(snap.lookup_cve("CVE-2020-1472"))

    def test_log4shell_metadata(self):
        snap = _snapshot()
        log4shell = snap.lookup_cve("CVE-2021-44228")
        self.assertIsNotNone(log4shell)
        self.assertEqual(log4shell.cvss_score, 10.0)
        self.assertIn("T1190", log4shell.mitre_attack_techniques)
        self.assertTrue(any("Log4j" in patch for patch in log4shell.patches))
        self.assertEqual(log4shell.published_date.isoformat(), "2021-12-10")

    def test_cross_link_technique_to_cve(self):
        snap = _snapshot()
        t1190 = snap.lookup_technique("T1190")
        self.assertIsNotNone(t1190)
        self.assertIn("CVE-2021-44228", t1190.related_cves)


class SnapshotFingerprintTest(unittest.TestCase):
    def test_each_source_is_fingerprinted(self):
        snap = _snapshot()
        self.assertEqual(len(snap.mitre_source.sha256), 64)
        self.assertTrue(snap.cve_sources)
        for fingerprint in snap.cve_sources:
            self.assertEqual(len(fingerprint.sha256), 64)


if __name__ == "__main__":
    unittest.main()
