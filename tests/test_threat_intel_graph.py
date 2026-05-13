"""Tests for the TI knowledge graph (Étape 2.B)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.threat_intel import (  # noqa: E402
    build_threat_graph,
    load_threat_intel,
)

_GRAPH = None
_SNAPSHOT = None


def _graph():
    global _GRAPH, _SNAPSHOT
    if _GRAPH is None:
        _SNAPSHOT = load_threat_intel()
        _GRAPH = build_threat_graph(_SNAPSHOT)
    return _GRAPH


class ThreatGraphTopologyTest(unittest.TestCase):
    def test_graph_has_typed_nodes_and_edges(self):
        graph = _graph()
        stats = graph.stats()
        self.assertGreater(stats["nodes"], 1000)
        self.assertGreater(stats["edges"], 1000)
        self.assertGreaterEqual(stats.get("nodes.ttp", 0), 600)
        self.assertGreaterEqual(stats.get("nodes.cve", 0), 5)
        self.assertGreaterEqual(stats.get("nodes.mitigation", 0), 30)
        self.assertGreaterEqual(stats.get("nodes.log_source", 0), 100)

    def test_graph_has_no_unknown_nodes(self):
        graph = _graph()
        stats = graph.stats()
        self.assertEqual(
            stats.get("nodes.unknown", 0),
            0,
            "Every node must carry a typed `kind` attribute (no stubs auto-created by add_edge).",
        )


class ThreatGraphQueriesTest(unittest.TestCase):
    def test_techniques_for_cve_returns_referenced_ttps(self):
        graph = _graph()
        techniques = graph.techniques_for_cve("CVE-2021-44228")
        self.assertIn("T1190", techniques)

    def test_cves_for_technique_reverse_direction(self):
        graph = _graph()
        cves = graph.cves_for_technique("T1190")
        self.assertIn("CVE-2021-44228", cves)

    def test_mitigations_for_technique(self):
        graph = _graph()
        mitigations = graph.mitigations_for_technique("T1190")
        self.assertGreater(len(mitigations), 0)
        for mit_id in mitigations:
            self.assertTrue(mit_id.startswith("M"))

    def test_techniques_sharing_mitigation(self):
        graph = _graph()
        sample_mitigation = graph.mitigations_for_technique("T1190")[0]
        peers = graph.techniques_sharing_mitigation(sample_mitigation)
        self.assertIn("T1190", peers)
        self.assertGreater(len(peers), 1, "A mitigation is typically shared by many techniques")

    def test_techniques_in_tactic(self):
        graph = _graph()
        techniques = graph.techniques_in_tactic("execution")
        self.assertIn("T1059", techniques)

    def test_subtechnique_parent_resolves_via_graph(self):
        graph = _graph()
        self.assertEqual(graph.parent_of_technique("T1059.001"), "T1059")
        self.assertIsNone(graph.parent_of_technique("T1059"))

    def test_log_sources_for_technique_match_snapshot(self):
        graph = _graph()
        sources = graph.log_sources_for_technique("T1190")
        self.assertGreater(len(sources), 5)
        from_snapshot = _SNAPSHOT.log_sources_for_technique("T1190")
        names_graph = {(s.name, s.channel) for s in sources}
        names_snap = {(s.name, s.channel) for s in from_snapshot}
        self.assertEqual(names_graph, names_snap)


if __name__ == "__main__":
    unittest.main()
