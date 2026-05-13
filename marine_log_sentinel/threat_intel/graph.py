"""Threat Intelligence knowledge graph (networkx).

Encodes the entire TI snapshot as a typed `MultiDiGraph` so we can answer
structural questions in O(degree) time and *audit-defendably* — every
finding by the scoring engine can be backed by a concrete path in this
graph:

    CVE-2021-44228 --[references]--> T1190 --[has_tactic]--> initial-access
    T1190 --[mitigated_by]--> M1048
    T1190 --[detected_by]--> <strategy> --[uses_analytic]--> <analytic>
                                                     |
                                                     +--[produces_log]--> WinEventLog:Sysmon::EventCode=1

Node IDs are namespaced (`cve:`, `ttp:`, `mit:` ...) so different kinds
never collide. Edge attribute `relation` is the contract for every query.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

import networkx as nx

from marine_log_sentinel.threat_intel.models import MitreLogSource
from marine_log_sentinel.threat_intel.snapshot import ThreatIntelSnapshot

NODE_KIND_CVE = "cve"
NODE_KIND_TTP = "ttp"
NODE_KIND_TACTIC = "tactic"
NODE_KIND_MITIGATION = "mitigation"
NODE_KIND_DATA_SOURCE = "data_source"
NODE_KIND_DATA_COMPONENT = "data_component"
NODE_KIND_DETECTION = "detection_strategy"
NODE_KIND_ANALYTIC = "analytic"
NODE_KIND_LOG_SOURCE = "log_source"

REL_REFERENCES = "references"
REL_HAS_TACTIC = "has_tactic"
REL_SUBTECH_OF = "subtechnique_of"
REL_MITIGATED_BY = "mitigated_by"
REL_DETECTED_BY = "detected_by"
REL_USES_ANALYTIC = "uses_analytic"
REL_INSPECTS_COMPONENT = "inspects_component"
REL_PRODUCES_LOG = "produces_log"


def _cve(cve_id: str) -> str:
    return f"cve:{cve_id.strip().upper()}"


def _ttp(ttp_id: str) -> str:
    return f"ttp:{ttp_id.strip().upper()}"


def _mit(mit_id: str) -> str:
    return f"mit:{mit_id.strip().upper()}"


def _tac(shortname: str) -> str:
    return f"tac:{shortname.strip().lower()}"


def _ds(stix_id: str) -> str:
    return f"ds:{stix_id}"


def _dc(stix_id: str) -> str:
    return f"dc:{stix_id}"


def _det(stix_id: str) -> str:
    return f"det:{stix_id}"


def _an(stix_id: str) -> str:
    return f"an:{stix_id}"


def _ls(name: str, channel: str | None) -> str:
    return f"ls:{name}::{channel or ''}"


def _strip(key: str) -> str:
    return key.split(":", 1)[1] if ":" in key else key


@dataclass
class ThreatGraph:
    """Typed view over a `networkx.MultiDiGraph` built from a TI snapshot."""

    graph: nx.MultiDiGraph

    @property
    def number_of_nodes(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def number_of_edges(self) -> int:
        return self.graph.number_of_edges()

    def stats(self) -> dict[str, int]:
        kinds: Counter[str] = Counter()
        for _, data in self.graph.nodes(data=True):
            kinds[str(data.get("kind", "unknown"))] += 1
        return {
            "nodes": self.number_of_nodes,
            "edges": self.number_of_edges,
            **{f"nodes.{kind}": count for kind, count in kinds.items()},
        }

    def _incoming(self, key: str, relation: str) -> list[str]:
        return [
            _strip(u)
            for u, _, data in self.graph.in_edges(key, data=True)
            if data.get("relation") == relation
        ]

    def _outgoing(self, key: str, relation: str) -> list[str]:
        return [
            _strip(v)
            for _, v, data in self.graph.out_edges(key, data=True)
            if data.get("relation") == relation
        ]

    def cves_for_technique(self, ttp_id: str) -> list[str]:
        return self._incoming(_ttp(ttp_id), REL_REFERENCES)

    def techniques_for_cve(self, cve_id: str) -> list[str]:
        return self._outgoing(_cve(cve_id), REL_REFERENCES)

    def mitigations_for_technique(self, ttp_id: str) -> list[str]:
        return self._outgoing(_ttp(ttp_id), REL_MITIGATED_BY)

    def techniques_sharing_mitigation(self, mitigation_id: str) -> list[str]:
        return self._incoming(_mit(mitigation_id), REL_MITIGATED_BY)

    def techniques_in_tactic(self, tactic_shortname: str) -> list[str]:
        return self._incoming(_tac(tactic_shortname), REL_HAS_TACTIC)

    def parent_of_technique(self, ttp_id: str) -> str | None:
        parents = self._outgoing(_ttp(ttp_id), REL_SUBTECH_OF)
        return parents[0] if parents else None

    def kev_listed_techniques(self) -> list[str]:
        result: set[str] = set()
        for node, data in self.graph.nodes(data=True):
            if data.get("kind") != NODE_KIND_CVE:
                continue
            if not data.get("kev_listed"):
                continue
            for _, target, edge_data in self.graph.out_edges(node, data=True):
                if edge_data.get("relation") == REL_REFERENCES:
                    result.add(_strip(target))
        return sorted(result)

    def log_sources_for_technique(self, ttp_id: str) -> list[MitreLogSource]:
        ttp_key = _ttp(ttp_id)
        if ttp_key not in self.graph:
            return []
        seen: set[tuple[str, str | None]] = set()
        log_sources: list[MitreLogSource] = []
        for strategy in self._outgoing(ttp_key, REL_DETECTED_BY):
            strategy_key = _det(strategy)
            for analytic in self._outgoing(strategy_key, REL_USES_ANALYTIC):
                analytic_key = _an(analytic)
                for log_node in self._outgoing(analytic_key, REL_PRODUCES_LOG):
                    log_key = f"ls:{log_node}"
                    data = self.graph.nodes[log_key]
                    pair = (str(data.get("name") or ""), data.get("channel"))
                    if pair in seen:
                        continue
                    seen.add(pair)
                    log_sources.append(MitreLogSource(name=pair[0], channel=pair[1]))
                for component in self._outgoing(analytic_key, REL_INSPECTS_COMPONENT):
                    component_key = _dc(component)
                    for log_node in self._outgoing(component_key, REL_PRODUCES_LOG):
                        log_key = f"ls:{log_node}"
                        data = self.graph.nodes[log_key]
                        pair = (str(data.get("name") or ""), data.get("channel"))
                        if pair in seen:
                            continue
                        seen.add(pair)
                        log_sources.append(MitreLogSource(name=pair[0], channel=pair[1]))
        return log_sources


def _add_unique_node(graph: nx.MultiDiGraph, key: str, **attrs: object) -> None:
    """Add a node, OR enrich an existing stub created earlier by `add_edge`.

    Without this, a sub-technique whose parent has not yet been iterated
    would auto-create a kind-less stub for the parent, which later breaks
    `stats()` and `kev_listed_techniques()`.
    """

    if key in graph:
        graph.nodes[key].update(attrs)
    else:
        graph.add_node(key, **attrs)


def _iter_log_sources(items: Iterable[MitreLogSource]) -> Iterable[tuple[str, str | None]]:
    for ls in items:
        if ls.name:
            yield ls.name, ls.channel


def build_threat_graph(snapshot: ThreatIntelSnapshot) -> ThreatGraph:
    """Materialize the full TI snapshot as a typed knowledge graph."""

    graph: nx.MultiDiGraph = nx.MultiDiGraph()

    for cve in snapshot.cves.values():
        _add_unique_node(
            graph,
            _cve(cve.cve_id),
            kind=NODE_KIND_CVE,
            name=cve.cve_id,
            cvss_score=cve.cvss_score,
            kev_listed=bool(cve.kev_listed),
            epss_score=cve.epss_score,
        )

    for tactic in snapshot.tactics.values():
        _add_unique_node(
            graph,
            _tac(tactic.shortname),
            kind=NODE_KIND_TACTIC,
            name=tactic.name,
            external_id=tactic.external_id,
        )

    for mitigation in snapshot.mitigations.values():
        _add_unique_node(
            graph,
            _mit(mitigation.external_id),
            kind=NODE_KIND_MITIGATION,
            name=mitigation.name,
        )

    for data_source in snapshot.data_sources.values():
        _add_unique_node(
            graph,
            _ds(data_source.stix_id),
            kind=NODE_KIND_DATA_SOURCE,
            name=data_source.name,
        )

    for component in snapshot.data_components.values():
        _add_unique_node(
            graph,
            _dc(component.stix_id),
            kind=NODE_KIND_DATA_COMPONENT,
            name=component.name,
        )
        for name, channel in _iter_log_sources(component.log_sources):
            log_key = _ls(name, channel)
            _add_unique_node(graph, log_key, kind=NODE_KIND_LOG_SOURCE, name=name, channel=channel)
            graph.add_edge(_dc(component.stix_id), log_key, relation=REL_PRODUCES_LOG)

    for analytic in snapshot.analytics.values():
        _add_unique_node(
            graph,
            _an(analytic.stix_id),
            kind=NODE_KIND_ANALYTIC,
            name=analytic.name,
        )
        for name, channel in _iter_log_sources(analytic.log_sources):
            log_key = _ls(name, channel)
            _add_unique_node(graph, log_key, kind=NODE_KIND_LOG_SOURCE, name=name, channel=channel)
            graph.add_edge(_an(analytic.stix_id), log_key, relation=REL_PRODUCES_LOG)
        for component_id in analytic.data_component_stix_ids:
            if component_id in snapshot.data_components:
                graph.add_edge(
                    _an(analytic.stix_id),
                    _dc(component_id),
                    relation=REL_INSPECTS_COMPONENT,
                )

    for strategy in snapshot.detection_strategies.values():
        _add_unique_node(
            graph,
            _det(strategy.stix_id),
            kind=NODE_KIND_DETECTION,
            name=strategy.name,
        )
        for analytic_id in strategy.analytic_stix_ids:
            if analytic_id in snapshot.analytics:
                graph.add_edge(
                    _det(strategy.stix_id),
                    _an(analytic_id),
                    relation=REL_USES_ANALYTIC,
                )

    for technique in snapshot.techniques.values():
        _add_unique_node(
            graph,
            _ttp(technique.external_id),
            kind=NODE_KIND_TTP,
            name=technique.name,
            is_subtechnique=technique.is_subtechnique,
        )
        for tactic_short in technique.tactics:
            if tactic_short in snapshot.tactics:
                graph.add_edge(
                    _ttp(technique.external_id),
                    _tac(tactic_short),
                    relation=REL_HAS_TACTIC,
                )
        if technique.parent_external_id:
            graph.add_edge(
                _ttp(technique.external_id),
                _ttp(technique.parent_external_id),
                relation=REL_SUBTECH_OF,
            )
        for mitigation_id in technique.mitigation_external_ids:
            if mitigation_id in snapshot.mitigations:
                graph.add_edge(
                    _ttp(technique.external_id),
                    _mit(mitigation_id),
                    relation=REL_MITIGATED_BY,
                )
        for strategy_id in technique.detection_strategy_stix_ids:
            if strategy_id in snapshot.detection_strategies:
                graph.add_edge(
                    _ttp(technique.external_id),
                    _det(strategy_id),
                    relation=REL_DETECTED_BY,
                )
        for cve_id in technique.related_cves:
            if cve_id in snapshot.cves:
                graph.add_edge(
                    _cve(cve_id),
                    _ttp(technique.external_id),
                    relation=REL_REFERENCES,
                )

    return ThreatGraph(graph)
