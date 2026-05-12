"""Threat-to-Log Value Engine for Sujet 1 Log as Code.

This module turns the challenge mapping table into a small explainable policy
engine. It is intentionally rules-based for the first MVP: the goal is to make
our decision logic explicit before adding automation or ML later.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAPPING_FILE = (
    PROJECT_ROOT
    / "SujetsHackathon2026"
    / "Sujet1"
    / "MiseEnJambe"
    / "mapping_ttps_cve_logs.csv"
)
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "ProjetsEtudiantsHackathon2026" / "generated_policies"
DEFAULT_ASSET_INVENTORY_FILE = PROJECT_ROOT / "ProjetsEtudiantsHackathon2026" / "asset_inventory_sample.csv"
DEFAULT_MITRE_ATTACK_ZIP_FILE = (
    PROJECT_ROOT
    / "SujetsHackathon2026"
    / "Sujet1"
    / "Généralisation"
    / "enterprise-attack.json.zip"
)

LEVEL_VALUE = {
    "low": 1.0,
    "medium": 1.4,
    "high": 1.9,
    "critical": 2.2,
}

COUT_BRUIT = {
    "faible": 1.0,
    "moyen": 1.25,
    "fort": 1.6,
}

LOG_SOURCE_PROFILES = {
    "Windows Sysmon": {"cost": "moyen", "noise": "moyen", "coverage": "forte"},
    "Apache Access Logs": {"cost": "faible", "noise": "moyen", "coverage": "forte"},
    "Windows Task Scheduler": {"cost": "faible", "noise": "faible", "coverage": "moyenne"},
    "DNS Logs": {"cost": "moyen", "noise": "fort", "coverage": "moyenne"},
}

COVERAGE_VALUE = {
    "faible": 1.0,
    "moyenne": 1.35,
    "forte": 1.8,
}

STRATEGY_MULTIPLIERS = {
    "minimal": 0.9,
    "balanced": 1.0,
    "high_assurance": 1.15,
}


class PolicyEngineError(ValueError):
    """Raised when a policy cannot be generated from provided inputs."""


def _clean(value: Any) -> str:
    return str(value or "").strip().strip('"').replace("\\n", "\n")


def _split_fields(value: str) -> list[str]:
    return [field.strip() for field in _clean(value).split(",") if field.strip()]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        cleaned = _clean(value)
        return float(cleaned) if cleaned else default
    except ValueError:
        return default


def _parse_challenge_row(raw_row: dict[str, str]) -> dict[str, Any]:
    """Normalize a row from the challenge CSV.

    The provided file is slightly irregular: some rows are fully quoted and the
    first CSV column contains several logical columns separated by commas. This
    function handles that specific shape while keeping the public output clean.
    """

    ttp_id = _clean(raw_row.get("ttp_id"))
    ttp_name = _clean(raw_row.get("ttp_name"))
    ttp_tactic = _clean(raw_row.get("ttp_tactic"))
    cve_id = _clean(raw_row.get("cve_id"))
    cve_description = _clean(raw_row.get("cve_description"))
    cve_score = _clean(raw_row.get("cve_score"))

    # In mapping_ttps_cve_logs.csv, each data line is wrapped as one physical
    # CSV cell that itself contains a CSV record. Re-parse that embedded record.
    if "," in ttp_id and not ttp_name:
        embedded_rows = list(csv.reader([ttp_id]))
        parts = embedded_rows[0] if embedded_rows else []
        # Some Splunk queries contain an unescaped comma, which creates an
        # extra physical column. Keep the first ten fields stable, merge the
        # query fragments, and keep the last field as Sigma.
        if len(parts) > 12:
            parts = parts[:10] + [",".join(parts[10:-1])] + [parts[-1]]
        while len(parts) < 12:
            parts.append("")
        (
            ttp_id,
            ttp_name,
            ttp_tactic,
            cve_id,
            cve_description,
            cve_score,
            log_type,
            log_source,
            log_fields,
            example_log,
            example_query_splunk,
            example_rule_sigma,
        ) = parts[:12]
    else:
        log_type = _clean(raw_row.get("log_type"))
        log_source = _clean(raw_row.get("log_source"))
        log_fields = raw_row.get("log_fields", "")
        example_log = _clean(raw_row.get("example_log"))
        example_query_splunk = _clean(raw_row.get("example_query_splunk"))
        example_rule_sigma = _clean(raw_row.get("example_rule_sigma"))

    return {
        "ttp_id": _clean(ttp_id),
        "ttp_name": _clean(ttp_name),
        "ttp_tactic": _clean(ttp_tactic),
        "cve_id": _clean(cve_id),
        "cve_description": _clean(cve_description),
        "cve_score": _clean(cve_score),
        "log_type": _clean(log_type),
        "log_source": _clean(log_source),
        "log_fields": _split_fields(log_fields),
        "example_log": _clean(example_log),
        "example_query_splunk": _clean(example_query_splunk),
        "example_rule_sigma": _clean(example_rule_sigma),
    }


def load_mapping_rows(mapping_file: Path = DEFAULT_MAPPING_FILE) -> list[dict[str, Any]]:
    """Load and normalize TTP/CVE/log mapping rows from the challenge CSV."""

    with Path(mapping_file).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = [_parse_challenge_row(row) for row in reader]

    return [row for row in rows if row["ttp_id"] and row["log_source"]]


def load_asset_inventory(asset_inventory_file: Path = DEFAULT_ASSET_INVENTORY_FILE) -> dict[str, dict[str, str]]:
    """Load a small asset inventory / mini-CMDB used to contextualize policies."""

    path = Path(asset_inventory_file)
    if not path.exists():
        return {}

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assets = {}
        for row in reader:
            asset_id = _clean(row.get("asset_id"))
            if not asset_id:
                continue
            assets[asset_id] = {key: _clean(value) for key, value in row.items()}
        return assets


def _mitre_external_id(stix_object: dict[str, Any]) -> str:
    return next(
        (
            _clean(reference.get("external_id"))
            for reference in stix_object.get("external_references", [])
            if reference.get("source_name") == "mitre-attack"
        ),
        "",
    )


def _mitre_tactics(stix_object: dict[str, Any]) -> list[str]:
    tactics = []
    for phase in stix_object.get("kill_chain_phases", []):
        phase_name = _clean(phase.get("phase_name"))
        if phase_name and phase_name not in tactics:
            tactics.append(phase_name)
    return tactics


def load_mitre_attack_techniques(mitre_zip_file: Path = DEFAULT_MITRE_ATTACK_ZIP_FILE) -> list[dict[str, Any]]:
    """Load active MITRE ATT&CK Enterprise techniques from the Généralisation STIX export.

    This is the first data-driven/NLP layer: instead of staying limited to the
    five MiseEnJambe mappings, it exposes hundreds of real ATT&CK techniques
    that can be searched and ranked from a free-text threat scenario.
    """

    with zipfile.ZipFile(Path(mitre_zip_file)) as archive:
        with archive.open("enterprise-attack.json") as handle:
            bundle = json.load(handle)

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ttp_id = _mitre_external_id(obj)
        if not ttp_id:
            continue
        techniques.append(
            {
                "ttp_id": ttp_id,
                "name": _clean(obj.get("name")),
                "description": _clean(obj.get("description")),
                "tactics": _mitre_tactics(obj),
                "data_sources": list(obj.get("x_mitre_data_sources", []) or []),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            }
        )

    techniques.sort(key=lambda item: item["ttp_id"])
    return techniques


STOPWORDS = {
    "and", "the", "with", "from", "that", "this", "pour", "avec", "dans", "sur",
    "les", "des", "une", "un", "est", "server", "serveur", "suspicious", "suspect",
}


def _tokens(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-zA-Z0-9]+", text.lower()) if len(token) > 2 and token not in STOPWORDS]


def _tf(tokens: list[str]) -> Counter[str]:
    return Counter(tokens)


def _cosine_similarity(left: Counter[str], right: Counter[str]) -> float:
    shared = set(left) & set(right)
    numerator = sum(left[token] * right[token] for token in shared)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return numerator / (left_norm * right_norm)


def recommend_similar_mitre_techniques(
    scenario: str,
    *,
    mitre_zip_file: Path = DEFAULT_MITRE_ATTACK_ZIP_FILE,
    top_n: int = 5,
) -> list[dict[str, Any]]:
    """Recommend MITRE techniques from a free-text scenario using lightweight NLP similarity.

    The method is intentionally dependency-free for hackathon portability: token
    overlap + cosine similarity + small explainability metadata. It is a real
    ML/NLP stepping stone because the same interface can later be replaced by
    TF-IDF, embeddings, or a learned ranker without changing the demo flow.
    """

    query_tokens = _tokens(scenario)
    query_vector = _tf(query_tokens)
    query_token_set = set(query_tokens)
    recommendations = []

    for technique in load_mitre_attack_techniques(mitre_zip_file):
        searchable_text = " ".join(
            [
                technique["ttp_id"],
                technique["name"],
                " ".join(technique["tactics"]),
                " ".join(technique["data_sources"]),
                technique["description"],
            ]
        )
        technique_tokens = _tokens(searchable_text)
        similarity = _cosine_similarity(query_vector, _tf(technique_tokens))

        # Small domain boost: top-level T1059 should represent the whole command
        # execution family in a management briefing, even if a sub-technique also matches.
        if "command" in query_token_set and "execution" in query_token_set and technique["ttp_id"] == "T1059":
            similarity += 0.25
        if "windows" in query_token_set and "windows" in set(technique_tokens):
            similarity += 0.03

        matched_terms = sorted(query_token_set & set(technique_tokens))
        display_matched_terms = ["Windows" if term == "windows" else term for term in matched_terms]
        if similarity <= 0:
            continue
        recommendations.append(
            {
                "ttp_id": technique["ttp_id"],
                "name": technique["name"],
                "tactics": technique["tactics"],
                "data_sources": technique["data_sources"],
                "similarity_score": round(similarity, 4),
                "matched_terms": display_matched_terms,
                "why": (
                    f"{technique['name']} ressort car le scénario partage les termes "
                    f"{', '.join(display_matched_terms[:6]) or 'techniques'} avec MITRE ATT&CK."
                ),
            }
        )

    recommendations.sort(
        key=lambda item: (item["similarity_score"], -item["ttp_id"].count(".")),
        reverse=True,
    )
    return recommendations[:top_n]


def _resolve_asset_context(
    *,
    asset_id: str | None,
    asset_inventory_file: Path,
    asset_type: str,
    asset_criticality: str,
) -> dict[str, str]:
    """Resolve asset metadata from the mini-CMDB, with manual fallback values."""

    assets = load_asset_inventory(asset_inventory_file)
    if asset_id and asset_id in assets:
        asset = assets[asset_id]
        return {
            "asset_id": asset_id,
            "asset_type": asset.get("asset_type", asset_type) or asset_type,
            "asset_criticality": asset.get("criticality", asset_criticality) or asset_criticality,
            "exposure": asset.get("exposure", "unknown") or "unknown",
            "business_role": asset.get("business_role", "Non renseigné") or "Non renseigné",
            "current_log_sources": asset.get("current_log_sources", "") or "",
            "retention_days": asset.get("retention_days", "") or "",
            "asset_notes": asset.get("notes", "") or "",
        }

    return {
        "asset_id": asset_id or "manual_context",
        "asset_type": asset_type,
        "asset_criticality": asset_criticality,
        "exposure": "unknown",
        "business_role": "Contexte manuel sans fiche d'actif",
        "current_log_sources": "",
        "retention_days": "",
        "asset_notes": "",
    }


def _asset_factor(asset_type: str, asset_criticality: str) -> float:
    base = LEVEL_VALUE.get(asset_criticality, LEVEL_VALUE["medium"])
    asset_bonus = {
        "windows_server": 1.12,
        "web_server": 1.15,
        "active_directory": 1.25,
        "linux_server": 1.08,
        "network": 1.05,
        "workstation": 0.95,
    }.get(asset_type, 1.0)
    return base * asset_bonus


def _threat_factor(candidate: dict[str, Any]) -> float:
    score = _safe_float(candidate.get("cve_score"), 0.0)
    if score >= 9:
        return 2.0
    if score >= 7:
        return 1.6
    if score > 0:
        return 1.25
    tactic = candidate.get("ttp_tactic", "")
    return {
        "execution": 1.65,
        "initial-access": 1.85,
        "defense-evasion": 1.75,
        "persistence": 1.45,
        "exfiltration": 1.55,
    }.get(tactic, 1.2)


def _priority_from_score(score: float) -> str:
    if score >= 8.0:
        return "indispensable"
    if score >= 5.0:
        return "recommandé"
    return "optionnel"


def score_candidate(
    candidate: dict[str, Any],
    *,
    asset_type: str = "generic_asset",
    asset_criticality: str = "medium",
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Return an explainable score and priority for one log candidate."""

    profile = LOG_SOURCE_PROFILES.get(
        candidate.get("log_source", ""),
        {"cost": "moyen", "noise": "moyen", "coverage": "moyenne"},
    )
    threat_value = _threat_factor(candidate)
    asset_value = _asset_factor(asset_type, asset_criticality)
    coverage_value = COVERAGE_VALUE[profile["coverage"]]
    strategy_value = STRATEGY_MULTIPLIERS.get(strategy, 1.0)
    cost_noise_penalty = COUT_BRUIT[profile["cost"]] * COUT_BRUIT[profile["noise"]]

    raw_score = (threat_value * asset_value * coverage_value * strategy_value / cost_noise_penalty) * 3
    score = round(min(raw_score, 10.0), 2)
    priority = _priority_from_score(score)

    ttp_id = candidate.get("ttp_id", "menace inconnue")
    log_source = candidate.get("log_source", "source inconnue")
    fields = candidate.get("log_fields", [])
    fields_text = ", ".join(fields) if fields else "les champs disponibles"

    return {
        **candidate,
        "log_value_score": score,
        "priority": priority,
        "estimated_cost": profile["cost"],
        "estimated_noise": profile["noise"],
        "detection_coverage": profile["coverage"],
        "reason": (
            f"{log_source} est classé {priority} pour {ttp_id} car cette source permet "
            f"d'observer {fields_text} sur un actif de type {asset_type} "
            f"avec une criticité {asset_criticality}."
        ),
        "blind_spot_if_missing": (
            f"Angle mort potentiel : sans {log_source}, l'équipe risque de moins bien détecter "
            f"les comportements associés à {ttp_id}, notamment les signaux portés par {fields_text}."
        ),
    }


def build_policy(
    mapping_file: Path = DEFAULT_MAPPING_FILE,
    *,
    threat_id: str,
    asset_id: str | None = None,
    asset_inventory_file: Path = DEFAULT_ASSET_INVENTORY_FILE,
    asset_type: str = "generic_asset",
    asset_criticality: str = "medium",
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Build a ranked, explainable logging policy for one TTP or CVE id."""

    asset_context = _resolve_asset_context(
        asset_id=asset_id,
        asset_inventory_file=asset_inventory_file,
        asset_type=asset_type,
        asset_criticality=asset_criticality,
    )
    resolved_asset_type = asset_context["asset_type"]
    resolved_criticality = asset_context["asset_criticality"]

    rows = load_mapping_rows(mapping_file)
    threat_id = threat_id.strip()
    candidates = [
        row
        for row in rows
        if row["ttp_id"].lower() == threat_id.lower()
        or row.get("cve_id", "").lower() == threat_id.lower()
    ]
    if not candidates:
        raise PolicyEngineError(f"Aucun mapping trouvé pour la menace `{threat_id}`.")

    scored = [
        score_candidate(
            candidate,
            asset_type=resolved_asset_type,
            asset_criticality=resolved_criticality,
            strategy=strategy,
        )
        for candidate in candidates
    ]
    scored.sort(key=lambda item: item["log_value_score"], reverse=True)

    first = scored[0]
    recommendations = []
    for item in scored:
        recommendations.append(
            {
                "log_source": item["log_source"],
                "log_type": item["log_type"],
                "priority": item["priority"],
                "log_value_score": item["log_value_score"],
                "fields": item["log_fields"],
                "estimated_cost": item["estimated_cost"],
                "estimated_noise": item["estimated_noise"],
                "detection_coverage": item["detection_coverage"],
                "reason": item["reason"],
                "blind_spot_if_missing": item["blind_spot_if_missing"],
                "covers": {
                    "ttp_id": item["ttp_id"],
                    "ttp_name": item["ttp_name"],
                    "tactic": item["ttp_tactic"],
                    "cve_id": item["cve_id"],
                    "cve_description": item["cve_description"],
                    "cve_score": item["cve_score"],
                },
                "detection_examples": {
                    "sample_log": item["example_log"],
                    "splunk_query": item["example_query_splunk"],
                    "sigma_rule": item["example_rule_sigma"],
                },
            }
        )

    return {
        "policy": {
            "name": f"Politique priorisée pour {threat_id}",
            "target": {
                "threat_id": threat_id,
                "ttp_id": first["ttp_id"],
                "ttp_name": first["ttp_name"],
                "asset_id": asset_context["asset_id"],
                "asset_type": resolved_asset_type,
                "asset_criticality": resolved_criticality,
                "exposure": asset_context["exposure"],
                "business_role": asset_context["business_role"],
                "current_log_sources": asset_context["current_log_sources"],
                "retention_days": asset_context["retention_days"],
                "asset_notes": asset_context["asset_notes"],
                "strategy": strategy,
            },
            "decision_model": {
                "name": "Threat-to-Log Value Engine",
                "principle": "Prioriser les logs selon menace, criticité de l'actif, couverture, coût et bruit.",
                "priority_levels": ["indispensable", "recommandé", "optionnel"],
            },
            "recommendations": recommendations,
        }
    }


def _to_yaml_like(value: Any, indent: int = 0) -> str:
    """Small dependency-free YAML-like serializer for demo policies."""

    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(_to_yaml_like(child, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {json.dumps(child, ensure_ascii=False)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(_to_yaml_like(item, indent + 2))
            else:
                lines.append(f"{prefix}- {json.dumps(item, ensure_ascii=False)}")
        return "\n".join(lines)
    return f"{prefix}{json.dumps(value, ensure_ascii=False)}"


def export_policy(policy: dict[str, Any], output_dir: Path = DEFAULT_OUTPUT_DIR, *, fmt: str = "json") -> Path:
    """Export a policy as JSON or dependency-free YAML-like text."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    threat_id = policy["policy"]["target"]["threat_id"].replace("/", "_")
    if fmt == "json":
        output_path = output_dir / f"policy_{threat_id}.json"
        output_path.write_text(json.dumps(policy, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_path
    if fmt in {"yaml", "yml"}:
        output_path = output_dir / f"policy_{threat_id}.yaml"
        output_path.write_text(_to_yaml_like(policy) + "\n", encoding="utf-8")
        return output_path
    raise PolicyEngineError(f"Format non supporté : {fmt}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère une politique de logs priorisée pour une TTP ou CVE.")
    parser.add_argument("--threat", required=True, help="Identifiant TTP ou CVE, ex: T1059 ou CVE-2021-44228")
    parser.add_argument("--asset-id", default=None, help="Identifiant d'actif à résoudre depuis la mini-CMDB")
    parser.add_argument("--asset-inventory", type=Path, default=DEFAULT_ASSET_INVENTORY_FILE, help="Fichier CSV de mini-CMDB")
    parser.add_argument("--asset-type", default="generic_asset", help="Type d'actif, ex: windows_server, web_server")
    parser.add_argument("--criticality", default="medium", choices=sorted(LEVEL_VALUE), help="Criticité de l'actif")
    parser.add_argument("--strategy", default="balanced", choices=sorted(STRATEGY_MULTIPLIERS), help="Stratégie de collecte")
    parser.add_argument("--format", default="json", choices=["json", "yaml"], help="Format de sortie")
    parser.add_argument("--mapping-file", type=Path, default=DEFAULT_MAPPING_FILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    policy = build_policy(
        args.mapping_file,
        threat_id=args.threat,
        asset_id=args.asset_id,
        asset_inventory_file=args.asset_inventory,
        asset_type=args.asset_type,
        asset_criticality=args.criticality,
        strategy=args.strategy,
    )
    output_path = export_policy(policy, args.output_dir, fmt=args.format)
    print(output_path)


if __name__ == "__main__":
    main()
