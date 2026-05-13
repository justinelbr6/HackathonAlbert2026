"""CVE local loaders.

For Étape 2.A we only load the small CVE samples shipped with the
challenge (`Extrait_cve_data.JSON` and `cve_data_with_cvss_and_mitre.csv`).
The full `cvelistV5` ingestion comes in Étape 2.B together with KEV/EPSS.
"""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path
from typing import Any

from marine_log_sentinel.threat_intel.models import CveRecord


def _to_date(value: Any) -> date | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _to_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_string_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
    return [chunk.strip() for chunk in text.split(",") if chunk.strip()]


def _cve_from_json(entry: dict[str, Any]) -> CveRecord:
    return CveRecord(
        cve_id=str(entry.get("cve_id", "")).strip().upper(),
        description=entry.get("description"),
        cvss_score=_to_float(entry.get("cvss_score")),
        cvss_vector=entry.get("cvss_vector"),
        published_date=_to_date(entry.get("published_date")),
        last_modified_date=_to_date(entry.get("last_modified_date")),
        exploitability=entry.get("exploitability"),
        mitre_attack_techniques=_parse_string_list(entry.get("mitre_attack_techniques")),
        affected_software=_parse_string_list(entry.get("affected_software")),
        patches=_parse_string_list(entry.get("patches")),
        references=_parse_string_list(entry.get("references")),
    )


def _cve_from_csv(row: dict[str, str]) -> CveRecord:
    return CveRecord(
        cve_id=str(row.get("cve_id", "")).strip().upper(),
        description=row.get("description"),
        cvss_score=_to_float(row.get("cvss_score")),
        cvss_vector=row.get("cvss_vector"),
        published_date=_to_date(row.get("published_date")),
        mitre_attack_techniques=_parse_string_list(row.get("mitre_attack_techniques")),
        references=_parse_string_list(row.get("mitre_attack_links")),
    )


def load_local_cves(
    json_path: Path | None = None,
    csv_path: Path | None = None,
) -> dict[str, CveRecord]:
    """Load CVE records from the challenge's two local files.

    The richer JSON record wins over the CSV in case both files describe
    the same CVE id, because the JSON carries `affected_software`, patches
    and references that the CSV does not.
    """

    cves: dict[str, CveRecord] = {}

    if json_path is not None:
        path = Path(json_path)
        if path.exists():
            bundle = json.loads(path.read_text(encoding="utf-8"))
            for entry in bundle.get("vulnerabilities", []):
                cve = _cve_from_json(entry)
                if cve.cve_id:
                    cves[cve.cve_id] = cve

    if csv_path is not None:
        path = Path(csv_path)
        if path.exists():
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    cve = _cve_from_csv(row)
                    if cve.cve_id and cve.cve_id not in cves:
                        cves[cve.cve_id] = cve

    return cves
