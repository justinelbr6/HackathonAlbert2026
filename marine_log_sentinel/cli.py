"""Top-level CLI for Marine Log Sentinel.

Exposes ingestion, ML analysis, TI management, scoring, French briefs,
HTML reports, and self-diagnostics (`doctor`).
"""

from __future__ import annotations

import argparse
import importlib
import platform
import sys
from pathlib import Path
from typing import Iterable

from marine_log_sentinel import __version__
from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.observability.audit import record, verify_chain
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.threat_intel.snapshot import DEFAULT_MITRE_ZIP

LOGGER = get_logger(__name__)

REQUIRED_LIBRARIES: tuple[str, ...] = (
    "attackcti",
    "stix2",
    "taxii2client",
    "pandas",
    "pydantic",
    "sklearn",
    "numpy",
    "openpyxl",
)


def _check_libraries(libs: Iterable[str]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for module_name in libs:
        try:
            module = importlib.import_module(module_name)
            version = getattr(module, "__version__", "unknown")
            rows.append((module_name, str(version)))
        except Exception as exc:  # noqa: BLE001
            rows.append((module_name, f"MISSING ({exc.__class__.__name__})"))
    return rows


def cmd_doctor(_args: argparse.Namespace) -> int:
    SETTINGS.ensure_directories()
    LOGGER.info("doctor.start", extra={"version": __version__})

    print(f"Marine Log Sentinel v{__version__}")
    print(f"Python:       {platform.python_version()} ({sys.executable})")
    print(f"Platform:     {platform.platform()}")
    print(f"Air-gap mode: {'ON' if SETTINGS.air_gap_mode else 'OFF'}")
    print(f"Project root: {SETTINGS.project_root}")
    print(f"Audit log:    {SETTINGS.audit_log_path}")
    print()

    rows = _check_libraries(REQUIRED_LIBRARIES)
    width = max(len(name) for name, _ in rows)
    missing: list[str] = []
    print("Library check:")
    for name, version in rows:
        ok = "MISSING" not in version
        marker = "OK " if ok else "NOK"
        if not ok:
            missing.append(name)
        print(f"  [{marker}] {name.ljust(width)}  {version}")
    print()

    valid, count, broken = verify_chain()
    chain_status = "OK" if valid else "BROKEN"
    suffix = f" - {broken}" if broken else ""
    print(f"Audit chain:  {chain_status} ({count} entries){suffix}")
    print()
    print(f"Sequence DB (fil d'acteur) : {SETTINGS.sequence_db_path}")

    print()
    mitre_ok = DEFAULT_MITRE_ZIP.exists()
    mk = "OK " if mitre_ok else "NOK"
    print("Air-gap readiness (static checks):")
    print(f"  [{mk}] MITRE Enterprise bundle present: {DEFAULT_MITRE_ZIP}")
    print(f"  [{'OK ' if SETTINGS.air_gap_mode else '   '}] MLS_AIR_GAP enforcement active now")
    if SETTINGS.air_gap_mode:
        print("       → ti sync / HTTP TI refresh must refuse (copy data/cache from connected host).")
    else:
        print("       → Pour production isolée : export MLS_AIR_GAP=1")

    record(
        "doctor.run",
        payload={
            "version": __version__,
            "libraries": {name: version for name, version in rows},
        },
        metadata={
            "air_gap_mode": SETTINGS.air_gap_mode,
            "mitre_bundle_present": mitre_ok,
        },
    )

    return 0 if not missing and valid and mitre_ok else 1


SUPPORTED_FORMATS: tuple[str, ...] = (
    "apache",
    "suricata",
    "sysmon",
    "windows_events",
    "linux_syslog",
    "network_traffic",
)


def cmd_ingest(args: argparse.Namespace) -> int:
    from marine_log_sentinel.ingestion import (
        normalize_directory,
        normalize_file,
    )

    SETTINGS.ensure_directories()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else SETTINGS.data_dir / "normalized"
    output_dir.mkdir(parents=True, exist_ok=True)

    if input_path.is_dir():
        results = list(normalize_directory(input_path, glob=args.glob))
    elif input_path.is_file():
        results = [normalize_file(input_path, format_hint=args.format)]
    else:
        print(f"Path not found: {input_path}", file=sys.stderr)
        return 1

    if not results:
        print(f"No recognizable log files found under {input_path}.", file=sys.stderr)
        return 1

    total_records = 0
    total_errors = 0
    print(f"{'Format':<18} {'File':<50} {'Records':>8}  {'Errors':>6}  SHA-256")
    for result in results:
        out_name = Path(result.source_file).name + ".normalized.jsonl"
        out_path = output_dir / out_name
        with out_path.open("w", encoding="utf-8") as handle:
            for record_obj in result.records:
                handle.write(record_obj.model_dump_json() + "\n")
        total_records += len(result.records)
        total_errors += len(result.errors)
        print(
            f"{result.detected_format:<18} "
            f"{Path(result.source_file).name:<50} "
            f"{len(result.records):>8}  "
            f"{len(result.errors):>6}  "
            f"{result.sha256[:16]}..."
        )

    print()
    print(f"Total: {total_records} records, {total_errors} errors.")
    print(f"Output: {output_dir}")
    return 0 if total_errors == 0 else 2


def cmd_score(args: argparse.Namespace) -> int:
    from marine_log_sentinel.scoring import score_predictions_file

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    output_path: Path | None = None
    if args.output:
        output_path = Path(args.output)
    else:
        SETTINGS.ensure_directories()
        output_path = SETTINGS.reports_dir.parent / "predictions" / "scored.jsonl"

    asset_inv: Path | None = Path(args.asset_inventory) if args.asset_inventory else None
    seq_db: Path | None = Path(args.sequence_db) if args.sequence_db else None
    try:
        scored = score_predictions_file(
            input_path,
            output_path,
            asset_inventory_path=asset_inv,
            sequential=args.sequential,
            sequence_db_path=seq_db,
        )
    except FileNotFoundError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1

    bands: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for entry in scored:
        bands[entry.severity_band] = bands.get(entry.severity_band, 0) + 1

    print(f"Scored predictions : {len(scored)}")
    print(f"Output             : {output_path}")
    if args.sequential:
        dbp = seq_db or SETTINGS.sequence_db_path
        print(f"Sequential merge   : ON  (SQLite: {dbp})")
    print(
        "Bands              : "
        + ", ".join(f"{band}={count}" for band, count in bands.items() if count)
    )
    print()

    top_n = min(args.top_n, len(scored))
    if top_n > 0:
        print(f"Top {top_n} highest-priority logs:")
        print(
            f"  {'#':>2}  {'score':>5}  {'band':>8}  {'fmt':>15}  "
            f"{'top TTP':>10}  {'CVE':>14}  raw"
        )
        print("  " + "-" * 140)
        for i, entry in enumerate(scored[:top_n], 1):
            ev = entry.evidence
            top_ttp = ev.top_ttp.technique_id if ev.top_ttp else "-"
            top_cve = ev.related_cves[0].cve_id if ev.related_cves else "-"
            raw = entry.prediction.raw_excerpt.replace("\n", " ")[:55]
            print(
                f"  {i:>2}  {entry.score:5.1f}  {entry.severity_band:>8}  "
                f"{entry.prediction.source_format:>15}  {top_ttp:>10}  "
                f"{top_cve:>14}  {raw}"
            )
    return 0


def cmd_brief(args: argparse.Namespace) -> int:
    from marine_log_sentinel.translation.brief import briefs_from_scored_file

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    inventory_path = Path(args.inventory) if args.inventory else None

    output_path: Path | None = Path(args.output) if args.output else None
    if output_path is not None:
        SETTINGS.ensure_directories()

    limit = None if args.top_n < 0 else args.top_n

    try:
        briefs = briefs_from_scored_file(
            input_path,
            inventory_path=inventory_path,
            output_path=output_path,
            top_n=limit,
        )
    except FileNotFoundError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Invalid inventory: {exc}", file=sys.stderr)
        return 2

    if args.format == "jsonl":
        for brief in briefs:
            print(brief.model_dump_json())
        if output_path:
            print(f"# wrote {len(briefs)} briefs → {output_path}", file=sys.stderr)
        return 0

    if output_path:
        print(f"Briefs written    : {len(briefs)} → {output_path}")
    else:
        print(f"Briefs generated : {len(briefs)} (stdout)")
    print()

    width = 76
    sep = "=" * width

    for i, brief in enumerate(briefs, 1):
        print(sep)
        print(f" [{i}] {brief.titre}")
        print(f"     {brief.niveau_operationnel_fr}")
        if brief.actif_identifie:
            af = f" (facteur actif ×{brief.facteur_actif:.2f})" if brief.facteur_actif else ""
            print(f"     Actif : {brief.actif_identifie}{af}")
        print()
        print("  Synthèse commandement")
        print(f"  {brief.resume_pour_commandement}")
        print()
        print("  Impacts opérationnels")
        for line in brief.impacts_operationnels:
            print(f"    • {line}")
        print()
        print("  Actions prioritaires")
        for line in brief.actions_prioritaires[:6]:
            print(f"    → {line}")
        print()
        print("  Journaux / traces")
        for line in brief.journaux_et_traces_a_collecter[:6]:
            print(f"    • {line}")
        a = brief.ancres_techniques
        print()
        print(
            "  Ancrage technique : "
            f"TTP={', '.join(a.technique_ids) or '-'} | "
            f"CVE={', '.join(a.cve_ids) or '-'} | "
            f"score={a.score_numerique:.1f} ({a.bande_securite})"
            + (" | KEV" if a.kev_signale else "")
        )
        print()
    print(sep)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from marine_log_sentinel.reporting.html_report import write_officer_html_report

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    SETTINGS.ensure_directories()
    output_path = Path(args.output) if args.output else SETTINGS.reports_dir / "rapport_officier.html"
    inventory_path = Path(args.inventory) if args.inventory else None

    try:
        digest, summary = write_officer_html_report(
            input_path,
            output_path,
            inventory_path=inventory_path,
            top_n=args.top_n,
        )
    except FileNotFoundError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2

    print(f"Rapport HTML     : {output_path}")
    print(f"SHA-256          : {digest[:24]}...")
    print(f"Événements total : {summary['total_events']}")
    print(f"Fiches détaillées: {summary['detail_cards']}")
    bands = summary.get("bands_count", {})
    if bands:
        print("Répartition       : " + ", ".join(f"{k}={v}" for k, v in sorted(bands.items())))
    print()
    print("Ouvrir le fichier dans un navigateur (hors ligne possible après génération).")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Launch the Streamlit UX (optional dependency)."""

    import shutil
    import subprocess

    if shutil.which("streamlit") is None:
        print(
            "Dependance manquante : installez Streamlit, p.ex.  pip install 'streamlit>=1.31'",
            file=sys.stderr,
        )
        return 1

    dash = Path(__file__).resolve().parent / "dashboard" / "app.py"
    if not dash.exists():
        print(f"Application introuvable: {dash}", file=sys.stderr)
        return 2

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dash),
        "--server.headless",
        "false",
        "--browser.gatherUsageStats",
        "false",
        "--server.port",
        str(args.port),
    ]
    LOGGER.info("dashboard.streamlit.start", extra={"port": args.port, "app": str(dash)})
    SETTINGS.ensure_directories()
    return subprocess.call(cmd, cwd=str(SETTINGS.project_root))


def cmd_analyze(args: argparse.Namespace) -> int:
    from marine_log_sentinel.ml import analyze_path

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    output_path: Path | None = None
    if args.output:
        output_path = Path(args.output)
    elif input_path.is_dir():
        SETTINGS.ensure_directories()
        output_path = SETTINGS.reports_dir.parent / "predictions" / "predictions.jsonl"

    try:
        result = analyze_path(input_path, output_path, top_k_ttps=args.top_k)
    except FileNotFoundError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1

    print(f"Predictions      : {len(result.predictions)}")
    print(f"Tagger vocabulary: {result.tagger_vocab_size}")
    print(f"Output           : {result.output_path or '<none>'}")
    if result.output_sha256:
        print(f"Output sha256    : {result.output_sha256[:16]}...")

    ranked = sorted(result.predictions, key=lambda p: -p.anomaly.score)
    top_n = min(args.top_n, len(ranked))
    if top_n > 0:
        print()
        print(f"Top {top_n} most anomalous logs:")
        print(f"  {'#':>2}  {'score':>5}  {'format':>15}  {'category':>20}  {'top TTP':>10}  raw")
        print("  " + "-" * 124)
        for i, pred in enumerate(ranked[:top_n], 1):
            top_ttp = pred.top_ttps[0].technique_id if pred.top_ttps else "-"
            raw = pred.raw_excerpt.replace("\n", " ")[:55]
            print(
                f"  {i:>2}  {pred.anomaly.score:5.3f}  {pred.source_format:>15}  "
                f"{pred.event_category:>20}  {top_ttp:>10}  {raw}"
            )
    return 0


def cmd_ti_show(args: argparse.Namespace) -> int:
    from marine_log_sentinel.threat_intel import load_threat_intel

    snapshot = load_threat_intel()

    if args.ttp:
        tech = snapshot.lookup_technique(args.ttp)
        if tech is None:
            print(f"Unknown technique: {args.ttp}", file=sys.stderr)
            return 1
        print(f"{tech.external_id} - {tech.name}")
        print(f"  Tactics             : {', '.join(tech.tactics) or '-'}")
        print(f"  Platforms           : {', '.join(tech.platforms) or '-'}")
        if tech.parent_external_id:
            print(f"  Parent              : {tech.parent_external_id}")
        if tech.sub_technique_external_ids:
            preview = ", ".join(tech.sub_technique_external_ids[:6])
            more = "" if len(tech.sub_technique_external_ids) <= 6 else f" (+{len(tech.sub_technique_external_ids) - 6})"
            print(f"  Sub-techniques      : {preview}{more}")
        if tech.mitigation_external_ids:
            print(f"  Mitigations ({len(tech.mitigation_external_ids):d}) : {', '.join(tech.mitigation_external_ids[:6])}")
        print(f"  Detection strategies: {len(tech.detection_strategy_stix_ids)}")
        print(f"  Linked CVEs         : {', '.join(tech.related_cves) or '-'}")
        log_sources = snapshot.log_sources_for_technique(tech.external_id)
        if log_sources:
            print(f"  Log sources to collect ({len(log_sources)}):")
            for ls in log_sources[:15]:
                suffix = f" :: {ls.channel}" if ls.channel else ""
                print(f"    - {ls.name}{suffix}")
            if len(log_sources) > 15:
                print(f"    ... (+{len(log_sources) - 15} more)")
        return 0

    if args.cve:
        cve = snapshot.lookup_cve(args.cve)
        if cve is None:
            print(f"Unknown CVE: {args.cve}", file=sys.stderr)
            return 1
        kev_flag = " [KEV]" if cve.kev_listed else ""
        epss_flag = ""
        if cve.epss_score is not None:
            epss_flag = f" [EPSS {cve.epss_score:.3f} p{int(round((cve.epss_percentile or 0) * 100))}]"
        print(f"{cve.cve_id} - CVSS {cve.cvss_score}{kev_flag}{epss_flag}")
        if cve.description:
            print(f"  Description     : {cve.description[:160]}{'...' if len(cve.description) > 160 else ''}")
        if cve.exploitability:
            print(f"  Exploitability  : {cve.exploitability}")
        if cve.published_date:
            print(f"  Published       : {cve.published_date.isoformat()}")
        if cve.kev_listed:
            ransomware = (
                "yes"
                if cve.kev_known_ransomware
                else ("unknown" if cve.kev_known_ransomware is False else "?")
            )
            added = cve.kev_date_added.isoformat() if cve.kev_date_added else "?"
            print(f"  CISA KEV        : listed since {added}, ransomware: {ransomware}")
        print(f"  MITRE techniques: {', '.join(cve.mitre_attack_techniques) or '-'}")
        if cve.affected_software:
            print(f"  Affected        : {', '.join(cve.affected_software[:3])}")
        if cve.patches:
            print(f"  Patches         : {', '.join(cve.patches[:3])}")
        return 0

    print("Provide --ttp <id> or --cve <id>", file=sys.stderr)
    return 1


def cmd_ti_sync(args: argparse.Namespace) -> int:
    from marine_log_sentinel.threat_intel import sync_threat_intel

    try:
        summary = sync_threat_intel(
            refresh_kev=not args.no_kev,
            refresh_epss=not args.no_epss,
            refresh_taxii=args.taxii,
        )
    except RuntimeError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2

    for feed, data in summary.items():
        if isinstance(data, dict):
            size_kb = int(data.get("size_bytes", 0)) // 1024
            cves = data.get("cves")
            line = f"  [OK ] {feed:6s} size={size_kb:>5d} KiB sha256={str(data.get('sha256',''))[:12]}"
            if cves is not None:
                line += f" cves={cves}"
            print(line)
    print("Done.")
    return 0


def cmd_ti_graph(args: argparse.Namespace) -> int:
    from marine_log_sentinel.threat_intel import build_threat_graph, load_threat_intel

    snapshot = load_threat_intel()
    graph = build_threat_graph(snapshot)

    if args.stats:
        for label, value in graph.stats().items():
            print(f"  {label:30s} {value}")
        return 0

    if args.ttp:
        tech = snapshot.lookup_technique(args.ttp)
        if tech is None:
            print(f"Unknown technique: {args.ttp}", file=sys.stderr)
            return 1
        print(f"{tech.external_id} - {tech.name}")
        print(f"  CVEs        : {', '.join(graph.cves_for_technique(tech.external_id)) or '-'}")
        print(f"  Mitigations : {', '.join(graph.mitigations_for_technique(tech.external_id)) or '-'}")
        parent = graph.parent_of_technique(tech.external_id)
        if parent:
            print(f"  Parent      : {parent}")
        log_sources = graph.log_sources_for_technique(tech.external_id)
        print(f"  Log sources : {len(log_sources)}")
        for ls in log_sources[:10]:
            suffix = f" :: {ls.channel}" if ls.channel else ""
            print(f"    - {ls.name}{suffix}")
        return 0

    if args.cve:
        cve_id = args.cve.strip().upper()
        techniques = graph.techniques_for_cve(cve_id)
        if not techniques and snapshot.lookup_cve(cve_id) is None:
            print(f"Unknown CVE: {cve_id}", file=sys.stderr)
            return 1
        print(f"{cve_id}")
        print(f"  Techniques  : {', '.join(techniques) or '-'}")
        return 0

    if args.kev_techniques:
        techniques = graph.kev_listed_techniques()
        print(f"KEV-linked techniques: {len(techniques)}")
        for ttp in techniques:
            print(f"  - {ttp}")
        return 0

    print("Provide --stats, --ttp <id>, --cve <id> or --kev-techniques", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="marine-log-sentinel",
        description="Marine Log Sentinel — military-grade log triage CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor",
        help="Check environment, required libraries, and audit log integrity.",
    )
    doctor.set_defaults(func=cmd_doctor)

    ingest = subparsers.add_parser(
        "ingest",
        help="Parse and normalize log files into the unified schema (JSONL output).",
    )
    ingest.add_argument(
        "--input", required=True, help="Log file or directory of log files."
    )
    ingest.add_argument(
        "--format", default=None, choices=SUPPORTED_FORMATS,
        help="Force a specific parser; auto-detected from filename otherwise.",
    )
    ingest.add_argument(
        "--glob", default="*", help="Glob pattern when --input is a directory.",
    )
    ingest.add_argument(
        "--output-dir", default=None,
        help="Output directory for the JSONL files (defaults to data/normalized/).",
    )
    ingest.set_defaults(func=cmd_ingest)

    analyze = subparsers.add_parser(
        "analyze",
        help=(
            "Run the ML pipeline (anomaly + TTP tagging) on normalized JSONL "
            "files and emit a predictions.jsonl ready for the scoring engine."
        ),
    )
    analyze.add_argument(
        "--input",
        required=True,
        help="Path to a .normalized.jsonl file or a directory containing several.",
    )
    analyze.add_argument(
        "--output",
        help="Where to write the predictions.jsonl (defaults to data/predictions/).",
    )
    analyze.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of MITRE techniques returned per log (default: 5).",
    )
    analyze.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Number of most-anomalous logs printed to stdout (default: 10).",
    )
    analyze.set_defaults(func=cmd_analyze)

    score = subparsers.add_parser(
        "score",
        help=(
            "Score every prediction from `analyze`, attach the explainable "
            "evidence chain, and rank logs by operational priority."
        ),
    )
    score.add_argument(
        "--input",
        required=True,
        help="Path to a predictions.jsonl produced by `analyze`.",
    )
    score.add_argument(
        "--output",
        help="Where to write the scored.jsonl (defaults to data/predictions/scored.jsonl).",
    )
    score.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="How many of the highest-priority logs to print (default: 10).",
    )
    score.add_argument(
        "--asset-inventory",
        default=None,
        help=(
            "Optional JSON inventory (hosts → criticality) to scale scores per asset; "
            "see marine_log_sentinel/examples/asset_inventory.example.json."
        ),
    )
    score.add_argument(
        "--sequential",
        action="store_true",
        help=(
            "Merge scores along time for the same actor (user/host/IP) with long-lived SQLite memory. "
            "Events are processed in chronological order, then re-sorted by effective priority."
        ),
    )
    score.add_argument(
        "--sequence-db",
        default=None,
        help=f"SQLite path for actor chains (default: {SETTINGS.sequence_db_path}).",
    )
    score.set_defaults(func=cmd_score)

    brief = subparsers.add_parser(
        "brief",
        help=(
            "Generate French operational briefs for officers from scored.jsonl "
            "(Étape 5 — translation)."
        ),
    )
    brief.add_argument(
        "--input",
        required=True,
        help="Path to scored.jsonl from `score`.",
    )
    brief.add_argument(
        "--inventory",
        default=None,
        help="Optional asset inventory JSON (same schema as score --asset-inventory).",
    )
    brief.add_argument(
        "--output",
        default=None,
        help="Optional path to write briefs as JSONL.",
    )
    brief.add_argument(
        "--top-n",
        type=int,
        default=5,
        help="How many highest-priority logs to brief (-1 = all). Default: 5.",
    )
    brief.add_argument(
        "--format",
        choices=("text", "jsonl"),
        default="text",
        help="stdout format (default: human-readable French text).",
    )
    brief.set_defaults(func=cmd_brief)

    report = subparsers.add_parser(
        "report",
        help=(
            "Generate a standalone French HTML officer report from scored.jsonl "
            "(Étape 6 — simple visualization)."
        ),
    )
    report.add_argument(
        "--input",
        required=True,
        help="Path to scored.jsonl produced by `score`.",
    )
    report.add_argument(
        "--output",
        default=None,
        help="Output HTML path (default: data/reports/rapport_officier.html).",
    )
    report.add_argument(
        "--inventory",
        default=None,
        help="Optional asset inventory JSON (same as score/brief).",
    )
    report.add_argument(
        "--top-n",
        type=int,
        default=25,
        help="Maximum number of detailed alert cards (default: 25, max practical cap 100).",
    )
    report.set_defaults(func=cmd_report)

    dashboard = subparsers.add_parser(
        "dashboard",
        help=(
            "Lancer le tableau de bord Streamlit (ingest/ML/score + replay chronologique). "
            "Requiert : pip install streamlit"
        ),
    )
    dashboard.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Port HTTP local (defaut: 8501).",
    )
    dashboard.set_defaults(func=cmd_dashboard)

    ti = subparsers.add_parser(
        "ti",
        help="Inspect or refresh the local Threat Intelligence snapshot (MITRE ATT&CK + CVE + KEV + EPSS).",
    )
    ti_sub = ti.add_subparsers(dest="ti_command", required=True)

    ti_show = ti_sub.add_parser("show", help="Show what we know about a TTP or a CVE.")
    group = ti_show.add_mutually_exclusive_group(required=True)
    group.add_argument("--ttp", help="MITRE technique id (e.g. T1059 or T1059.001).")
    group.add_argument("--cve", help="CVE id (e.g. CVE-2021-44228).")
    ti_show.set_defaults(func=cmd_ti_show)

    ti_sync = ti_sub.add_parser(
        "sync",
        help="Refresh KEV/EPSS (and optionally MITRE via TAXII) into the local cache. Forbidden in air-gap mode.",
    )
    ti_sync.add_argument("--no-kev", action="store_true", help="Skip CISA KEV refresh.")
    ti_sync.add_argument("--no-epss", action="store_true", help="Skip EPSS refresh.")
    ti_sync.add_argument(
        "--taxii",
        action="store_true",
        help="Also refresh the MITRE Enterprise STIX bundle via TAXII 2.1.",
    )
    ti_sync.set_defaults(func=cmd_ti_sync)

    ti_graph = ti_sub.add_parser(
        "graph",
        help="Query the local TI knowledge graph (networkx).",
    )
    graph_group = ti_graph.add_mutually_exclusive_group(required=True)
    graph_group.add_argument("--stats", action="store_true", help="Print graph statistics.")
    graph_group.add_argument("--ttp", help="List CVEs/mitigations/log sources for a technique.")
    graph_group.add_argument("--cve", help="List techniques referenced by a CVE.")
    graph_group.add_argument(
        "--kev-techniques",
        action="store_true",
        help="List techniques reachable from at least one KEV-listed CVE.",
    )
    ti_graph.set_defaults(func=cmd_ti_graph)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
