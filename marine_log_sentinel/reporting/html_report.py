"""Standalone HTML officer report (Étape 6).

Produces a single `.html` file with embedded CSS — no CDN, no framework,
works offline after generation (air-gap friendly). All dynamic strings are
HTML-escaped to prevent XSS if log payloads contain markup.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from marine_log_sentinel import __version__
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger
from marine_log_sentinel.scoring.models import ScoredLog
from marine_log_sentinel.translation.assets import try_load_inventory
from marine_log_sentinel.translation.brief import build_operational_brief_fr
from marine_log_sentinel.translation.models import OperationalBriefFr

LOGGER = get_logger(__name__)

_BAND_LABEL_FR = {
    "CRITICAL": "Critique",
    "HIGH": "Élevé",
    "MEDIUM": "Modéré",
    "LOW": "Faible",
}


def _load_scored_sorted(path: Path) -> list[ScoredLog]:
    with path.open(encoding="utf-8") as handle:
        logs = [ScoredLog.model_validate_json(line) for line in handle if line.strip()]
    logs.sort(key=lambda s: -s.score)
    return logs


def _pairs_for_report(
    scored_logs: list[ScoredLog],
    *,
    inventory_path: Path | None,
    detail_limit: int,
) -> tuple[list[tuple[ScoredLog, OperationalBriefFr]], int]:
    """Return (detail_rows, total_count). Detail rows capped at ``detail_limit``."""

    inventory = try_load_inventory(inventory_path)
    rows: list[tuple[ScoredLog, OperationalBriefFr]] = []
    for entry in scored_logs[:detail_limit]:
        hit = inventory.resolve(entry.prediction) if inventory else None
        rows.append((entry, build_operational_brief_fr(entry, asset_hit=hit)))
    return rows, len(scored_logs)


def _dashboard_cells(counts: Counter[str]) -> str:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    parts: list[str] = []
    for band in order:
        n = counts.get(band, 0)
        cls = f"dash-{band.lower()}"
        label = escape(_BAND_LABEL_FR.get(band, band))
        parts.append(f'<div class="dash-cell {cls}"><span class="dash-n">{n}</span><span class="dash-l">{label}</span></div>')
    return "\n".join(parts)


def _render_card(idx: int, scored: ScoredLog, brief: OperationalBriefFr) -> str:
    band = scored.severity_band
    band_fr = escape(_BAND_LABEL_FR.get(band, band))
    pred = scored.prediction
    ts = pred.timestamp_utc.isoformat()
    raw_safe = escape(pred.raw_excerpt[:2000])
    title = escape(brief.titre)
    niveau = escape(brief.niveau_operationnel_fr)
    resume = escape(brief.resume_pour_commandement)

    impacts = "".join(f"<li>{escape(line)}</li>" for line in brief.impacts_operationnels)
    actions = "".join(f"<li>{escape(line)}</li>" for line in brief.actions_prioritaires[:8])
    journaux = "".join(f"<li>{escape(line)}</li>" for line in brief.journaux_et_traces_a_collecter[:8])

    anc = brief.ancres_techniques
    ttps = escape(", ".join(anc.technique_ids) or "—")
    cves = escape(", ".join(anc.cve_ids) or "—")
    kev = "oui" if anc.kev_signale else "non"

    meta_parts = [
        f'<span><strong>Format</strong> {escape(pred.source_format)}</span>',
        f'<span><strong>Fichier source</strong> {escape(pred.source_file)}</span>',
        f'<span><strong>Horodatage</strong> {escape(ts)}</span>',
        f'<span><strong>Score</strong> {anc.score_numerique:.1f}</span>',
    ]
    if brief.actif_identifie:
        meta_parts.append(f'<span><strong>Actif</strong> {escape(brief.actif_identifie)}</span>')
    meta_row = '<div class="meta">' + " · ".join(meta_parts) + "</div>"

    seq_block = ""
    if scored.sequence:
        seq = scored.sequence
        seq_block = f"""
  <section class="block sequence">
    <h3>Fil conducteur (même acteur, mémoire longue)</h3>
    <p><strong>Acteur</strong> <code>{escape(seq.actor_key)}</code> — événement n°{seq.chain_index} enregistré en base.</p>
    <p>Score <em>ponctuel</em> {seq.point_in_time_score:.1f} ({escape(seq.point_in_time_band)}) → score <em>opérationnel fusionné</em> {seq.effective_score:.1f} ({escape(seq.effective_band)}).</p>
    <p>{escape(seq.rationale_fr)}</p>
  </section>"""

    anchor_id = f"alert-{idx}"

    return f"""
<article id="{anchor_id}" class="card severity-{band.lower()}" aria-labelledby="{anchor_id}-title">
  <header class="card-head">
    <span class="badge band-{band.lower()}" aria-label="Niveau {band_fr}">{band_fr}</span>
    <h2 id="{anchor_id}-title">{title}</h2>
  </header>
  <p class="lead">{niveau}</p>
  {meta_row}
  {seq_block}
  <section class="block">
    <h3>Synthèse pour le commandement</h3>
    <p>{resume}</p>
  </section>
  <section class="block">
    <h3>Impacts opérationnels possibles</h3>
    <ul>{impacts}</ul>
  </section>
  <section class="block">
    <h3>Actions prioritaires</h3>
    <ul class="actions">{actions}</ul>
  </section>
  <section class="block">
    <h3>Journaux et traces à conserver ou collecter</h3>
    <ul>{journaux}</ul>
  </section>
  <section class="block tech">
    <h3>Références techniques (SOC)</h3>
    <p class="mono">TTP : {ttps} · CVE : {cves} · KEV : {kev}</p>
  </section>
  <details class="raw">
    <summary>Extrait brut du log (technique)</summary>
    <pre>{raw_safe}</pre>
  </details>
</article>
"""


def build_officer_html_document(
    *,
    scored_sorted: list[ScoredLog],
    detail_rows: list[tuple[ScoredLog, OperationalBriefFr]],
    generated_at_utc: datetime | None = None,
) -> str:
    """Return full HTML document string."""

    when = generated_at_utc or datetime.now(timezone.utc)
    when_str = escape(when.isoformat())
    counts = Counter(s.severity_band for s in scored_sorted)
    total = len(scored_sorted)
    detail_n = len(detail_rows)

    toc_items = "".join(
        f'<li><a href="#alert-{i + 1}">#{i + 1} — {escape(brief.titre[:72])}</a></li>'
        for i, (_, brief) in enumerate(detail_rows)
    )

    cards = "".join(_render_card(i + 1, s, b) for i, (s, b) in enumerate(detail_rows))

    wf = ""
    if scored_sorted:
        wf = escape(scored_sorted[0].weights_fingerprint[:16])

    extras = ""
    if wf:
        extras = f"<p>Poids de scoring (empreinte) : <code>{wf}</code>…</p>"

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Rapport Marine Log Sentinel</title>
  <style>
:root {{
  --ink: #0f2942;
  --paper: #f6f8fb;
  --card: #ffffff;
  --muted: #546e7a;
  --critical: #b71c1c;
  --high: #e65100;
  --medium: #f57f17;
  --low: #455a64;
  --border: #cfd8dc;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  background: var(--paper);
  color: var(--ink);
  line-height: 1.5;
}}
header.site {{
  background: linear-gradient(135deg, var(--ink), #1a4971);
  color: #fff;
  padding: 1.75rem 1.5rem 2rem;
}}
header.site h1 {{ margin: 0 0 0.35rem; font-size: 1.55rem; font-weight: 650; }}
header.site p {{ margin: 0; opacity: 0.92; font-size: 0.95rem; }}
.wrap {{ max-width: 920px; margin: 0 auto; padding: 0 1rem 3rem; }}
.dashboard {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.65rem;
  margin: -1.25rem 0 1.5rem;
  position: relative;
  z-index: 1;
}}
@media (max-width: 720px) {{ .dashboard {{ grid-template-columns: repeat(2, 1fr); }} }}
.dash-cell {{
  background: var(--card);
  border-radius: 10px;
  padding: 1rem;
  text-align: center;
  box-shadow: 0 2px 8px rgba(15,41,66,.08);
  border-top: 4px solid var(--border);
}}
.dash-critical {{ border-top-color: var(--critical); }}
.dash-high {{ border-top-color: var(--high); }}
.dash-medium {{ border-top-color: var(--medium); }}
.dash-low {{ border-top-color: var(--low); }}
.dash-n {{ display: block; font-size: 1.85rem; font-weight: 700; }}
.dash-l {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}

.layout {{
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 1.5rem;
  align-items: start;
}}
@media (max-width: 800px) {{ .layout {{ grid-template-columns: 1fr; }} }}

nav.toc {{
  position: sticky;
  top: 1rem;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem;
  font-size: 0.88rem;
}}
nav.toc h2 {{ margin: 0 0 0.6rem; font-size: 0.95rem; }}
nav.toc ul {{ margin: 0; padding-left: 1.1rem; }}
nav.toc li {{ margin-bottom: 0.35rem; }}
nav.toc a {{ color: #1565c0; text-decoration: none; }}
nav.toc a:hover {{ text-decoration: underline; }}

.card {{
  background: var(--card);
  border-radius: 12px;
  padding: 1.35rem 1.35rem 1rem;
  margin-bottom: 1.35rem;
  box-shadow: 0 2px 10px rgba(15,41,66,.07);
  border: 1px solid var(--border);
  border-left-width: 5px;
}}
.severity-critical {{ border-left-color: var(--critical); }}
.severity-high {{ border-left-color: var(--high); }}
.severity-medium {{ border-left-color: var(--medium); }}
.severity-low {{ border-left-color: var(--low); }}

.card-head {{
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.65rem;
}}
.card-head h2 {{ margin: 0; font-size: 1.18rem; flex: 1 1 200px; }}

.badge {{
  display: inline-block;
  padding: 0.25rem 0.55rem;
  border-radius: 6px;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: .03em;
  color: #fff;
}}
.band-critical {{ background: var(--critical); }}
.band-high {{ background: var(--high); }}
.band-medium {{ background: var(--medium); }}
.band-low {{ background: var(--low); }}

.lead {{ font-weight: 600; color: var(--muted); margin: 0.5rem 0 0.75rem; }}
.meta {{
  font-size: 0.82rem;
  color: var(--muted);
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 1rem;
  margin-bottom: 1rem;
}}
.block h3 {{
  margin: 1rem 0 0.4rem;
  font-size: 0.92rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--ink);
}}
.block ul {{ margin: 0.35rem 0 0; padding-left: 1.2rem; }}
.block li {{ margin-bottom: 0.35rem; }}
.block.sequence {{
  background: #e8f4fc;
  border-left: 4px solid #1565c0;
  padding: 0.75rem 1rem;
  border-radius: 8px;
}}
.block.sequence code {{ font-size: 0.84rem; }}
.actions li {{ font-weight: 500; }}
.tech .mono {{
  font-family: ui-monospace, monospace;
  font-size: 0.84rem;
  word-break: break-word;
}}
details.raw {{
  margin-top: 1rem;
  border-top: 1px dashed var(--border);
  padding-top: 0.75rem;
}}
details.raw summary {{
  cursor: pointer;
  font-weight: 600;
  color: var(--muted);
}}
details.raw pre {{
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.78rem;
  background: #eceff1;
  padding: 0.75rem;
  border-radius: 8px;
  overflow-x: auto;
}}

footer {{
  margin-top: 2rem;
  padding: 1.25rem;
  font-size: 0.82rem;
  color: var(--muted);
  border-top: 1px solid var(--border);
}}
footer strong {{ color: var(--ink); }}
  </style>
</head>
<body>
  <header class="site">
    <div class="wrap">
      <h1>Rapport de prioritisation cyber</h1>
      <p>Marine Log Sentinel v{escape(__version__)} · généré le {when_str} (UTC)</p>
    </div>
  </header>
  <div class="wrap">
    <section class="dashboard" aria-label="Synthèse par niveau">
{_dashboard_cells(counts)}
    </section>
    <p>Ce rapport présente les <strong>{detail_n}</strong> événements les plus prioritaires sur un total de <strong>{total}</strong> événements analysés.</p>
    {extras}

    <div class="layout">
      <nav class="toc" aria-label="Sommaire">
        <h2>Sommaire</h2>
        <ul>
{toc_items}
        </ul>
      </nav>
      <main>
{cards}
      </main>
    </div>

    <footer>
      <p><strong>Lecture opérationnelle.</strong> Les scores combinent anomalie statistique, correspondance avec le référentiel MITRE ATT&CK, gravité CVE et signaux CISA KEV lorsque disponibles. Les actions listées sont indicatives : adapter aux procédures internes et au niveau de classification du SI.</p>
      <p>Document autonome — aucune connexion réseau requise pour consulter cette page après génération.</p>
    </footer>
  </div>
</body>
</html>
"""


def write_officer_html_report(
    scored_path: Path,
    output_path: Path,
    *,
    inventory_path: Path | None = None,
    top_n: int = 25,
) -> tuple[str, dict[str, object]]:
    """Write HTML report; return ``(sha256_hex, summary_dict)``."""

    scored_sorted = _load_scored_sorted(scored_path)
    n_total = len(scored_sorted)
    cap = max(1, min(top_n, 100))
    detail_rows, total = _pairs_for_report(
        scored_sorted,
        inventory_path=inventory_path,
        detail_limit=min(cap, n_total),
    )

    html = build_officer_html_document(
        scored_sorted=scored_sorted,
        detail_rows=detail_rows,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = html.encode("utf-8")
    output_path.write_bytes(payload_bytes)
    digest = hashlib.sha256(payload_bytes).hexdigest()

    bands_count = dict(Counter(s.severity_band for s in scored_sorted))

    summary: dict[str, object] = {
        "total_events": total,
        "detail_cards": len(detail_rows),
        "bands_count": bands_count,
        "output_sha256": digest,
    }

    audit_record(
        "reporting.html.generated",
        payload={
            "input_scored_path": str(scored_path),
            "output_path": str(output_path),
            "output_sha256": digest,
            "inventory_path": str(inventory_path) if inventory_path else None,
            "top_n_requested": top_n,
            **{k: v for k, v in summary.items() if k != "output_sha256"},
        },
    )
    LOGGER.info(
        "reporting.html.ok",
        extra={"sha256": digest[:16], "cards": len(detail_rows)},
    )
    return digest, summary
