#!/usr/bin/env python3
"""Tableau de bord Streamlit — données, pipeline ML/score, évolution chronologique.

Lancer depuis la racine du dépôt ::

    pip install streamlit
    python -m streamlit run marine_log_sentinel/dashboard/app.py

Ou::

    python -m marine_log_sentinel dashboard
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from marine_log_sentinel.config import SETTINGS
from marine_log_sentinel.scoring.models import ScoredLog
from marine_log_sentinel.ingestion import normalize_directory
from marine_log_sentinel.ml import analyze_path
from marine_log_sentinel.scoring import score_predictions_file
from marine_log_sentinel.analysis import (
    attack_map_flat_frame,
    build_attack_map_from_scored,
    format_attack_campaigns_markdown_fr,
)

DASHBOARD_DIR = Path(__file__).resolve().parent
LOGO_PATH = DASHBOARD_DIR / "assets" / "marine_nationale_logo.png"

st.set_page_config(
    page_title="Marine Log Sentinel — Dashboard",
    page_icon=str(LOGO_PATH) if LOGO_PATH.exists() else "⚓",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Thème aux couleurs institutionnelles Marine nationale (bleu marine, rouge, blanc).
_MARINE_CSS = """
<style>
  :root {
    --mn-navy: #002045;
    --mn-navy-deep: #00152d;
    --mn-red: #e1000f;
    --mn-surface: #f4f6f9;
    --mn-sidebar-text: #e8eef4;
  }

  html, body, [data-testid="stAppViewContainer"], .main {
    background-color: var(--mn-surface) !important;
  }

  header[data-testid="stHeader"] {
    background: #ffffff !important;
    border-bottom: 4px solid var(--mn-red) !important;
  }

  section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, var(--mn-navy-deep) 0%, var(--mn-navy) 100%);
    border-right: 3px solid var(--mn-red);
  }

  section[data-testid="stSidebar"] h1,
  section[data-testid="stSidebar"] h2,
  section[data-testid="stSidebar"] h3 {
    color: #ffffff !important;
    font-weight: 700;
    letter-spacing: 0.04em;
  }

  section[data-testid="stSidebar"] label,
  section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
  section[data-testid="stSidebar"] .stMarkdown {
    color: var(--mn-sidebar-text) !important;
  }

  .main .block-container h1,
  div[data-testid="stMarkdownContainer"] h1 {
    color: var(--mn-navy) !important;
    font-weight: 800;
    letter-spacing: 0.02em;
    border-bottom: 3px solid var(--mn-red);
    padding-bottom: 0.4rem !important;
  }

  .main h2,
  .main h3,
  div[data-testid="stMarkdownContainer"] h2,
  div[data-testid="stMarkdownContainer"] h3 {
    color: var(--mn-navy) !important;
    font-weight: 700;
    border-left: 4px solid var(--mn-red);
    padding-left: 0.65rem !important;
  }

  hr {
    border: none !important;
    border-top: 1px solid rgba(0, 32, 69, 0.25) !important;
  }

  .streamlit-expanderHeader {
    color: var(--mn-navy) !important;
    font-weight: 600 !important;
  }

  .stButton button[kind="primary"] {
    background-color: var(--mn-red) !important;
    color: #ffffff !important;
    border: none !important;
    font-weight: 700 !important;
  }

  .stButton button[kind="primary"]:hover {
    filter: brightness(1.06);
    box-shadow: 0 0 0 2px rgba(225, 0, 15, 0.35);
  }

  .stButton button[kind="secondary"] {
    background-color: #ffffff !important;
    color: var(--mn-navy) !important;
    border: 2px solid var(--mn-navy) !important;
    font-weight: 600 !important;
  }

  .stButton button[kind="secondary"]:hover {
    background-color: rgba(0, 32, 69, 0.06) !important;
    border-color: var(--mn-red) !important;
    color: var(--mn-navy) !important;
  }
</style>
"""
st.markdown(_MARINE_CSS, unsafe_allow_html=True)

st.title("Marine Log Sentinel")
st.caption(
    "**Marine Nationale** · triage cyber — ingestion, ML + scoring TI, puis **replay "
    "chronologique** (simulation quasi temps réel sur l’historique)."
)


@st.cache_resource
def _ti_snapshot():
    """Charge MITRE/CVE une fois (mode offline après synchronisation artefacts)."""

    from marine_log_sentinel.threat_intel.snapshot import load_threat_intel

    return load_threat_intel()


def _sidebar_logo(path: Path) -> None:
    """Compatible anciennes versions de Streamlit (use_column_width puis largeur étirée)."""

    p = str(path)
    try:
        st.image(p, use_container_width=True)
    except TypeError:
        try:
            st.image(p, use_column_width=True)  # Streamlit ancien (< ~1.33)
        except TypeError:
            st.image(p)


def _load_scored_chron(jsonl_path: Path) -> list[ScoredLog]:
    rows: list[ScoredLog] = []
    if not jsonl_path.exists():
        return rows
    with jsonl_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(ScoredLog.model_validate_json(line))
    rows.sort(key=lambda s: s.prediction.timestamp_utc)
    return rows


with st.sidebar:
    if LOGO_PATH.exists():
        _sidebar_logo(LOGO_PATH)
    st.markdown(
        '<p style="text-align:center;color:#b8c5d0;font-size:0.78rem;margin:-0.25rem 0 1rem 0;">'
        "Identité visuelle — Marine nationale</p>",
        unsafe_allow_html=True,
    )
    st.header("Entrées")
    raw_dir = st.text_input(
        "Dossier logs bruts (ingest)",
        value=str(SETTINGS.project_root / "SujetsHackathon2026/Sujet1"),
        help="Répertoire contenant les fichiers du challenge (.JSON, CSV, Sysmon, …).",
    )
    norm_dir_val = str(SETTINGS.data_dir / "normalized")
    norm_out = st.text_input("Sortie normalisation (`ingest`)", value=norm_dir_val)

    st.divider()
    use_sequential = st.checkbox(
        "Scoring séquentiel (mémoire acteur, SQLite)",
        value=False,
    )
    seq_db_override = st.text_input(
        "SQLite séquence (vide = défaut)",
        value="",
        help=str(SETTINGS.sequence_db_path),
    )

    st.divider()
    delay_ms = st.slider("Pause replay (ms) par événement", 0, 500, 80, step=10)
    replay_from_file = st.text_input(
        "Replay direct depuis fichier scored.jsonl (optionnel)",
        value="",
        help="Si rempli et fichier existant → pas besoin de relancer le pipeline pour l’animation.",
    )

    st.divider()
    st.subheader("Carte d’attaque")
    attack_min_score = st.slider(
        "Score minimal (filtre événements)", 0.0, 100.0, 0.0, 0.5,
        help="Ignore les lignes scored dont le score final est sous ce seuil.",
    )
    attack_max_ttps = st.slider(
        "TTP pris par événement",
        min_value=1,
        max_value=8,
        value=5,
        help="Plus il est élevé, plus vous captez d’hypothèses « moyens » possibles sous chaque étape.",
    )

col_a, col_b, col_c = st.columns(3)

with col_a:
    run_ingest = st.button("1 — Ingestion", type="secondary")
with col_b:
    run_ml = st.button("2 — Analyse ML", type="secondary")
with col_c:
    run_score_btn = st.button("3 — Scoring TI", type="primary")

st.divider()
run_all = st.button("Pipeline complet (ingest → analyse → score)", type="primary")

status = st.container()
log_panel = st.expander("Détails d’exécution")

pred_path_default = SETTINGS.data_dir / "predictions" / "predictions.jsonl"
scored_path_default = SETTINGS.data_dir / "predictions" / "scored.jsonl"

state = st.session_state
if "pipeline_log" not in state:
    state.pipeline_log = []


def _log(msg: str) -> None:
    state.pipeline_log.append(msg)


def _ingest(raw: Path, norm_out_: Path) -> int:
    norm_out_.mkdir(parents=True, exist_ok=True)
    results = list(normalize_directory(raw, glob="*"))
    n_records = sum(len(r.records) for r in results)
    n_err = sum(len(r.errors) for r in results)
    _log(f"Ingest : {len(results)} fichiers, {n_records} enreg., {n_err} erreurs → {norm_out_}")
    for r in results:
        fname = Path(r.source_file).name + ".normalized.jsonl"
        out_path = norm_out_ / fname
        with out_path.open("w", encoding="utf-8") as h:
            for rec in r.records:
                h.write(rec.model_dump_json() + "\n")
    return 0 if n_err == 0 else 2


def _analyze(norm: Path, out_predictions: Path) -> None:
    _ti_snapshot()
    res = analyze_path(norm, out_predictions)
    _log(f"ML : {len(res.predictions)} prédictions → {out_predictions}")


def _score(pred: Path, out_scored: Path, sequential: bool, seq_db: Path | None) -> None:
    _ti_snapshot()
    score_predictions_file(
        pred,
        out_scored,
        sequential=sequential,
        sequence_db_path=seq_db if seq_db and str(seq_db) else None,
    )
    path = seq_db if seq_db and str(seq_db) else SETTINGS.sequence_db_path
    mode = "séquentiel" if sequential else "ponctuel"
    _log(f"Score ({mode}) → {out_scored} · DB séquence : {path}")


def _seq_db_path_from_ui() -> Path | None:
    p = seq_db_override.strip()
    return Path(p) if p else None


raw_path = Path(raw_dir).expanduser()
norm_path = Path(norm_out).expanduser()
pred_out = Path(pred_path_default)
scored_out = Path(scored_path_default)


with log_panel:
    if state.pipeline_log:
        st.code("\n".join(state.pipeline_log[-40:]))
    if run_all or run_ingest or run_ml or run_score_btn:
        seq_db = _seq_db_path_from_ui()
        try:
            if run_all or run_ingest:
                if not raw_path.is_dir():
                    st.error(f"Dossier introuvable : {raw_path}")
                else:
                    with status:
                        st.info("Étape ingestion…")
                    rc = _ingest(raw_path, norm_path)
                    if rc != 0:
                        status.warning("Ingest terminé avec des erreurs (voir dossier)")
                    else:
                        status.success("Ingest terminé.")

            if run_all or run_ml:
                if not norm_path.is_dir() or not list(norm_path.glob("*.jsonl")):
                    status.error(f"Pas de JSONL sous {norm_path} — lançez l’ingestion d’abord.")
                else:
                    status.info("Analyse ML (IsolationForest + TTP TF-IDF)…")
                    _analyze(norm_path, pred_out)
                    status.success(f"Prédictions écrites : {pred_out}")

            if run_all or run_score_btn:
                if not pred_out.exists():
                    status.error("Fichier predictions absent — analyse ML d’abord.")
                else:
                    status.info("Scoring + TI…")
                    _score(pred_out, scored_out, use_sequential, seq_db)
                    status.success(f"Scores écrits : {scored_out}")
        except Exception as exc:
            status.error(str(exc))
            _log(str(exc))


st.divider()
st.subheader("Carte d’attaque (chemins reconstitués)")
st.caption(
    "**Étape tactique** = objectif générique du framework ATT&CK (ex. gagner une « entrée », "
    "**peu importe le biais**).\n\n"
    "**Moyens observés** = techniques `Txxxx` détectées sur les logs comme autant "
    "**d’itinéraires concrets distincts**, comparables aux façons différentes d’atteindre "
    "**la même** intention."
)

attack_src_txt = replay_from_file.strip() or str(scored_path_default)
attack_src_path = Path(attack_src_txt).expanduser()
col_ma, col_mb = st.columns([1, 2])
with col_ma:
    run_attack_carto = st.button("Construire depuis scored.jsonl", type="secondary")
with col_mb:
    st.markdown(
        f"**Fichier** : `{attack_src_path}` — aligné sur la zone **Replay** lorsque vous ne "
        "remplacez pas le chemin personnalisé."
    )

if run_attack_carto:
    if not attack_src_path.exists():
        st.warning(f"Aucune donnée scored : `{attack_src_path}` — lancez le scoring d’abord.")
    else:
        try:
            snap = _ti_snapshot()
            rows_map = _load_scored_chron(attack_src_path)
            atk = build_attack_map_from_scored(
                rows_map,
                snap,
                min_log_score=float(attack_min_score),
                max_ttps_per_event=int(attack_max_ttps),
            )
            meta = (
                f"Évènements hors seuil ({attack_min_score}) : **{atk.rows_skipped_low_score}**. "
                f"Sans attribution TTP : **{atk.rows_without_ttp}**."
            )
            st.markdown(format_attack_campaigns_markdown_fr(atk))
            st.markdown(meta)
            flat = attack_map_flat_frame(atk)
            if not flat.empty:
                st.markdown("##### Table agrégée (export / filtre)")
                st.dataframe(flat, hide_index=True, use_container_width=True)
            else:
                st.info(
                    "Aucune ligne exploitable après filtrage "
                    "(fichier vide, scores trop faibles, pas de TTP sur les lignes)."
                )
        except FileNotFoundError as exc:
            st.error(f"Fichier ou artefact TI manquant : {exc}")
        except Exception as exc:
            st.error(str(exc))


st.divider()
st.subheader("Évolution quasi temps réel (ordre chronologique)")

anim_path_txt = replay_from_file.strip() or str(scored_out)
anim_path = Path(anim_path_txt).expanduser()
col_r1, col_r2 = st.columns([1, 3])
with col_r1:
    start_anim = st.button("Lancer le replay chronologique", type="secondary")
with col_r2:
    stop_anim = st.button("Réinitialiser l’historique affiché", type="secondary")

if stop_anim:
    state.pop("replay_df", None)
    state.pop("replay_i", None)
    st.success("Courbes effacées côté session.")

chart_slot = st.empty()
table_slot = st.empty()

if start_anim:
    if not anim_path.exists():
        st.warning(f"Aucune donnée : {anim_path}")
    else:
        rows_chron = _load_scored_chron(anim_path)
        if not rows_chron:
            st.warning("Fichier vide ou aucune ligne scored valide.")
        else:
            history: list[dict[str, object]] = []
            for i, s in enumerate(rows_chron):
                ts = s.prediction.timestamp_utc.isoformat()
                band = s.severity_band
                actor = ""
                seq_note = ""
                if s.sequence:
                    actor = s.sequence.actor_key
                    seq_note = f"punctuel={s.sequence.point_in_time_score:.1f}"
                tip = ""
                if s.evidence.top_ttp:
                    tip = s.evidence.top_ttp.technique_id
                prev_max = max((float(h["score"]) for h in history), default=0.0)
                cumul_max = max(prev_max, float(s.score))
                history.append(
                    {
                        "i": i + 1,
                        "instant": pd.Timestamp(ts),
                        "score": float(s.score),
                        "cumul_max": cumul_max,
                        "bande": band,
                        "fmt": s.prediction.source_format,
                        "ttp": tip,
                        "acteur": actor[:48] + ("…" if len(actor) > 48 else actor),
                        "note_seq": seq_note,
                    }
                )
                df = pd.DataFrame(history)
                df_idx = df.set_index("instant")
                chart_slot.line_chart(df_idx[["score", "cumul_max"]], height=280)
                table_slot.dataframe(df.tail(12), hide_index=True, use_container_width=True)
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            state.replay_df = history
            st.success(f"Replay terminé ({len(history)} événements).")


if getattr(state, "replay_df", None) and not start_anim:
    df = pd.DataFrame(state.replay_df)
    if not df.empty:
        df_idx = df.set_index("instant")
        st.line_chart(df_idx[["score", "cumul_max"]], height=280)
        st.dataframe(df, hide_index=True, use_container_width=True)

st.markdown(
    """
---
**À savoir pour le jury** :
- Les boutons utilisent les **modules Python** déjà présents dans le projet (pas d’API externe après install).
- Le « temps réel » est un **replay** sur l’horloge réelle ou des données pré-calculées, adapté aux environnements **air-gap**.
- Pour un flux SIEM continu réel il faudrait brancher cette boucle à un broker (Kafka, etc.), hors périmètre hackathon actuel.
"""
)
