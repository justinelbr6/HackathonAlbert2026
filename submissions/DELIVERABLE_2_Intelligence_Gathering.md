# Deliverable 2 — Intelligence Gathering
**Mission briefing · Marine Log Sentinel** — *SOC log triage + open threat-intel fusion (air-gap capable)* · **Tuesday May 12, 2026**

**Export**: copy into Word/Google Docs → *Print → Save as PDF* — **1 page**, narrow margins (~1.27 cm), **10 pt**, single spacing.

---

## A. OSINT framework

**Methodology (how we mine intel)**  
We treat **official, publicly distributed cyber intelligence** as OSINT corpora: artefacts are **ingested once** (sync host or sneakernet), frozen under **SHA-256 fingerprints**, and replayed offline. No opaque scraping; **`ti.load`** is written to an audit trace so scoring/ML rests on **named files**, not a “black box”.  
*Tactical implication*: intelligence is reproducible aboard or in **air-gap** (`MLS_AIR_GAP`), matching the naval constraint more than ephemeral web queries.

| OSINT channels (technical / open) | Role in targeting this problem |
|-----------------------------------|-------------------------------|
| **MITRE ATT&CK** (Enterprise STIX bundle via official distribution) | Tactics/TTP taxonomy, detection strategies, → **structured “enemy doctrine”** for log text matching & officer narrative. |
| **CVE / NVD-style extracts + MITRE linkage** | Vulnerability identifiers tied to techniques → **exploit exposure signal** fused into priority. |
| **CISA Known Exploited Vulnerabilities (KEV)** | Binary “actively exploited in the wild?” → raises confidence when correlated with a CVE. |
| **FIRST EPSS** (probability of exploitation in the wild) | **Ranking under uncertainty** when CVSS alone is blunt. |
| **Optional TAXII 2.x** (`taxii2-client`) | Controlled pull of MITRE collections when online; artefacts then cached locally. |

| Tools in the belt | Why they fit **this** target |
|-------------------|-----------------------------|
| **Python 3.x** + **Pydantic v2** | Typed pipeline for logs + TI — auditable schemas, jury-defensible parsing. |
| **stix2**, **attackcti**, **taxii2-client** | Standard STIX/TAXII access to ATT&CK (no bespoke scrapers — **explicitly excludes `pyattck`** per ADR-001 for air-gap & dependency hygiene). |
| **NetworkX** | Lightweight **CVE ↔ TTP ↔ mitigation ↔ detection ↔ log-source** graph for explainable enrichment. |
| **scikit-learn** (IsolationForest + TF-IDF cosine) | **No pretrained LLM outbound download**: anomaly trained on-batch; TTP hypotheses from technique **OSINT descriptions** + log text → fits constrained networks. |

---

## B. Dataset inventory (“the gold”)

| Primary dataset | Provenance | Freshness (*as used*) | “So what” (one sentence) |
|-----------------|-----------|------------------------|---------------------------|
| **Enterprise ATT&CK STIX ZIP** (`enterprise-attack.json.zip`, challenge bundle `Sujet1/Généralisation/`) | MITRE Corp. redistribution in pack | Frozen at **challenge snapshot** timestamp; refresh via official bundle replace. | Supplies the **ontology** tying raw logs to **named adversary behaviours** officers recognize. |
| **CVE excerpts** (`Extrait_cve_data.JSON`, `cve_data_with_cvss_and_mitre.csv`, `Sujet1/MiseEnJambe/`) | NVD-aligned extract packaged with challenge | Idem — **pinned** cohort for hackathon reproducibility. | Converts “random vulnerability strings in logs” into **severity + technique bridges** usable in fusion scoring. |
| **KEV + EPSS cache files** (when present under project cache post-`sync`) | CISA + FIRST *(public CSV/JSON norms)* | **As-of sync date** recorded alongside file hashes in audit payloads. | Distinguishes “theoretical vuln noise” from **operational urgency** proxies. |
| **Normalized corpus** (`*.normalized.jsonl` from raw challenge logs — Sysmon, Apache, Suricata, etc.) | Supplied synthetic / exercise logs | Frozen per run batch; ingestion output is deterministic for a given SHA. | Provides the **telemetry “soil layer”**: without it ATT&CK is only theory — here it becomes **actionable prioritization**. |

**Data provenance discipline:** SHA-256 of MITRE/CVE sources logged at **`ti.load`** (`marine_log_sentinel/threat_intel/snapshot.py`); avoids “sand foundation” arguments.

---

## C. Intelligence gaps & risks

| Gap (missing link) | Mitigation |
|--------------------|-----------|
| **No ground-truth labels** (“this log line = benign/malicious”) for supervised learning beyond weak TI proxies. | **Unsupervised** per-format IsolationForest + **interpretable** TF-IDF matches with **rationales**; officer sees “why ATT&CK,” not black-box probabilities. |
| **No proprietary CTI feeds** (ISAC feeds, classified reporting). | Lean on **KEV / EPSS / CVSS** as open proxies + **explicit graph paths** CVE→TTP→detection→log channel for “collection guidance.” |
| **Ephemeral freshness** risk if artefacts age beyond exercise window. | **Versioned bundles** + hash audit; optional **TAXII sync** on connected segment, then **air-gap replay** of same snapshot. |
| **Volume / diversity** of real fleet logs under exercise size. | Honest scope: **proof of fusion & explainability** on challenge scale; scale argument = architected batch pipeline, not hero demo on petabytes. |

**Bottom line:** Foundation is **named public intelligence corpora + reproducible fingerprints**, not undisclosed APIs — compatible with a **mission briefing** standard of evidence.
