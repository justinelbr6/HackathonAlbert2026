# Marine Log Sentinel

Outil d'analyse de logs militaire pour le hackathon Marine nationale — Sujet 1
*Log as Code*.

## Idée

Backend complexe, frontend simple. On ingère des logs hétérogènes, on les
relie aux référentiels MITRE ATT&CK et CVE en local, on les passe dans un
pipeline ML (anomalie + retrieval sémantique), on les score, et on en sort
un rapport opérationnel destiné à un officier non-cyber.

## Architecture en couches

```text
marine_log_sentinel/
├── config.py            # Configuration centrale + mode air-gap
├── observability/       # Logger JSON + audit log à chaîne de hash
├── ingestion/           # (Étape 1) Parsers + schéma de log unifié
├── threat_intel/        # (Étape 2) MITRE ATT&CK + CVE + KEV + EPSS
├── ml/                  # (Étape 3) Détection d'anomalies + TTP retrieval
├── scoring/             # (Étape 4) Score composite explicable
├── translation/         # (Étape 5) Traduction cyber -> Marine
├── reporting/           # (Étape 6) Rapport officier
└── cli.py               # CLI (doctor, ingest, triage, report)
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Geler les versions exactes pour la reproductibilité d'audit :
pip freeze > requirements.lock.txt
```

## Vérification de l'environnement

```bash
python -m marine_log_sentinel doctor
```

Affiche la version Python, les bibliothèques imposées présentes/manquantes,
le mode air-gap, et l'état de la chaîne d'audit.

## Mode air-gap

Activable par variable d'environnement :

```bash
export MLS_AIR_GAP=1
```

Quand ce mode est ON, aucune couche n'a le droit d'effectuer d'appel
réseau sortant. Les composants de threat intelligence n'utilisent que le
cache local.

## Décisions d'architecture

Les décisions techniques structurantes (par exemple le retrait délibéré de
`pyattck` pour préserver la posture air-gap) sont documentées dans
[`ARCHITECTURE_DECISIONS.md`](./ARCHITECTURE_DECISIONS.md).

## Audit log

Toutes les actions sensibles sont consignées dans
`data/audit/audit.log.jsonl`, chaque entrée embarquant le SHA-256 de la
précédente. La vérification se fait via :

```python
from marine_log_sentinel.observability.audit import verify_chain
print(verify_chain())
```
