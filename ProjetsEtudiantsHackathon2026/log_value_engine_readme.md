# Threat-to-Log Value Engine — MVP

## Objectif

Ce module est le premier prototype concret de notre solution **Log as Code**.

Il ne se contente pas de transformer une TTP en YAML. Il ajoute une couche de décision :

> menace + actif + contrainte → logs candidats → score de valeur → priorité → politique expliquée

L’objectif est de montrer que notre originalité vient de la **priorisation** et de l’**explicabilité**, pas seulement de la génération d’un fichier.

---

## Fichier principal

```text
scripts/log_value_engine.py
```

Ce script lit le fichier fourni par le challenge :

```text
SujetsHackathon2026/Sujet1/MiseEnJambe/mapping_ttps_cve_logs.csv
```

Il exploite maintenant aussi le dataset de généralisation MITRE ATT&CK :

```text
SujetsHackathon2026/Sujet1/Généralisation/enterprise-attack.json.zip
```

Cette brique charge environ **697 techniques ATT&CK actives** et ajoute un premier module NLP léger de similarité texte → techniques MITRE. L’objectif est de dépasser les 5 lignes de `MiseEnJambe` sans prétendre à un modèle supervisé production.

Il peut aussi enrichir le contexte via une mini-CMDB d'exemple :

```text
ProjetsEtudiantsHackathon2026/asset_inventory_sample.csv
```

Cette table ajoute, pour chaque actif :

- un identifiant d'actif ;
- un type d'actif ;
- une criticité ;
- une exposition ;
- un rôle métier ;
- les sources de logs actuellement disponibles ;
- une rétention indicative.

Puis le moteur génère une politique dans :

```text
ProjetsEtudiantsHackathon2026/generated_policies/
```

---

## Commandes d’exemple

### Générer une policy JSON pour T1059 sur serveur Windows critique

```bash
python3 scripts/log_value_engine.py \
  --threat T1059 \
  --asset-id win_srv_ops \
  --strategy balanced \
  --format json
```

### Générer une policy YAML pour Log4Shell / T1190 sur serveur web critique

```bash
python3 scripts/log_value_engine.py \
  --threat T1190 \
  --asset-id web_frontend \
  --strategy balanced \
  --format yaml
```

### Générer une policy minimale pour T1048 sur réseau

```bash
python3 scripts/log_value_engine.py \
  --threat T1048 \
  --asset-id network_dns \
  --strategy minimal \
  --format yaml
```

### Tester la première brique NLP sur MITRE ATT&CK Généralisation

```bash
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from log_value_engine import recommend_similar_mitre_techniques

zip_file = Path('SujetsHackathon2026/Sujet1/Généralisation/enterprise-attack.json.zip')
for rec in recommend_similar_mitre_techniques(
    'PowerShell command execution and suspicious parent process on Windows server',
    mitre_zip_file=zip_file,
    top_n=5,
):
    print(rec['ttp_id'], rec['name'], rec['similarity_score'], '-', rec['why'])
PY
```

---

## Ce que produit le moteur

Chaque sortie contient :

- la menace ciblée ;
- l’actif concerné ;
- la stratégie de collecte ;
- les sources de logs recommandées ;
- les champs à collecter ;
- une priorité : `indispensable`, `recommandé`, `optionnel` ;
- un `log_value_score` ;
- un coût estimé ;
- un bruit estimé ;
- une couverture de détection estimée ;
- une justification ;
- un angle mort si le log n’est pas collecté ;
- des exemples de détection : log brut, requête Splunk, règle Sigma.

---

## Logique de scoring

La logique est volontairement simple pour le MVP.

Le score dépend de :

1. **Valeur menace**
   - CVSS élevé ou tactique critique = plus de priorité.

2. **Criticité de l’actif**
   - un serveur critique vaut plus qu’un actif générique.

3. **Couverture de détection**
   - une source très pertinente pour la menace monte dans le ranking.

4. **Coût et bruit**
   - une source coûteuse ou très bruyante est pénalisée.

5. **Stratégie**
   - `minimal`, `balanced`, `high_assurance` modifient légèrement le niveau d’exigence.

La formule simplifiée est :

```text
score = menace × actif × couverture × stratégie / (coût × bruit)
```

Le score est ensuite ramené entre 0 et 10.

---

## Pourquoi cette brique est importante

Une solution basique ferait :

```text
TTP → log source → YAML
```

Notre moteur fait plutôt :

```text
TTP/CVE + actif + criticité + contrainte
→ logs candidats
→ score explicable
→ priorité
→ policy justifiée
→ angle mort si absent
```

C’est ce qui rend l’approche plus originale.

---

## Exemples générés

Les exemples déjà générés sont :

```text
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1059.json
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1059.yaml
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1190.json
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1190.yaml
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1048.json
ProjetsEtudiantsHackathon2026/generated_policies/policy_T1048.yaml
```

---

## Tests

Les tests sont dans :

```text
tests/test_log_value_engine.py
```

Commande :

```bash
python3 -m unittest tests/test_log_value_engine.py -v
```

Les tests vérifient que :

- le CSV fourni par le challenge est bien normalisé ;
- le scoring produit une priorité explicable ;
- une policy est bien générée pour une TTP ;
- les exports JSON et YAML fonctionnent ;
- le gros export `Généralisation/enterprise-attack.json.zip` est bien parsé ;
- la brique NLP recommande des techniques MITRE depuis un scénario texte libre.

---

## Limites actuelles

Ce MVP est volontairement simple.

Limites :

- les coûts et niveaux de bruit sont estimés à la main ;
- le moteur NLP actuel est une similarité texte légère, pas encore un modèle supervisé entraîné ;
- les sources MITRE ne suffisent pas seules à savoir quoi collecter dans un SI réel sans contexte asset/logs ;
- il ne récupère pas encore CVE ou CISA KEV automatiquement ;
- il n’y a pas encore d’interface utilisateur.

Ces limites sont normales pour cette étape.

---

## Prochaine étape logique

La suite la plus utile serait d’ajouter :

1. une sortie CLI dédiée pour le mode `--mitre-scenario` ;
2. un enrichissement CVE / CISA KEV ;
3. une table coût/bruit plus explicite par source de logs ;
4. une sortie HTML lisible pour démo ;
5. plus tard, un vrai modèle de ranking entraîné sur des exemples labellisés.
