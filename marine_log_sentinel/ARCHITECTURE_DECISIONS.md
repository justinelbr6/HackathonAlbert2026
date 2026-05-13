# Architecture Decision Records — Marine Log Sentinel

Décisions techniques structurantes du projet, conservées pour traçabilité
d'audit. Chaque entrée suit le format ADR allégé : contexte, décision,
conséquences.

---

## ADR-001 — Exclusion délibérée de `pyattck`

**Date** : 2026-05-12  
**Statut** : Accepté

### Contexte
Le sujet impose une famille de bibliothèques d'accès au framework MITRE
ATT&CK : `attackcti`, `pyattck`, `stix2`, et un client TAXII de MITRE.
Lors de l'installation, deux problèmes apparaissent :

1. **Incompatibilité Pydantic**. `pyattck>=7.1` tire `pyattck-data` qui
   épingle `pydantic<2.0`. Notre socle utilise pydantic v2 pour la
   validation du schéma de log unifié.
2. **Surface réseau non maîtrisée**. `pyattck-data` tire `googletrans` et
   `bs4`, parce que `pyattck` réalise un scraping opportuniste de
   Wikipedia / Google Translate pour enrichir certaines entités. Ce
   comportement n'est pas compatible avec la posture *air-gap* de l'outil
   (variable `MLS_AIR_GAP=1`) et introduit un risque non auditable dans
   un contexte Marine.

### Décision
On retire `pyattck` de la liste des dépendances installées. Le besoin
fonctionnel (récupération des techniques, tactiques, relations,
sous-techniques, data sources, data components, mitigations) est couvert
en intégralité par la combinaison `attackcti` + `stix2` + `taxii2-client`,
qui sont les briques d'accès TAXII officielles à MITRE ATT&CK.

### Conséquences
- Posture *air-gap* préservée : aucun composant ne tente d'appeler
  Wikipedia, Google Translate ou un site tiers non MITRE.
- Pydantic v2 conservé pour la couche de validation de logs.
- Le code de la couche `threat_intel/` (Étape 2) consommera directement
  les objets STIX 2.x via `attackcti` / `taxii2-client` plutôt que les
  abstractions de plus haut niveau de `pyattck`.
- Argument défendable face au jury : suppression volontaire d'une surface
  d'attaque non maîtrisée plutôt que prolifération de dépendances.
