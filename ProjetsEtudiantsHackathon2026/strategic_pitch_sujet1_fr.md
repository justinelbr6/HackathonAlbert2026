# Deliverable 1 — Strategic pitch
## Sujet 1 — *Log as code* : génération automatisée de politiques de logs de sécurité

### A. Définition du périmètre
**Problème ciblé**
- Aujourd’hui, le problème n’est pas de manquer de logs, mais de manquer de **logs utiles**.
- Les organisations collectent souvent trop de données peu exploitables, tout en laissant des **angles morts** sur les événements réellement critiques.
- Le lien entre **la menace** (*MITRE ATT&CK, CVE, CVSS*) et **la politique concrète de journalisation** reste souvent manuel, diffus et difficile à maintenir.

**Objectif**
- Concevoir un **prototype d’aide à la décision** qui répond à une question simple : **quels logs faut-il collecter en priorité pour détecter les menaces qui comptent vraiment ?**
- Plus précisément, le prototype doit permettre de :
  - **prioriser** les TTP et CVE critiques ;
  - **associer** ces menaces aux sources de logs pertinentes ;
  - **générer** une politique lisible en **YAML/JSON** indiquant **quoi collecter, sur quels systèmes, et pour quelle finalité de détection**.

### B. Pertinence pour la Marine nationale
**Pourquoi ce sujet est directement pertinent**
- La Marine nationale évolue dans un environnement où la **disponibilité des systèmes**, la **résilience opérationnelle** et la **rapidité de détection** sont critiques.
- Elle doit superviser des environnements variés : **postes, serveurs, équipements réseau, services web et systèmes connectés**, avec des contraintes fortes de priorisation et de charge analytique.
- Dans ce contexte, une approche *log as code* apporte une logique utile : **partir de la menace pour définir la journalisation**, et non l’inverse.

**Ce que cela apporte concrètement**
- **Réduire le bruit** dans la collecte et dans les alertes.
- **Mieux couvrir** les comportements d’attaque réellement prioritaires.
- **Aligner** la veille menace, la détection et la configuration de la journalisation.
- **Industrialiser** la politique de logs via un format structuré, explicable et automatisable.

### C. Pourquoi c’est important
**Le “so what ?”**
- Si ce prototype fonctionne, la Marine nationale gagne un moyen de passer d’une logique de journalisation “large mais peu hiérarchisée” à une logique **orientée menace, orientée risque et orientée usage**.
- Les métriques directement concernées sont :
  - **couverture de détection** des TTP prioritaires ;
  - **temps moyen d’identification** d’un incident (*MTTD*) ;
  - **volume de bruit** dans les événements remontés ;
  - **temps nécessaire** pour définir ou mettre à jour une politique de logs.

**Pourquoi maintenant ?**
- Les menaces évoluent plus vite que les politiques de journalisation.
- Attendre six mois, c’est continuer à stocker des données peu utiles tout en risquant de **manquer des signaux réellement critiques**.
- Commencer maintenant permet de poser une **base simple, explicable et transposable**, immédiatement utile sur un périmètre restreint, puis extensible à des environnements plus réalistes.

### Proposition de valeur
**Notre angle n’est pas de “faire parler des logs avec de l’IA”, mais d’utiliser la CTI pour décider, de façon plus pertinente et plus défendable, quels logs méritent réellement d’être collectés.**
