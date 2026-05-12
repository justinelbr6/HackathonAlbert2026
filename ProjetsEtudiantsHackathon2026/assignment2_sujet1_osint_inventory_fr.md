# Deliverable 2 — OSINT framework, inventaire des données et gaps
## Sujet 1 — *Log as code* : génération automatisée de politiques de logs de sécurité

## 1. Objectif de cette étape
À ce stade, l’objectif n’est pas encore de prétendre produire une politique de logs parfaite. L’enjeu est d’abord de démontrer une démarche crédible de **collecte, structuration et exploitation de données OSINT** pour préparer un moteur capable de répondre à la question centrale du sujet :

**quels logs faut-il collecter en priorité pour détecter les menaces qui comptent vraiment ?**

Cette étape sert donc à :
- identifier les sources ouvertes pertinentes ;
- inventorier les jeux de données réellement disponibles dans le repo ;
- évaluer leur qualité et leur utilité ;
- expliciter les manques qui empêcheront une généralisation naïve ;
- proposer des enrichissements de données qui peuvent clairement valoriser le projet.

---

## 2. OSINT framework retenu

### A. Sources CTI et vulnérabilités
Le socle informationnel du projet repose sur trois familles de données complémentaires.

**1. MITRE ATT&CK**  
Utilisé pour représenter les comportements d’attaque sous forme de TTP (tactiques et techniques). C’est la couche la plus utile pour relier une menace à des besoins de détection concrets.

**2. CVE / NVD / CVSS**  
Utilisés pour représenter les vulnérabilités exploitables, leur sévérité, leur contexte technique et leur criticité. Cette couche permet de prioriser les menaces à partir d’un signal plus opérationnel que le simple nom d’une technique.

**3. Exemples de logs et schémas de logs**  
Ils servent à faire le pont entre la menace théorique et la politique de collecte concrète. C’est la couche qui permet de répondre non pas seulement à “quelle menace existe ?”, mais à “dans quel log peut-on l’observer ?”.

### B. Logique de traitement
La chaîne de valeur visée est la suivante :

**CVE prioritaire -> TTP associée -> type de log pertinent -> champs utiles -> politique YAML/JSON**

Cette chaîne est cohérente avec les consignes du sujet, qui demandent d’aller vers :
- l’association TTP / CVE ;
- la normalisation des logs ;
- la priorisation des menaces ;
- la génération automatique de politiques de logs.

### C. Outils et stack de travail
Le repo oriente explicitement vers un stack de traitement simple et crédible :
- Python ;
- CSV / JSON ;
- pandas pour la normalisation tabulaire ;
- éventuellement `attackcti`, `pyattck` ou `stix2` pour industrialiser la récupération et la manipulation des données ATT&CK / STIX ;
- Jinja2 pour générer automatiquement les politiques YAML.

Autrement dit, le projet ne repose pas sur une boîte noire d’IA. Il repose d’abord sur un **pipeline de structuration de connaissance cyber**, potentiellement enrichi ensuite par du scoring, du NLP ou de la recommandation.

---

## 3. Inventaire concret des données présentes dans le repo

Les fichiers réellement disponibles pour le Sujet 1 se trouvent dans :
`SujetsHackathon2026/Sujet1/MiseEnJambe/`

### A. Données de menace et de connaissance cyber

#### 1. `Extrait_cve_data.JSON`
**Contenu**  
Extrait JSON de vulnérabilités CVE.

**Structure observée**  
Clé principale : `vulnerabilities`  
Nombre d’entrées observées : **5**

**Champs utiles observés**
- `cve_id`
- `description`
- `cvss_score`
- `cvss_vector`
- `published_date`
- `last_modified_date`
- `exploitability`
- `mitre_attack_techniques`
- `affected_software`
- `example_exploit`
- `patches`
- `references`

**Utilité**  
Très utile pour construire la couche de priorisation des vulnérabilités. Ce fichier porte déjà les éléments nécessaires pour un scoring simple : sévérité, lien vers ATT&CK, logiciels affectés, contexte d’exploitation.

#### 2. `cve_data_with_cvss_and_mitre.csv`
**Contenu**  
Version tabulaire compacte de CVE enrichies avec CVSS et liens ATT&CK.

**Volume observé**  
**5 lignes**

**Colonnes observées**
- `cve_id`
- `description`
- `cvss_score`
- `cvss_vector`
- `published_date`
- `mitre_attack_techniques`
- `mitre_attack_links`

**Utilité**  
Très bon point d’entrée pour un prototype. Le CSV est plus facile à manipuler qu’un JSON riche quand on veut faire du ranking ou du join avec une table TTP/logs.

#### 3. `Extrait_mitre_attck.JSON`
**Contenu**  
Extrait JSON de techniques ATT&CK.

**Observation qualité**  
Le fichier contient une structure riche et pertinente, mais il semble **mal formé** sur la fin : la lecture brute échoue sur une erreur de syntaxe JSON. Malgré cela, les premières lignes montrent des champs très utiles.

**Champs observés sur les objets `attack-pattern`**
- `type`
- `id`
- `name`
- `external_references`
- `x_mitre_attack.tactics`
- `x_mitre_attack.platforms`
- `x_mitre_attack.data_sources`
- `x_mitre_attack.defense_bypassed`
- `x_mitre_attack.impact_type`
- `x_mitre_attack.mitigations`
- `x_mitre_attack.example_procedure`
- `x_mitre_attack.detection.data_components`
- `x_mitre_attack.detection.example_query`

**Utilité**  
C’est probablement le fichier le plus important du corpus, car il contient déjà la logique qui nous intéresse pour relier **technique d’attaque** et **composants de détection**.

**Limite**  
Avant industrialisation, il faudra soit corriger ce fichier, soit le remplacer par une extraction propre depuis la source officielle MITRE STIX.

#### 4. `dictionnaire-cve-nvd.csv`
**Contenu**  
Dictionnaire de données pour les champs CVE / NVD.

**Volume observé**  
**13 lignes**

**Colonnes observées**
- `Champ`
- `Type`
- `Description`
- `Exemple`
- `Obligatoire`

**Utilité**  
Très utile pour documenter proprement le pipeline et justifier la sémantique des champs exploités.

#### 5. `dictionnaire-enterprise-attack (1).csv`
**Contenu**  
Dictionnaire de données des objets ATT&CK Enterprise.

**Volume observé**  
**10 lignes**

**Colonnes observées**
- `Type d'objet`
- `Champ`
- `Type`
- `Description`
- `Exemple`
- `Obligatoire`

**Utilité**  
Même rôle que le dictionnaire CVE : utile pour structurer proprement le modèle de données et rendre le pipeline explicable.

### B. Données de mapping déjà semi-exploitables

#### 6. `mapping_ttps_cve_logs.csv`
**Contenu**  
Fichier pivot le plus utile du prototype, car il fait déjà le lien entre :
- TTP MITRE ;
- CVE ;
- type de log ;
- source de log ;
- champs à observer ;
- exemples de requêtes ;
- exemples de règles Sigma.

**Volume observé**  
**5 lignes**

**Colonnes observées**
- `ttp_id`
- `ttp_name`
- `ttp_tactic`
- `cve_id`
- `cve_description`
- `cve_score`
- `log_type`
- `log_source`
- `log_fields`
- `example_log`
- `example_query_splunk`
- `example_rule_sigma`

**Exemples concrets présents**
- `T1059` -> logs Sysmon -> `CommandLine`, `ProcessName`, `ParentProcessName`
- `T1190` + `CVE-2021-44228` -> logs Apache Access -> `HttpRequest`, `UserAgent`, `Payload`
- `T1048` -> logs DNS -> exfiltration potentielle

**Utilité**  
C’est la meilleure base actuelle pour un MVP, parce qu’il contient déjà la graine du raisonnement attendu par le sujet :
**menace -> indicateur -> log -> requête de détection -> politique de collecte**

**Limite**  
Le volume est très faible. Ce fichier est excellent pour une démonstration, mais pas assez large pour représenter une vraie base de connaissances.

### C. Données de logs et schémas de logs

#### 7. `Sysmon.JSON`
**Champs observés**
- `EventID`
- `Computer`
- `ProcessName`
- `CommandLine`
- `ParentProcessName`
- `Timestamp`

**Utilité**  
Très utile pour les techniques orientées exécution, persistance ou défense évasive sur Windows.

#### 8. `Suricata.JSON`
**Champs observés**
- `timestamp`
- `event_type`
- `src_ip`
- `dest_ip`
- `alert`

**Utilité**  
Utile pour la couche réseau et pour montrer que la politique ne se limite pas à des logs hôte.

#### 9. `Apache.JSON`
**Contenu observé**  
Le fichier contient une ligne de log Apache réaliste, par exemple une requête avec tentative `${jndi:ldap://...}`.

**Observation qualité**  
Le fichier n’est pas un JSON structuré valide, malgré son extension `.JSON`. C’est en réalité davantage un **exemple brut de log Apache** qu’un objet JSON.

**Utilité**  
Très utile pour illustrer `T1190` / Log4Shell, mais nécessite une phase de parsing / normalisation.

#### 10. `sample_logs_windows_events.csv`
**Volume observé**  
**8 lignes**

**Colonnes observées**
- `timestamp`
- `event_id`
- `event_source`
- `computer`
- `user`
- `process_name`
- `command_line`
- `parent_process_name`
- `ip_source`
- `ip_destination`
- `port`
- `protocol`

**Utilité**  
Très bonne base pédagogique pour montrer la normalisation d’événements hétérogènes vers un schéma commun.

**Observation qualité**  
Le quoting CSV est imparfait sur certaines lignes ; un parseur robuste sera nécessaire.

#### 11. `sample_logs_linux_syslog.CSV.log`
**Contenu observé**  
Exemples de logs SSH, CRON, sudo, téléchargement de payload et persistance via crontab.

**Utilité**  
Très intéressant pour illustrer des techniques Linux de persistance, d’exécution et d’usage de shell.

#### 12. `sample_logs_network_traffic.csv.xlsx`
**Contenu observé**  
Le fichier contient un tableau réseau avec, dans sa première ligne logique, les champs suivants :
- `timestamp`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `protocol`
- `payload`
- `http_user_agent`
- `http_request`

**Volume observé**  
Environ **7 lignes utiles**

**Utilité**  
Permet de montrer la couche réseau, la résolution de patterns simples, et le lien avec les détections web / exfiltration / trafic anormal.

---

## 4. Lecture globale : ce que ces données permettent déjà
Ces données permettent déjà de construire un prototype cohérent en quatre briques.

### 1. Prioriser
À partir des CVE et du score CVSS, on peut filtrer les vulnérabilités les plus critiques.

### 2. Enrichir
À partir des liens CVE -> TTP, on peut rattacher les vulnérabilités à des comportements d’attaque ATT&CK.

### 3. Observer
À partir du mapping TTP/logs et des exemples de logs, on peut déterminer quelles sources de logs et quels champs de détection sont utiles.

### 4. Générer
À partir de là, on peut produire une politique structurée JSON/YAML de type :
- technique ciblée ;
- systèmes concernés ;
- types de logs à collecter ;
- champs obligatoires ;
- durée de rétention ;
- justification.

Autrement dit, le repo ne contient pas juste des exemples isolés. Il contient déjà les briques suffisantes pour un **MVP de moteur de recommandation de journalisation**.

---

## 5. Intelligence gaps, limites et risques

### A. Gap de volume et de couverture
Le principal gap est simple : le corpus est **petit**.

Quelques fichiers clés n’ont que **5 entrées**. Cela suffit pour démontrer la logique, mais pas pour entraîner ou valider sérieusement une généralisation.

### B. Gap de qualité et d’homogénéité
Plusieurs fichiers sont exploitables mais pas directement industrialisables.

Exemples :
- `Extrait_mitre_attck.JSON` semble mal formé ;
- `Apache.JSON` n’est pas un vrai JSON structuré ;
- certains CSV ont des guillemets et des séparateurs qui demandent un parsing robuste ;
- le fichier réseau est livré en `.xlsx`, alors que le reste est surtout en CSV / JSON.

Cela ne bloque pas un prototype, mais impose une couche de normalisation explicite.

### C. Gap de réalisme opérationnel
Les logs présents sont surtout des **exemples synthétiques ou démonstratifs**. Ils sont parfaits pour comprendre la logique, mais insuffisants pour affirmer qu’une politique générée fonctionnera telle quelle sur un SI réel.

### D. Gap de contexte métier Marine
Le repo ne fournit pas, à ce stade, une vraie description détaillée de l’environnement de la Marine :
- criticité par type d’actif ;
- volumétrie réelle des logs ;
- contraintes de stockage ;
- politique actuelle de rétention ;
- priorités défensives réelles.

Donc la politique générée devra être présentée comme une **policy priorisée générique et défendable**, pas comme une configuration prête à déployer.

### E. Gap de scoring métier
Le CVSS permet de prioriser la sévérité technique, mais pas à lui seul l’importance pour l’organisation. Il manque une vraie couche de scoring contextualisé du type :
- criticité de l’actif ;
- exposition internet ;
- sensibilité des données ;
- fréquence observée dans les logs ;
- coût de collecte / bruit attendu.

---

## 6. Données additionnelles qui pourraient clairement valoriser le projet
Le repo précise qu’aller chercher d’autres données peut être valorisé. C’est vrai, à condition qu’elles renforcent le raisonnement et pas juste le volume.

Voici les ajouts les plus intelligents.

### 1. Flux MITRE ATT&CK officiel à jour
**Pourquoi c’est utile**  
Permet de corriger le problème de qualité du fichier ATT&CK local et d’industrialiser la récupération.

**Valeur ajoutée**  
Vous montrez que la démarche n’est pas figée sur un extrait statique, mais déjà pensée pour une mise à jour régulière.

### 2. Flux CVE officiel quotidien (`cvelistV5` / CVE.org / NVD)
**Pourquoi c’est utile**  
Permet de sortir du mini échantillon de 5 CVE et de montrer une capacité de veille réelle.

**Valeur ajoutée**  
Très fort pour défendre un futur pipeline quotidien de priorisation.

### 3. Catalogues CISA KEV (Known Exploited Vulnerabilities)
**Pourquoi c’est utile**  
Ajoute une couche très forte de priorisation : une CVE critique n’est pas forcément exploitée activement ; une CVE présente dans le catalogue KEV l’est beaucoup plus probablement.

**Valeur ajoutée**  
Excellent pour justifier un ranking plus pertinent que le seul CVSS.

### 4. Sigma rule repository
**Pourquoi c’est utile**  
Le fichier `mapping_ttps_cve_logs.csv` contient déjà des exemples Sigma. Enrichir cela avec un corpus plus large de règles Sigma permettrait de relier plus finement :
- technique ;
- log source ;
- champs ;
- logique de détection.

**Valeur ajoutée**  
Très cohérent avec le sujet, car cela renforce le pont entre menace et détection concrète.

### 5. ATT&CK Data Sources / Data Components complets
**Pourquoi c’est utile**  
Le vrai levier du projet est moins “connaître une TTP” que “savoir quels composants de données sont nécessaires pour la détecter”.

**Valeur ajoutée**  
C’est probablement l’enrichissement le plus stratégique pour un moteur *log as code*.

### 6. Logs plus réalistes ou anonymisés
**Pourquoi c’est utile**  
Pour sortir du pur démonstrateur et tester la robustesse de la normalisation sur un corpus plus hétérogène.

**Exemples**
- jeux de logs Windows EVTX convertis ;
- logs Apache / Nginx plus volumineux ;
- journaux Linux auth / syslog ;
- PCAP ou extraits Zeek / Suricata déjà structurés.

**Valeur ajoutée**  
Très utile pour montrer que la politique générée n’est pas seulement correcte sur 4 exemples “parfaits”.

### 7. Données d’actifs / CMDB simplifiée
**Pourquoi c’est utile**  
Même un petit fichier listant des actifs par type (`AD`, `web`, `poste`, `bastion`, `serveur Linux`) changerait fortement la valeur du prototype.

**Valeur ajoutée**  
Cela permettrait de contextualiser la policy selon l’actif et pas seulement selon la menace. C’est très différenciant.

### 8. Référentiel de coût / volumétrie des logs
**Pourquoi c’est utile**  
C’est l’ajout qui permettrait d’aller vers l’angle le plus intelligent du sujet : **la priorisation de la journalisation sous contrainte**.

Même une approximation simple du type :
- coût faible / moyen / fort ;
- bruit faible / moyen / fort ;
- rétention courte / longue ;

serait déjà très utile.

**Valeur ajoutée**  
Très forte, car cela transforme un générateur naïf en outil d’arbitrage défendable.

---

## 7. Recommandation stratégique
Si nous voulons maximiser la valeur du projet, il ne faut pas seulement produire un générateur de policies. Il faut construire un prototype qui aide à décider **quels logs valent réellement la peine d’être collectés**.

La suite la plus intelligente consiste donc à viser un MVP capable de produire, pour une menace prioritaire :
- les logs **indispensables** ;
- les logs **recommandés** ;
- les champs clés ;
- une justification ;
- et idéalement une notion simple de coût / bruit / couverture.

C’est cette couche de priorisation qui peut rendre le projet plus marquant qu’un simple export YAML.

---

## 8. Conclusion
Le repo fournit déjà une base solide pour démarrer :
- des extraits CVE ;
- des extraits ATT&CK ;
- un mapping TTP/CVE/logs ;
- plusieurs exemples de logs hôte, web et réseau ;
- des dictionnaires de données utiles pour documenter proprement le pipeline.

Cette base est suffisante pour un **prototype défendable**.

En revanche, elle présente aussi des limites claires :
- volume faible ;
- hétérogénéité des formats ;
- qualité variable de certains fichiers ;
- manque de contexte métier réel ;
- absence de données explicites sur le coût et la criticité des actifs.

La meilleure manière de valoriser le projet consiste donc à assumer cette réalité :
**montrer un pipeline propre, explicable et priorisé, puis proposer des enrichissements de données ciblés qui renforcent directement la pertinence opérationnelle du moteur de recommandation de logs.**
