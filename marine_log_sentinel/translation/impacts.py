"""Map MITRE technique identifiers to French operational impact lines."""

from __future__ import annotations

from marine_log_sentinel.ml.models import TtpHit

# Technique-specific bullets (French). Keys may be exact STIX-style IDs used by our tagger.
_IMPACT_BY_ID: dict[str, tuple[str, ...]] = {
    "T1190": (
        "Tentative ou réussite d'exploitation d'une application exposée (web, VPN, messagerie…).",
        "Risque élevé de prise de contrôle du service ou du système qui l'héberge.",
        "Impact possible sur la disponibilité du SI et la confidentialité des données traitées par l'application.",
    ),
    "T1059": (
        "Exécution de commandes ou de scripts via un interpréteur (shell, PowerShell, etc.).",
        "Souvent utilisée après intrusion pour automatiser des actions malveillantes.",
        "Peut conduire à un mouvement latéral ou à l'exfiltration de données.",
    ),
    "T1059.001": (
        "Usage de PowerShell ou équivalent pour exécuter du code — vecteur fréquent d'attaque.",
        "Peut permettre le téléchargement d'outils et la consolidation de l'accès.",
    ),
    "T1105": (
        "Téléchargement d'un fichier ou d'un outil depuis un système distant.",
        "Étape typique avant l'exécution de malware ou d'outils d'administration détournés.",
    ),
    "T1078": (
        "Usage ou abus de comptes légitimes (locaux ou domaine).",
        "Peut masquer une activité malveillante derrière des identités autorisées.",
    ),
    "T1036": (
        "Tentative de dissimuler un programme ou une activité malveillante (nom usurpé, chemin trompeur…).",
        "Complique la détection par les équipes et les antivirus.",
    ),
    "T1036.009": (
        "Masquage potentiel du trafic ou du comportement réseau pour éviter l'analyse.",
    ),
    "T1548": (
        "Tentative d'élévation de privilèges pour obtenir des droits administrateur.",
        "Renforce la capacité de l'adversaire à modifier la configuration ou persister.",
    ),
    "T1548.003": (
        "Élévation de privilèges via mécanisme système — risque de contrôle élargi sur la machine.",
    ),
    "T1596": (
        "Collecte d'informations via les services réseau (DNS, WHOIS…).",
        "Souvent précurseur d'une phase d'intrusion plus destructive.",
    ),
}


def _ttp_candidates(ttp: TtpHit | None) -> list[str]:
    if ttp is None:
        return []
    out = [ttp.technique_id]
    # Parent fallback for sub-techniques Txxxx.yyy -> Txxxx
    tid = ttp.technique_id
    if "." in tid:
        base = tid.split(".", 1)[0]
        if base not in out:
            out.append(base)
    if ttp.parent_external_id and ttp.parent_external_id not in out:
        out.append(ttp.parent_external_id)
    return out


def operational_impacts_fr(ttp: TtpHit | None) -> tuple[str, ...]:
    """Return 2–4 French bullets describing operational risk."""

    if ttp is None:
        return (
            "Activité inhabituelle détectée sans rattachement clair à une technique ATT&CK précise.",
            "Il convient de corréler avec d'autres journaux et avec le contexte réseau.",
        )

    for cand in _ttp_candidates(ttp):
        hits = _IMPACT_BY_ID.get(cand)
        if hits:
            return hits

    name = ttp.technique_name or cand
    return (
        f"Comportement associé à la technique MITRE « {name} » ({ttp.technique_id}).",
        "Évaluer l'impact selon le rôle du système dans la chaîne opérationnelle (navigation, armement, administration…).",
        "Prioriser l'isolation réseau contrôlée et la préservation des preuves pour analyse SOC.",
    )


def headline_fr(ttp: TtpHit | None, severity_band: str) -> str:
    """Short headline for dashboards."""

    band_fr = {
        "CRITICAL": "Priorité maximale",
        "HIGH": "Priorité élevée",
        "MEDIUM": "À traiter sous surveillance",
        "LOW": "Veille",
    }.get(severity_band, severity_band)

    if ttp:
        return f"{band_fr} — suspicion « {ttp.technique_name} » ({ttp.technique_id})"
    return f"{band_fr} — activité anormale sans technique dominante"


def niveau_operationnel_fr(severity_band: str) -> str:
    return {
        "CRITICAL": "Critique — intervention immédiate recommandée",
        "HIGH": "Élevé — traitement prioritaire sous quelques heures",
        "MEDIUM": "Modéré — planifier analyse et corrélations",
        "LOW": "Faible — surveillance continue",
    }.get(severity_band, severity_band)


def summarize_for_command_fr(
    *,
    severity_band: str,
    ttp: TtpHit | None,
    cve_labels: list[str],
    kev: bool,
    asset_line: str | None,
) -> str:
    """One paragraph for non-specialists."""

    parts: list[str] = []
    parts.append(niveau_operationnel_fr(severity_band) + ".")

    if ttp:
        parts.append(
            f"L'analyse automatique rattache l'événement à la technique {ttp.technique_id} "
            f"({ttp.technique_name}), compatible avec une tactique adversaire répertoriée."
        )
    if cve_labels:
        cves = ", ".join(cve_labels[:3])
        parts.append(f"Vulnérabilités citées dans le référentiel : {cves}.")
    if kev:
        parts.append(
            "Au moins une de ces vulnérabilités figure au catalogue KEV de la CISA "
            "(exploitation active connue) : traiter le correctif comme priorité absolue."
        )
    if asset_line:
        parts.append(asset_line)

    if not ttp and not cve_labels:
        parts.append(
            "Le score repose surtout sur une anomalie statistique ; une validation humaine reste nécessaire."
        )

    return " ".join(parts)


def mitigation_to_action_fr(name_en: str, mitigation_id: str) -> str:
    """Turn English ATT&CK mitigation titles into actionable French lines."""

    key = name_en.strip().lower()
    cookbook: dict[str, str] = {
        "patch": "Appliquer les correctifs de sécurité validés par la chaîne de mise à jour du navire.",
        "restrict web-based content": "Restreindre ou filtrer l'exposition des applications web et les téléchargements non maîtrisés.",
        "execution prevention": "Renforcer les politiques d'exécution (liste blanche, durcissement des postes/serveurs).",
        "behavior prevention on endpoint": "Vérifier que les capacités anti-exploit et contrôle de comportement sont actives à bord.",
        "disable or remove feature": "Désactiver ou retirer la fonctionnalité non indispensable ayant permis l'exploitation.",
        "network segmentation": "Segmenter le réseau pour limiter la propagation en cas de compromission.",
        "privileged account management": "Réviser les comptes privilégiés et appliquer le moindre privilège.",
        "password policies": "Durcir la politique des mots de passe et privilégier l'authentification forte.",
        "user training": "Sensibiliser les équipes aux vecteurs d'ingénierie sociale.",
        "multi-factor authentication": "Étendre l'authentification multi-facteurs aux accès sensibles.",
    }
    for needle, sentence in cookbook.items():
        if needle in key:
            return f"{sentence} (réf. MITRE {mitigation_id} — {name_en})."

    return f"Mettre en œuvre la mitigation MITRE {mitigation_id} : « {name_en} »."
