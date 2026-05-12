from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem

OUTPUT = Path('/home/snowy/HackathonAlbert2026/ProjetsEtudiantsHackathon2026/strategic_pitch_sujet1_fr.pdf')

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(
    name='TitleHack', parent=styles['Title'], fontName='Helvetica-Bold',
    fontSize=16, leading=18, textColor=colors.HexColor('#0f172a'), alignment=TA_LEFT, spaceAfter=4,
))
styles.add(ParagraphStyle(
    name='SubtitleHack', parent=styles['Heading2'], fontName='Helvetica-Bold',
    fontSize=11.5, leading=13.5, textColor=colors.HexColor('#1d4ed8'), spaceAfter=6, spaceBefore=2,
))
styles.add(ParagraphStyle(
    name='SectionHack', parent=styles['Heading3'], fontName='Helvetica-Bold',
    fontSize=10.5, leading=12.5, textColor=colors.HexColor('#111827'), spaceAfter=4, spaceBefore=6,
))
styles.add(ParagraphStyle(
    name='BodyHack', parent=styles['BodyText'], fontName='Helvetica',
    fontSize=9.2, leading=11.2, textColor=colors.HexColor('#1f2937'), spaceAfter=2,
))
styles.add(ParagraphStyle(
    name='ValueHack', parent=styles['BodyText'], fontName='Helvetica-Bold',
    fontSize=9.4, leading=11.4, textColor=colors.HexColor('#0f172a'),
    backColor=colors.HexColor('#eef4ff'), borderPadding=6, borderColor=colors.HexColor('#bfdbfe'), borderWidth=0.6,
    borderRadius=4, spaceBefore=6,
))

story = []
story.append(Paragraph('Deliverable 1 — Strategic pitch', styles['TitleHack']))
story.append(Paragraph('Sujet 1 — <i>Log as code</i> : génération automatisée de politiques de logs de sécurité', styles['SubtitleHack']))

story.append(Paragraph('A. Définition du périmètre', styles['SectionHack']))
story.append(Paragraph('<b>Problème ciblé</b>', styles['BodyHack']))
problem_items = [
    "Le problème n’est pas de manquer de logs, mais de manquer de <b>logs utiles</b>.",
    "Une collecte trop large crée du <b>bruit</b>, du <b>coût</b> et des alertes peu exploitables ; une collecte trop faible crée des <b>angles morts</b>.",
    "Le lien entre <b>menace connue</b> (MITRE ATT&CK, CVE, CVSS) et <b>politique concrète de journalisation</b> reste souvent manuel et difficile à maintenir.",
]
story.append(ListFlowable([ListItem(Paragraph(i, styles['BodyHack'])) for i in problem_items], bulletType='bullet', start='circle', leftIndent=12))
story.append(Paragraph('<b>Objectif</b>', styles['BodyHack']))
obj_items = [
    "Construire un <b>prototype d’aide à la décision</b> répondant à la question : <b>quels logs faut-il collecter en priorité pour détecter les menaces qui comptent vraiment ?</b>",
    "<b>Prioriser</b> les TTP et CVE critiques.",
    "<b>Associer</b> ces menaces aux sources de logs pertinentes.",
    "<b>Générer</b> une politique en <b>YAML/JSON</b> indiquant <b>quoi collecter, sur quels systèmes et pour quelle finalité de détection</b>.",
]
story.append(ListFlowable([ListItem(Paragraph(i, styles['BodyHack'])) for i in obj_items], bulletType='bullet', start='circle', leftIndent=12))

story.append(Paragraph('B. Pertinence pour la Marine nationale', styles['SectionHack']))
rel_items = [
    "La Marine nationale évolue dans un environnement où la <b>disponibilité</b>, la <b>résilience opérationnelle</b> et la <b>rapidité de détection</b> sont critiques.",
    "Elle doit superviser des environnements variés : <b>postes, serveurs, équipements réseau, services web et systèmes connectés</b>.",
    "Une approche <i>log as code</i> permet de <b>partir de la menace pour définir la journalisation</b>, et non l’inverse.",
    "Elle aide à <b>réduire le bruit</b>, <b>mieux couvrir</b> les comportements d’attaque prioritaires et <b>industrialiser</b> la politique de logs.",
]
story.append(ListFlowable([ListItem(Paragraph(i, styles['BodyHack'])) for i in rel_items], bulletType='bullet', start='circle', leftIndent=12))

story.append(Paragraph('C. Pourquoi c’est important', styles['SectionHack']))
roi_items = [
    "Passer d’une logique de journalisation “large mais peu hiérarchisée” à une logique <b>orientée menace, orientée risque et orientée usage</b>.",
    "Métriques visées : <b>couverture de détection</b>, <b>MTTD</b>, <b>volume de bruit</b>, <b>temps de mise à jour d’une politique de logs</b>.",
    "Le faire <b>maintenant</b> évite de continuer à stocker des données peu utiles tout en risquant de <b>manquer des signaux critiques</b>.",
    "La valeur du prototype est d’être <b>simple, explicable et transposable</b> dès un premier périmètre restreint.",
]
story.append(ListFlowable([ListItem(Paragraph(i, styles['BodyHack'])) for i in roi_items], bulletType='bullet', start='circle', leftIndent=12))

story.append(Spacer(1, 5))
story.append(Paragraph('Proposition de valeur — <b>Notre angle n’est pas de “faire parler des logs avec de l’IA”, mais d’utiliser la CTI pour décider, de façon plus pertinente et plus défendable, quels logs méritent réellement d’être collectés.</b>', styles['ValueHack']))

doc = SimpleDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=14*mm, rightMargin=14*mm, topMargin=12*mm, bottomMargin=12*mm)
doc.build(story)
print(OUTPUT)
