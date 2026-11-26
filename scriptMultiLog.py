#!/usr/bin/env python3

import os
import re
import json
import time
import signal
import smtplib
import threading
from collections import deque
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# CONFIGURATION & CHARGEMENT EXTERNE


CONFIG_PATH = BASE_DIR / "aiops_config.json"
DOSSIER_DATA = BASE_DIR / "aiops_data"
DOSSIER_INCIDENTS = DOSSIER_DATA / "incidents"
DOSSIER_RAPPORTS = DOSSIER_DATA / "rapports"

URL_OLLAMA = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
NOM_MODELE = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
TIMEOUT_OLLAMA = 300
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")

GLPI_URL = os.getenv("GLPI_URL", "http://localhost")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN")

EMAIL_EXPEDITEUR = os.getenv("EMAIL_EXPEDITEUR")
EMAIL_MOT_DE_PASSE = os.getenv("EMAIL_MOT_DE_PASSE")
EMAIL_DEFAUT_DESTINATAIRE = os.getenv("EMAIL_DEFAUT_DESTINATAIRE")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))

LIGNES_DE_CONTEXTE = 15
VERROU_TRAITEMENT = threading.Lock()


def charger_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Fichier de configuration introuvable : {CONFIG_PATH}")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


# PARSEURS MULTI-FORMATS (JAVA LOG4J2 / LOGBACK et PHP MONOLOG)


REGEX_LOG4J2 = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"\[(?P<thread>.*?)\]\s+"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s+-\s+(?P<message>.*)$"
)

REGEX_LOGBACK = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\.\d{3}(?:[+-]\d{2}:\d{2})?)\s+"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\d+\s+---\s+\[(?P<thread>.*?)\]\s+"
    r"(?P<logger>\S+)\s*:\s*(?P<message>.*)$"
)

REGEX_MONOLOG = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)\]\s+"
    r"(?P<logger>[\w\-]+\.(?P<niveau>DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|ALERT|EMERGENCY)):\s*"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)


def parser_ligne_log(ligne):
    for regex in (REGEX_LOG4J2, REGEX_LOGBACK, REGEX_MONOLOG):
        m = regex.match(ligne)
        if m:
            niveau = m.group("niveau").upper()
            if niveau == "WARNING":
                niveau = "WARN"
            return {
                "timestamp": m.group("timestamp"),
                "niveau": niveau,
                "logger": m.group("logger"),
                "message": m.group("message"),
            }
    return None


# AUTO-DECOUVERTE et TRIAGE DES FICHIERS LOGS


def decouvrir_fichiers_logs(racine_str, dossiers_ignores, mots_cles_ignores):
    racine = Path(racine_str)
    fichiers_trouves = {}
    ignores_dossiers = {d.strip().casefold() for d in dossiers_ignores}
    ignores_fichiers = [m.strip().casefold() for m in mots_cles_ignores]

    for dossier_app in racine.iterdir():
        if not dossier_app.is_dir():
            continue
        if dossier_app.name.strip().casefold() in ignores_dossiers or dossier_app.name.startswith("."):
            continue

        nom_app = dossier_app.name.strip()

        for root, dirs, files in os.walk(dossier_app):
            # Exclure les sous-dossiers ignorés ou cachés
            dirs[:] = [
                d for d in dirs
                if d.strip().casefold() not in ignores_dossiers and not d.startswith(".")
            ]

            for file in files:
                # 1. Garder uniquement les vrais fichiers .log (exclut .log.gz, .txt, etc.)
                if not file.lower().endswith(".log"):
                    continue

                # 2. Triage : exclure les rapports, preuves, logs d'installation ou access logs
                nom_lower = file.casefold()
                if any(mot in nom_lower for mot in ignores_fichiers):
                    continue

                # 3. Si le fichier contient une date (ex: dev-2026-11-17.log), ne garder que celui du jour
                match_date = re.search(r"(\d{4}-\d{2}-\d{2})", file)
                if match_date:
                    date_aujourd_hui = datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d")
                    if match_date.group(1) != date_aujourd_hui:
                        continue

                chemin_complet = Path(root) / file
                fichiers_trouves[str(chemin_complet)] = {
                    "chemin": chemin_complet,
                    "application": nom_app,
                }

    return fichiers_trouves



# CLIENT GLPI


def glpi_headers(session_token=None, content_type=True):
    headers = {"App-Token": GLPI_APP_TOKEN}
    if session_token:
        headers["Session-Token"] = session_token
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def glpi_init_session():
    resp = requests.get(
        f"{GLPI_URL}/apirest.php/initSession",
        headers={
            "App-Token": GLPI_APP_TOKEN,
            "Authorization": f"user_token {GLPI_USER_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json().get("session_token")
    if not token:
        raise RuntimeError("Impossible d'obtenir un session_token GLPI.")
    return token


def glpi_get_all(session_token, itemtype):
    resultats, debut, taille = [], 0, 100
    while True:
        fin = debut + taille - 1
        resp = requests.get(
            f"{GLPI_URL}/apirest.php/{itemtype}/",
            headers=glpi_headers(session_token),
            params={"range": f"{debut}-{fin}"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            break
        resultats.extend(data)
        if len(data) < taille:
            break
        debut += taille
    return resultats


def trouver_id_par_nom(elements, nom):
    cible = re.sub(r"\s+", " ", str(nom).strip().casefold())
    for el in elements:
        if re.sub(r"\s+", " ", str(el.get("name", "")).strip().casefold()) == cible:
            return int(el["id"])
    return None


def resoudre_routage_glpi(session_token, routage_config):
    groupes = glpi_get_all(session_token, "Group")
    utilisateurs = glpi_get_all(session_token, "User")
    categories = glpi_get_all(session_token, "ITILCategory")

    resolution = {}
    for domaine, cfg in routage_config.items():
        u_ids = []
        for u_nom in cfg.get("utilisateurs_glpi", []):
            uid = trouver_id_par_nom(utilisateurs, u_nom)
            if uid is not None:
                u_ids.append(uid)

        resolution[domaine] = {
            "groupe_id": trouver_id_par_nom(groupes, cfg.get("groupe_glpi", "")),
            "user_ids": u_ids,
            "categorie_id": trouver_id_par_nom(categories, cfg.get("categorie_glpi", "")),
            "emails": cfg.get("emails_equipe", []),
        }
    return resolution



# ANALYSE IA OLLAMA (PROMPT SRE POLYGLOTTE GENERALISTE)


SECTIONS = ["DESCRIPTION", "FONCTIONNEMENT", "CAUSE", "INDICES", "GRAVITE", "DOMAINE", "ACTION"]

GRAVITE_CANONIQUE = {
    "critique": "Critique", "critical": "Critique",
    "élevé": "Élevé", "eleve": "Élevé", "high": "Élevé",
    "moyen": "Moyen", "medium": "Moyen",
    "faible": "Faible", "low": "Faible",
}


def construire_prompt_sre(app_name, entree):
    return f"""
Tu es un ingénieur SRE (Site Reliability Engineering) senior polyglotte (Java/Spring Boot, PHP/Laravel/Symfony, MySQL, Linux).
Tu analyses un incident réel détecté sur l'application : {app_name}.

RÈGLE ABSOLUE :
Base chaque affirmation uniquement sur les faits présents dans le log fourni.
N'invente aucune classe, fichier ou configuration absente du log. Si une cause ne peut pas être confirmée, écris : "Non confirmable avec ce log seul".

FORMAT DE RÉPONSE STRICT (texte brut sans Markdown) :

DESCRIPTION:
Résumé clair de l'incident en 1 à 2 phrases.

FONCTIONNEMENT:
Impact sur la disponibilité de l'application {app_name}.

CAUSE:
Cause technique la plus probable déduite de l'exception ou du message.

INDICES:
Éléments clés exacts extraits du log (codes d'erreur, exceptions, fichiers).

GRAVITE:
Un seul mot parmi : Critique / Élevé / Moyen / Faible
Suivi d'une phrase de justification.

DOMAINE:
Un seul mot parmi : BASE_DE_DONNEES, SECURITE, PRODUCTION, APPLICATION, RESEAU, AUTRE

ACTION:
Action corrective concrète et immédiate pour l'équipe technique.

--- CONTEXTE DE L'INCIDENT ---
Application : {app_name}
Fichier log : {entree['fichier']} (ligne {entree['numero_ligne']})
Niveau      : {entree['niveau']}
Composant   : {entree['logger']}
Message     : {entree['message']}
Trace / Détails :
{entree['details'][:2500] if entree['details'] else "Aucun détail supplémentaire."}
"""


def analyser_avec_ollama(app_name, entree):
    prompt = construire_prompt_sre(app_name, entree)
    try:
        resp = requests.post(
            URL_OLLAMA,
            json={"model": NOM_MODELE, "prompt": prompt, "stream": False},
            timeout=TIMEOUT_OLLAMA,
        )
        resp.raise_for_status()
        texte = resp.json().get("response", "")
        texte = re.sub(r"\*\*(.*?)\*\*", r"\1", texte)
        texte = re.sub(r"^#+\s*", "", texte, flags=re.MULTILINE).strip()

        motif = re.compile(r"^\s*(" + "|".join(SECTIONS) + r")\s*:\s*$", re.IGNORECASE | re.MULTILINE)
        matches = list(motif.finditer(texte))
        sections = {k: "" for k in SECTIONS}

        if not matches:
            sections["DESCRIPTION"] = texte
        else:
            for i, m in enumerate(matches):
                cle = m.group(1).upper()
                debut = m.end()
                fin = matches[i + 1].start() if i + 1 < len(matches) else len(texte)
                sections[cle] = texte[debut:fin].strip()

        grav_raw = sections.get("GRAVITE", "").casefold()
        gravite = "Moyen"
        for k, v in GRAVITE_CANONIQUE.items():
            if k in grav_raw:
                gravite = v
                break
        if entree["niveau"] in ("FATAL", "CRITICAL", "EMERGENCY"):
            gravite = "Critique"
        sections["GRAVITE"] = gravite

        dom_raw = sections.get("DOMAINE", "").upper()
        domaine = "APPLICATION"
        for d in ("BASE_DE_DONNEES", "SECURITE", "PRODUCTION", "APPLICATION", "RESEAU", "AUTRE"):
            if d in dom_raw:
                domaine = d
                break
        sections["DOMAINE"] = domaine

        return sections
    except Exception as exc:
        return {
            "DESCRIPTION": f"[Erreur analyse Ollama : {exc}]",
            "FONCTIONNEMENT": "Indéterminé",
            "CAUSE": "Service Ollama injoignable ou timeout",
            "INDICES": entree["message"],
            "GRAVITE": "Élevé" if entree["niveau"] in ("ERROR", "FATAL", "CRITICAL") else "Moyen",
            "DOMAINE": "APPLICATION",
            "ACTION": "Vérifier le service Ollama et consulter la preuve jointe.",
        }



# PREUVE, TICKET GLPI ET EMAIL


def creer_fichier_preuve(app_name, entree):
    DOSSIER_INCIDENTS.mkdir(parents=True, exist_ok=True)
    horodatage = datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d_%H-%M-%S")
    safe_app = re.sub(r"[^a-zA-Z0-9_-]", "_", app_name)
    chemin = DOSSIER_INCIDENTS / f"incident_{safe_app}_{horodatage}.log"

    with open(chemin, "w", encoding="utf-8") as f:
        f.write(f"Application : {app_name}\n")
        f.write(f"Fichier     : {entree['fichier']}\n")
        f.write(f"Ligne       : {entree['numero_ligne']}\n")
        f.write(f"Timestamp   : {entree['timestamp']}\n")
        f.write(f"Niveau      : {entree['niveau']}\n")
        f.write("-" * 60 + "\n")
        if entree["contexte_avant"]:
            f.write("".join(entree["contexte_avant"]) + "\n")
        f.write(entree["ligne_brute"] + "\n")
        if entree["details"]:
            f.write(entree["details"] + "\n")

    return chemin


def traiter_incident_global(app_name, entree, glpi_session, routage_glpi):
    with VERROU_TRAITEMENT:
        print(f"\n[{app_name}] Alerte {entree['niveau']} détectée (ligne {entree['numero_ligne']}) : {entree['message'][:100]}")

        sections = analyser_avec_ollama(app_name, entree)
        gravite = sections["GRAVITE"]
        domaine = sections["DOMAINE"]
        cible_routage = routage_glpi.get(domaine, routage_glpi.get("AUTRE", {}))

        chemin_preuve = creer_fichier_preuve(app_name, entree)

        ticket_id = None
        urgence = {"Critique": 5, "Élevé": 4, "Moyen": 3, "Faible": 2}.get(gravite, 3)
        titre_ticket = f"[AIOps][{app_name}][{domaine}][{entree['niveau']}] {gravite}"
        corps_ticket = (
            f"INCIDENT MULTI-LOGS DÉTECTÉ SUR : {app_name}\n"
            f"Fichier : {entree['fichier']} (ligne {entree['numero_ligne']})\n"
            f"Domaine : {domaine} | Gravité : {gravite}\n\n"
            f"DESCRIPTION :\n{sections.get('DESCRIPTION')}\n\n"
            f"CAUSE PROBABLE :\n{sections.get('CAUSE')}\n\n"
            f"ACTION RECOMMANDÉE :\n{sections.get('ACTION')}\n\n"
            f"EXTRAIT LOG :\n{entree['ligne_brute']}"
        )

        payload_ticket = {
            "input": {
                "name": titre_ticket,
                "content": corps_ticket,
                "type": 1,
                "urgency": urgence,
                "impact": urgence,
            }
        }
        if cible_routage.get("categorie_id"):
            payload_ticket["input"]["itilcategories_id"] = cible_routage["categorie_id"]

        try:
            r_tick = requests.post(
                f"{GLPI_URL}/apirest.php/Ticket/",
                headers=glpi_headers(glpi_session),
                json=payload_ticket,
                timeout=15,
            )
            r_tick.raise_for_status()
            ticket_id = int(r_tick.json()["id"])
            print(f"  -> Ticket GLPI #{ticket_id} créé ({domaine} / {gravite})")

            manifest = {"input": {"name": chemin_preuve.name, "_filename": [chemin_preuve.name]}}
            with open(chemin_preuve, "rb") as f_bin:
                r_doc = requests.post(
                    f"{GLPI_URL}/apirest.php/Document/",
                    headers={"Session-Token": glpi_session, "App-Token": GLPI_APP_TOKEN},
                    files={
                        "uploadManifest": (None, json.dumps(manifest), "application/json"),
                        "filename[0]": (chemin_preuve.name, f_bin, "text/plain"),
                    },
                    timeout=20,
                )
                r_doc.raise_for_status()
                doc_id = int(r_doc.json()["id"])
                requests.post(
                    f"{GLPI_URL}/apirest.php/Document_Item/",
                    headers=glpi_headers(glpi_session),
                    json={"input": {"documents_id": doc_id, "itemtype": "Ticket", "items_id": ticket_id}},
                    timeout=10,
                )

            if cible_routage.get("groupe_id"):
                requests.post(
                    f"{GLPI_URL}/apirest.php/Group_Ticket/",
                    headers=glpi_headers(glpi_session),
                    json={"input": {"tickets_id": ticket_id, "groups_id": cible_routage["groupe_id"], "type": 2}},
                    timeout=10,
                )
            for uid in cible_routage.get("user_ids", []):
                requests.post(
                    f"{GLPI_URL}/apirest.php/Ticket_User/",
                    headers=glpi_headers(glpi_session),
                    json={"input": {"tickets_id": ticket_id, "users_id": uid, "type": 2}},
                    timeout=10,
                )
        except Exception as exc:
            print(f"  -> Erreur GLPI : {exc}")

        destinataires = [e for e in cible_routage.get("emails", []) if e and "exemple.com" not in e]
        if not destinataires and EMAIL_DEFAUT_DESTINATAIRE:
            destinataires = [EMAIL_DEFAUT_DESTINATAIRE]

        if destinataires and EMAIL_EXPEDITEUR and EMAIL_MOT_DE_PASSE:
            try:
                msg = EmailMessage()
                msg["Subject"] = f"AIOps [{app_name}] {gravite} - Ticket GLPI #{ticket_id or 'N/A'}"
                msg["From"] = EMAIL_EXPEDITEUR
                msg["To"] = ", ".join(destinataires)
                msg.set_content(corps_ticket)
                with open(chemin_preuve, "rb") as f_att:
                    msg.add_attachment(f_att.read(), maintype="text", subtype="plain", filename=chemin_preuve.name)
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.login(EMAIL_EXPEDITEUR, EMAIL_MOT_DE_PASSE)
                    smtp.send_message(msg)
                print(f"  -> Email envoyé à {', '.join(destinataires)}")
            except Exception as exc:
                print(f"  -> Erreur Email : {exc}")

        DOSSIER_RAPPORTS.mkdir(parents=True, exist_ok=True)
        date_jour = datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d")
        rapport_file = DOSSIER_RAPPORTS / f"rapport_multilog_{date_jour}.jsonl"
        with open(rapport_file, "a", encoding="utf-8") as f_rep:
            f_rep.write(json.dumps({
                "timestamp_analyse": datetime.now(FUSEAU_LOCAL).isoformat(),
                "application": app_name,
                "fichier_log": entree["fichier"],
                "niveau": entree["niveau"],
                "gravite": gravite,
                "domaine": domaine,
                "ticket_glpi": ticket_id,
                "message": entree["message"],
                "analyse": sections,
            }, ensure_ascii=False) + "\n")



# THREAD DE SURVEILLANCE PAR FICHIER DE LOG


def surveiller_fichier(chemin_log, app_name, niveaux_critiques, glpi_session, routage_glpi, stop_event):
    print(f"[+] Surveillance active : {app_name} -> {chemin_log}")
    contexte = deque(maxlen=LIGNES_DE_CONTEXTE)

    with open(chemin_log, encoding="utf-8", errors="replace") as f:
        num_ligne = sum(1 for _ in f)
        entree_courante = None
        cycles_vides = 0

        while not stop_event.is_set():
            ligne = f.readline()
            if not ligne:
                cycles_vides += 1
                if entree_courante and cycles_vides >= 3:
                    if entree_courante["niveau"] in niveaux_critiques:
                        traiter_incident_global(app_name, entree_courante, glpi_session, routage_glpi)
                    entree_courante = None
                    cycles_vides = 0
                time.sleep(0.5)
                continue

            cycles_vides = 0
            num_ligne += 1
            ligne_clean = ligne.rstrip("\n")
            parsed = parser_ligne_log(ligne_clean)

            if parsed:
                if entree_courante and entree_courante["niveau"] in niveaux_critiques:
                    traiter_incident_global(app_name, entree_courante, glpi_session, routage_glpi)

                entree_courante = {
                    "fichier": str(chemin_log),
                    "timestamp": parsed["timestamp"],
                    "niveau": parsed["niveau"],
                    "logger": parsed["logger"],
                    "message": parsed["message"],
                    "details": "",
                    "numero_ligne": num_ligne,
                    "contexte_avant": list(contexte),
                    "ligne_brute": ligne_clean,
                }
            elif entree_courante:
                entree_courante["details"] += ligne_clean + "\n"

            contexte.append(ligne)



# BOUCLE PRINCIPALE D'ORCHESTRATION ET AUTO-DECOUVERTE


def main():
    config = charger_config()
    niveaux_critiques = set(config.get("niveaux_critiques", ["WARN", "ERROR", "FATAL"]))

    print("=== DÉMARRAGE DU COLLECTEUR AIOPS MULTI-APPLICATIONS ===")
    glpi_session = glpi_init_session()
    routage_glpi = resoudre_routage_glpi(glpi_session, config.get("routage_domaines", {}))
    print("Connexion GLPI et tables de routage chargées.\n")

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda s, f: stop_event.set())

    threads_actifs = {}

    while not stop_event.is_set():
        fichiers = decouvrir_fichiers_logs(
            config["dossier_scan_racine"],
            config.get("dossiers_ignores", []),
            config.get("mots_cles_fichiers_ignores", []),
        )
        for chemin_str, info in fichiers.items():
            if chemin_str not in threads_actifs or not threads_actifs[chemin_str].is_alive():
                t = threading.Thread(
                    target=surveiller_fichier,
                    args=(info["chemin"], info["application"], niveaux_critiques, glpi_session, routage_glpi, stop_event),
                    daemon=True,
                )
                t.start()
                threads_actifs[chemin_str] = t

        time.sleep(5)

    print("\nArrêt propre du collecteur Multi-Logs.")


if __name__ == "__main__":
    main()