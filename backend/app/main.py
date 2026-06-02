from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel
import re

# initialise ton API FastAPI et donne des métadonnées visibles dans la documentation automatique.
app = FastAPI(
    title="Cyber SOC Platform API",
    description="Mini plateforme SOC pour collecter et analyser des logs",
    version="0.1.0"
)


# crées une classe appelée LogInput. Elle hérite de BaseModel
# contenir trois champs de type str
# source: str --> indique d’où vient le log "firewall server endpoint ids nginx windows"
# log_type: str --> indique le type de log "info warning error alert authentication network"
# le contenu réel du log --> Exemple : Failed login attempt for user admin
class LogInput(BaseModel):
    source: str
    log_type: str
    message: str


# crée une liste vide
logs_storage = []
alerts_storage = []

# transformer les logs bruts en événements structurés.
def parse_linux_auth_log(message: str):
    """
    Parser simple pour les logs SSH Linux.
    Pour l'instant, il détecte seulement les échecs de connexion SSH.
    """

    # une expression régulière, aussi appelée regex
    # Le r devant la chaîne veut dire raw string. C’est pratique pour écrire des regex sans devoir doubler tous les \
    # ?P<username>\w+) veut dire : capture une partie du texte et appelle-la username
    # \w+ : veut dire : une ou plusieurs lettres, chiffres ou _.
    # re.compile ???
    FAILED_LOGIN_PATTERNS = [
        re.compile(
            r"Failed password for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Invalid password for user (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Authentication failed for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
        re.compile(
            r"Login failed user=(?P<username>\w+) src=(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        ),
    ]

    for pattern in FAILED_LOGIN_PATTERNS:
        match = pattern.search(message)

        if match:
            return {
                "category": "authentication",
                "action": "login_failed",
                "username": match.group("username"),
                "source_ip": match.group("source_ip"),
                "severity": "medium"
            }

    return {
        "category": "unknown",
        "action": "unknown",
        "username": None,
        "source_ip": None,
        "severity": "low"
    }


@app.get("/")
def home():
    return {
        "message": "Cyber SOC Platform API is running"
    }


def detect_brute_force():
    """
    Détection simple :
    si une IP a 5 échecs SSH ou plus, créer une alerte.
    """
    # dic (map)
    failed_login_count_by_ip = {}

    for log in logs_storage:
        parsed = log.get("parsed", {})

        if (
                parsed.get("category") == "authentication"
                and parsed.get("action") == "login_failed"
                and parsed.get("source_ip") is not None
        ):
            source_ip = parsed["source_ip"]
            # compter
            failed_login_count_by_ip[source_ip] = failed_login_count_by_ip.get(source_ip, 0) + 1

    for source_ip, count in failed_login_count_by_ip.items():
        if count >= 5:
            alert_already_exists = any(
                alert["source_ip"] == source_ip
                and alert["rule_id"] == "SSH_BRUTE_FORCE"
                and alert["status"] == "open"
                for alert in alerts_storage
            )

            if not alert_already_exists:
                alert = {
                    "id": len(alerts_storage) + 1,
                    "rule_id": "SSH_BRUTE_FORCE",
                    "title": "Possible SSH brute force attack",
                    "description": f"{count} failed SSH login attempts from {source_ip}",
                    "severity": "high",
                    "source_ip": source_ip,
                    "failed_attempts": count,
                    "status": "open",
                    "created_at": datetime.utcnow().isoformat()
                }

                alerts_storage.append(alert)


@app.post("/ingest/log")
def ingest_log(log: LogInput):
    parsed_data = {}

    if log.log_type == "linux_auth":
        parsed_data = parse_linux_auth_log(log.message)

    log_entry = {
        "id": len(logs_storage) + 1,
        "source": log.source,
        "log_type": log.log_type,
        "message": log.message,
        "parsed": parsed_data,
        "received_at": datetime.utcnow().isoformat()
    }

    logs_storage.append(log_entry)
    
    detect_brute_force()


    return {
        "status": "success",
        "message": "Log received and parsed and analyzed successfully",
        "data": log_entry
    }


@app.get("/logs")
def get_logs():
    return {
        "count": len(logs_storage),
        "logs": logs_storage
    }

@app.get("/alerts")
def get_alerts():
    return {
        "count": len(alerts_storage),
        "alerts": alerts_storage
    }