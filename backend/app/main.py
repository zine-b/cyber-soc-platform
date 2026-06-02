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


# transformer les logs bruts en événements structurés.
#
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

    return {
        "status": "success",
        "message": "Log received successfully",
        "data": log_entry
    }


@app.get("/logs")
def get_logs():
    return {
        "count": len(logs_storage),
        "logs": logs_storage
    }
