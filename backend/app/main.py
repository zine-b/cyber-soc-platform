from datetime import datetime, timedelta
from fastapi import FastAPI
from pydantic import BaseModel
import re
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker

# initialise ton API FastAPI et donne des métadonnées visibles dans la documentation automatique.
app = FastAPI(
    title="Cyber SOC Platform API",
    description="Mini plateforme SOC pour collecter et analyser des logs",
    version="0.1.0"
)

# -------------------------
# Database configuration
# -------------------------
DATABASE_URL = "sqlite:///./cyber_soc.db"

# l’objet qui gère la connexion entre app Python et la base de données
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Une session SQLAlchemy sert à parler avec la base de données : ajouter, lire, modifier, supprimer des données.
SessionLocal = sessionmaker(
    # les changements ne sont pas validés automatiquement --> db.commit()
    # synchronise pas automatiquement les changements avec la base avant certaines requêtes
    autocommit=False,
    autoflush=False,
    bind=engine
)

# crée la classe de base pour définir tes tables.
Base = declarative_base()


# -------------------------
# Database models
# -------------------------
class LogModel(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String)
    log_type = Column(String)
    message = Column(String)
    parsed = Column(JSON)
    received_at = Column(DateTime)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String)
    title = Column(String)
    description = Column(String)
    severity = Column(String)
    source_ip = Column(String)
    failed_attempts = Column(Integer)
    time_window_minutes = Column(Integer)
    status = Column(String)
    created_at = Column(DateTime)


Base.metadata.create_all(bind=engine)


# crées une classe appelée LogInput. Elle hérite de BaseModel
# contenir trois champs de type str
# source: str --> indique d’où vient le log "firewall server endpoint ids nginx x"
# log_type: str --> indique le type de log "info warning error alert authentication network"
# le contenu réel du log --> Exemple : Failed login attempt for user admin

# -------------------------
# Request schemas
# -------------------------
class LogInput(BaseModel):
    source: str
    log_type: str
    message: str

# -------------------------
# Helpers
# -------------------------
def get_db():
    return SessionLocal()

# crée une liste vide
#logs_storage = []
#alerts_storage = []


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

def log_to_dict(log: LogModel):
    return {
        "id": log.id,
        "source": log.source,
        "log_type": log.log_type,
        "message": log.message,
        "parsed": log.parsed,
        "received_at": log.received_at.isoformat()
    }

def alert_to_dict(alert: AlertModel):
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "failed_attempts": alert.failed_attempts,
        "time_window_minutes": alert.time_window_minutes,
        "status": alert.status,
        "created_at": alert.created_at.isoformat()
    }




def detect_brute_force(db):
    """
    Détection :
    si une IP a 5 échecs SSH ou plus dans les 10 dernières minutes,
    créer une alerte.
    """

    now = datetime.utcnow()
    time_window_start = now - timedelta(minutes=10)

    recent_logs = (
        db.query(LogModel)
        .filter(LogModel.received_at >= time_window_start)
        .all()
    )

    failed_login_count_by_ip = {}

    for log in recent_logs:
        parsed = log.parsed or {}

        is_failed_login = (
            parsed.get("category") == "authentication"
            and parsed.get("action") == "login_failed"
            and parsed.get("source_ip") is not None
        )

        if is_failed_login:
            source_ip = parsed["source_ip"]
            failed_login_count_by_ip[source_ip] = failed_login_count_by_ip.get(source_ip, 0) + 1

    for source_ip, count in failed_login_count_by_ip.items():
        if count >= 5:
            alert_already_exists = (
                db.query(AlertModel)
                .filter(AlertModel.source_ip == source_ip)
                .filter(AlertModel.rule_id == "SSH_BRUTE_FORCE")
                .filter(AlertModel.status == "open")
                .first()
            )

            if not alert_already_exists:
                alert = AlertModel(
                    rule_id="SSH_BRUTE_FORCE",
                    title="Possible SSH brute force attack",
                    description=f"{count} failed SSH login attempts from {source_ip} in the last 10 minutes",
                    severity="high",
                    source_ip=source_ip,
                    failed_attempts=count,
                    time_window_minutes=10,
                    status="open",
                    created_at=datetime.utcnow()
                )

                db.add(alert)
                db.commit()


# -------------------------
# API routes
# -------------------------
@app.get("/")
def home():
    return {
        "message": "Cyber SOC Platform API is running"
    }

@app.post("/ingest/log")
def ingest_log(log: LogInput):
    db = get_db()

    parsed_data = {}

    if log.log_type == "linux_auth":
        parsed_data = parse_linux_auth_log(log.message)

    log_entry = LogModel(
        source=log.source,
        log_type=log.log_type,
        message=log.message,
        parsed=parsed_data,
        received_at=datetime.utcnow()
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    detect_brute_force(db)

    response = {
        "status": "success",
        "message": "Log received, parsed, analyzed and saved successfully",
        "data": log_to_dict(log_entry)
    }

    db.close()

    return response



@app.get("/logs")
def get_logs():
    db = get_db()

    logs = (
        db.query(LogModel)
        .order_by(LogModel.id.desc())
        .all()
    )

    response = {
        "count": len(logs),
        "logs": [log_to_dict(log) for log in logs]
    }

    db.close()

    return response


@app.get("/alerts")
def get_alerts():
    db = get_db()

    alerts = (
        db.query(AlertModel)
        .order_by(AlertModel.id.desc())
        .all()
    )

    response = {
        "count": len(alerts),
        "alerts": [alert_to_dict(alert) for alert in alerts]
    }

    db.close()

    return response
