from datetime import datetime
from fastapi import FastAPI

from app.database import Base, engine, get_db
from app.models import LogModel, AlertModel
from app.schemas import LogInput
from app.parsers import parse_linux_auth_log
from app.detection import detect_brute_force


app = FastAPI(
    title="Cyber SOC Platform API",
    description="Mini plateforme SOC pour collecter et analyser des logs",
    version="0.1.0"
)

Base.metadata.create_all(bind=engine)


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