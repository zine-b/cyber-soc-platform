from datetime import datetime
from fastapi import FastAPI

from app.database import Base, engine, get_db
from app.models import LogModel, AlertModel, IncidentModel
from app.schemas import (
    LogInput,
    AlertStatusUpdate,
    AlertAssignIncident,
    IncidentCreate,
    IncidentStatusUpdate
)
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

def incident_to_dict(incident: IncidentModel):
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "created_at": incident.created_at.isoformat()
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
        "incident_id": alert.incident_id,
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

@app.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: int):
    db = get_db()

    alert = (
        db.query(AlertModel)
        .filter(AlertModel.id == alert_id)
        .first()
    )

    if alert is None:
        db.close()
        return {
            "status": "error",
            "message": "Alert not found"
        }

    response = {
        "status": "success",
        "alert": alert_to_dict(alert)
    }

    db.close()

    return response

@app.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status_update: AlertStatusUpdate):
    db = get_db()

    allowed_statuses = ["open", "investigating", "resolved", "false_positive"]

    if status_update.status not in allowed_statuses:
        db.close()
        return {
            "status": "error",
            "message": f"Invalid status. Allowed values: {allowed_statuses}"
        }

    alert = (
        db.query(AlertModel)
        .filter(AlertModel.id == alert_id)
        .first()
    )

    if alert is None:
        db.close()
        return {
            "status": "error",
            "message": "Alert not found"
        }

    alert.status = status_update.status
    db.commit()
    db.refresh(alert)

    response = {
        "status": "success",
        "message": "Alert status updated successfully",
        "alert": alert_to_dict(alert)
    }

    db.close()

    return response

@app.post("/incidents")
def create_incident(incident: IncidentCreate):
    db = get_db()

    allowed_severities = ["low", "medium", "high", "critical"]

    if incident.severity not in allowed_severities:
        db.close()
        return {
            "status": "error",
            "message": f"Invalid severity. Allowed values: {allowed_severities}"
        }

    new_incident = IncidentModel(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status="open",
        created_at=datetime.utcnow()
    )

    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)

    response = {
        "status": "success",
        "message": "Incident created successfully",
        "incident": incident_to_dict(new_incident)
    }

    db.close()

    return response

@app.get("/incidents")
def get_incidents():
    db = get_db()

    incidents = (
        db.query(IncidentModel)
        .order_by(IncidentModel.id.desc())
        .all()
    )

    response = {
        "count": len(incidents),
        "incidents": [incident_to_dict(incident) for incident in incidents]
    }

    db.close()

    return response

@app.get("/incidents/{incident_id}")
def get_incident_by_id(incident_id: int):
    db = get_db()

    incident = (
        db.query(IncidentModel)
        .filter(IncidentModel.id == incident_id)
        .first()
    )

    if incident is None:
        db.close()
        return {
            "status": "error",
            "message": "Incident not found"
        }

    linked_alerts = (
        db.query(AlertModel)
        .filter(AlertModel.incident_id == incident_id)
        .order_by(AlertModel.id.desc())
        .all()
    )

    response = {
        "status": "success",
        "incident": incident_to_dict(incident),
        "linked_alerts_count": len(linked_alerts),
        "linked_alerts": [alert_to_dict(alert) for alert in linked_alerts]
    }

    db.close()

    return response

@app.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, status_update: IncidentStatusUpdate):
    db = get_db()

    allowed_statuses = ["open", "investigating", "resolved", "false_positive"]

    if status_update.status not in allowed_statuses:
        db.close()
        return {
            "status": "error",
            "message": f"Invalid status. Allowed values: {allowed_statuses}"
        }

    incident = (
        db.query(IncidentModel)
        .filter(IncidentModel.id == incident_id)
        .first()
    )

    if incident is None:
        db.close()
        return {
            "status": "error",
            "message": "Incident not found"
        }

    incident.status = status_update.status
    db.commit()
    db.refresh(incident)

    response = {
        "status": "success",
        "message": "Incident status updated successfully",
        "incident": incident_to_dict(incident)
    }

    db.close()

    return response

@app.patch("/alerts/{alert_id}/assign-incident")
def assign_alert_to_incident(alert_id: int, assign_data: AlertAssignIncident):
    db = get_db()

    alert = (
        db.query(AlertModel)
        .filter(AlertModel.id == alert_id)
        .first()
    )

    if alert is None:
        db.close()
        return {
            "status": "error",
            "message": "Alert not found"
        }

    incident = (
        db.query(IncidentModel)
        .filter(IncidentModel.id == assign_data.incident_id)
        .first()
    )

    if incident is None:
        db.close()
        return {
            "status": "error",
            "message": "Incident not found"
        }

    alert.incident_id = assign_data.incident_id
    db.commit()
    db.refresh(alert)

    response = {
        "status": "success",
        "message": "Alert assigned to incident successfully",
        "alert": alert_to_dict(alert)
    }

    db.close()

    return response

