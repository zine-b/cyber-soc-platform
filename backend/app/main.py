from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine, get_db
from .models import LogModel, AlertModel, IncidentModel
from .schemas import (
    LogInput,
    AlertStatusUpdate,
    AlertAssignIncident,
    IncidentCreate,
    IncidentStatusUpdate,
    IncidentAssign,
    LogResponse,
    AlertResponse,
    IncidentResponse
)
from .parsers import parse_linux_auth_log
from .detection import detect_brute_force

import os
from dotenv import load_dotenv

load_dotenv()
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")


app = FastAPI(
    title="Cyber SOC Platform API",
    description="Mini plateforme SOC pour collecter et analyser des logs",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)



@app.get("/")
def home():
    return {
        "message": "Cyber SOC Platform API is running"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "backend"
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
        "data": LogResponse.model_validate(log_entry)
    }

    db.close()

    return response

@app.get("/logs")
def get_logs(page: int = 1, limit: int = 10):
    db = get_db()

    if page < 1:
        page = 1

    if limit < 1:
        limit = 10

    if limit > 100:
        limit = 100

    offset = (page - 1) * limit
    total_logs = db.query(LogModel).count()

    logs = (
        db.query(LogModel)
        .order_by(LogModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    response = {
        "count": len(logs),
        "total": total_logs,
        "page": page,
        "limit": limit,
        "total_pages": (total_logs + limit - 1) // limit,
        "logs": [LogResponse.model_validate(log) for log in logs]
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
        "alerts": [AlertResponse.model_validate(alert) for alert in alerts]
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
        "alert": AlertResponse.model_validate(alert)
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
        "alert": AlertResponse.model_validate(alert)
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
        assigned_to=None,
        created_at=datetime.utcnow()
    )

    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)

    response = {
        "status": "success",
        "message": "Incident created successfully",
        "incident": IncidentResponse.model_validate(new_incident)
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
        "incidents": [IncidentResponse.model_validate(incident) for incident in incidents]
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
        "incident": IncidentResponse.model_validate(incident),
        "linked_alerts_count": len(linked_alerts),
        "linked_alerts": [AlertResponse.model_validate(alert) for alert in linked_alerts]
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
        "incident": IncidentResponse.model_validate(incident)
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
        "alert": AlertResponse.model_validate(alert)
    }

    db.close()

    return response

@app.patch("/incidents/{incident_id}/assign")
def assign_incident(incident_id: int, assign_data: IncidentAssign):
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

    incident.assigned_to = assign_data.assigned_to
    db.commit()
    db.refresh(incident)

    response = {
        "status": "success",
        "message": "Incident assigned successfully",
        "incident": IncidentResponse.model_validate(incident)
    }

    db.close()

    return response