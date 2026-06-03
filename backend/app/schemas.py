from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from datetime import datetime


# -------------------------
# Input schemas
# -------------------------
class LogInput(BaseModel):
    source: str
    log_type: str
    message: str

class AlertStatusUpdate(BaseModel):
    status: str

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str

class IncidentStatusUpdate(BaseModel):
    status: str

class AlertAssignIncident(BaseModel):
    incident_id: int

class IncidentAssign(BaseModel):
    assigned_to: str


# -------------------------
# Response schemas
# -------------------------
class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    log_type: str
    message: str
    parsed: Optional[dict[str, Any]]
    received_at: datetime


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    title: str
    description: str
    severity: str
    source_ip: str
    failed_attempts: int
    time_window_minutes: int
    status: str
    incident_id: Optional[int]
    created_at: datetime


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str
    severity: str
    status: str
    assigned_to: Optional[str]
    created_at: datetime