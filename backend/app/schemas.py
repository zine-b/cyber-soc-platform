from pydantic import BaseModel

# -------------------------
# Request schemas
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