from sqlalchemy import Column, Integer, String, DateTime, JSON
from .database import Base

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
    incident_id = Column(Integer, nullable=True)
    title = Column(String)
    description = Column(String)
    severity = Column(String)
    source_ip = Column(String)
    failed_attempts = Column(Integer)
    time_window_minutes = Column(Integer)
    status = Column(String)
    created_at = Column(DateTime)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    severity = Column(String)
    status = Column(String)
    assigned_to = Column(String, nullable=True)
    created_at = Column(DateTime)