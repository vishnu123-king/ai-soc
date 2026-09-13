from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.app.database.connection import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)               # INCIDENT_STATUS_CHANGE, AGENT_REGISTER, etc.
    resource_type = Column(String(64), nullable=False)         # incident, agent, rule, auth
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
