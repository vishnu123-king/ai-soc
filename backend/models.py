from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship
from backend.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    hostname = Column(String(255), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    event_type = Column(String(64), index=True, nullable=False)  # auth, process, network, privilege, etc.
    action = Column(String(64), nullable=True)                 # login, exec, connect, sudo, etc.
    status = Column(String(32), nullable=False)                 # success, failure, denied, attempt
    process = Column(String(255), nullable=True)
    command = Column(Text, nullable=True)
    raw_message = Column(Text, nullable=True)
    log_metadata = Column(JSON, default=dict)
    ingested_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), index=True, nullable=False)
    rule_name = Column(String(255), nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    hostname = Column(String(255), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), nullable=True)
    username = Column(String(128), index=True, nullable=True)
    mitre_technique_id = Column(String(32), index=True, nullable=True)
    mitre_technique_name = Column(String(128), nullable=True)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=list)  # list of log event summaries or IDs
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="alerts")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), index=True, default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(32), default="OPEN", index=True)      # OPEN, INVESTIGATING, CONTAINED, CLOSED
    risk_score = Column(Float, default=0.0)
    risk_explanation = Column(Text, default="")
    affected_host = Column(String(255), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    mitre_techniques = Column(JSON, default=list)  # list of technique objects
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # AI Analyst Output cache
    ai_analysis = Column(JSON, nullable=True)
    ai_model_used = Column(String(64), nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")
