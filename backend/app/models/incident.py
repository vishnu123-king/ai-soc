from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON, ForeignKey, Table
from sqlalchemy.orm import relationship
from backend.app.database.connection import Base

# Association Table: incident_events
incident_events = Table(
    "incident_events",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", Integer, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime, default=datetime.utcnow)
)

# Association Table: incident_detections
incident_detections = Table(
    "incident_detections",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("detection_id", Integer, ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime, default=datetime.utcnow)
)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=50.0)                   # 0.0 - 100.0
    risk_explanation = Column(Text, nullable=True)
    confidence = Column(Float, default=0.85)
    status = Column(String(32), default="NEW", index=True)      # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    
    agent_id = Column(String(100), nullable=True)
    hostname = Column(String(255), index=True, nullable=False)
    source_ip = Column(String(64), nullable=True)
    username = Column(String(128), nullable=True)
    
    mitre_techniques = Column(JSON, default=list)              # [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}]
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    detections = relationship("Detection", back_populates="incident", lazy="selectin")
    events = relationship("Event", secondary=incident_events, lazy="selectin")
    ai_analyses = relationship("AIAnalysis", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
