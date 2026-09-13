from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database.connection import Base

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.85)
    mitre_technique_id = Column(String(32), index=True, nullable=False)
    mitre_technique_name = Column(String(255), nullable=False)
    evidence_event_ids = Column(JSON, default=list)  # list of integer event IDs
    hostname = Column(String(255), index=True, nullable=False)
    agent_id = Column(String(100), nullable=True)
    source_ip = Column(String(64), nullable=True)
    username = Column(String(128), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)

    incident = relationship("Incident", back_populates="detections")
