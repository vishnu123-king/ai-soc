from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database.connection import Base

class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    model_provider = Column(String(64), nullable=False)        # gemini, local_qwen, mock
    summary = Column(Text, nullable=False)
    attack_type = Column(String(255), nullable=False)
    severity_assessment = Column(String(255), nullable=False)
    confidence = Column(Float, default=0.90)
    
    attack_progression = Column(JSON, default=list)            # list of string steps
    observed_evidence = Column(JSON, default=list)             # strictly anti-hallucination factual evidence
    hypotheses = Column(JSON, default=list)                    # plausible analyst hypotheses
    mitre_analysis = Column(JSON, default=list)                # mitre correlations
    investigation_steps = Column(JSON, default=list)           # procedural steps for SOC Tier-2/3
    containment_recommendations = Column(JSON, default=list)   # containment actions
    
    created_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="ai_analyses")
