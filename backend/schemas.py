from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class SecurityLogCreate(BaseModel):
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    hostname: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str  # auth, network, process, privilege, file, system
    action: Optional[str] = None  # login, exec, connect, sudo, modify
    status: str  # success, failure, denied, attempt
    process: Optional[str] = None
    command: Optional[str] = None
    raw_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SecurityLogResponse(BaseModel):
    id: int
    timestamp: datetime
    hostname: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    event_type: str
    action: Optional[str]
    status: str
    process: Optional[str]
    command: Optional[str]
    raw_message: Optional[str]
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, alias="log_metadata")
    ingested_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True

class AlertResponse(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    hostname: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    description: str
    evidence: List[Any]
    incident_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True

class MitreTechniqueSchema(BaseModel):
    id: str
    name: str
    tactic: str
    description: Optional[str] = None

class AIAnalysisSchema(BaseModel):
    incident_summary: str
    likely_attack_type: str
    severity_assessment: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    attack_progression: List[str]
    evidence: List[str]
    mitre_techniques: List[str]
    recommended_investigation_steps: List[str]
    recommended_containment_steps: List[str]
    model_provider: str
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

class IncidentResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    risk_score: float
    risk_explanation: str
    affected_host: str
    source_ip: Optional[str]
    username: Optional[str]
    mitre_techniques: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    ai_model_used: Optional[str] = None
    ai_analyzed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class IncidentDetailResponse(IncidentResponse):
    alerts: List[AlertResponse] = []
    ai_analysis: Optional[AIAnalysisSchema] = None

class IncidentStatusUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, CONTAINED, CLOSED

class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    active_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    security_score: int  # 0 - 100 overall defense health
    threat_distribution: List[Dict[str, Any]]
    timeline_stats: List[Dict[str, Any]]
    recent_alerts: List[AlertResponse]
