from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from backend.app.schemas.event import EventResponse
from backend.app.schemas.detection import DetectionResponse
from backend.app.schemas.ai import AIAnalysisSchema

class MitreItem(BaseModel):
    id: str
    name: str
    tactic: str

class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE")

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    risk_score: float
    risk_explanation: Optional[str] = None
    confidence: float
    status: str
    agent_id: Optional[str] = None
    hostname: str
    affected_host: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    detections_count: Optional[int] = 0
    events_count: Optional[int] = 0
    ai_analyzed: Optional[bool] = False
    ai_analysis: Optional[AIAnalysisSchema] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.affected_host:
            self.affected_host = self.hostname

    model_config = ConfigDict(from_attributes=True)

class IncidentDetailResponse(IncidentResponse):
    detections: List[DetectionResponse] = Field(default_factory=list)
    alerts: Optional[List[Any]] = None
    events: List[EventResponse] = Field(default_factory=list)
    ai_analyses: List[AIAnalysisSchema] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        if not self.alerts:
            self.alerts = [
                {
                    "id": d.id,
                    "rule_id": d.rule_id,
                    "rule_name": d.title,
                    "severity": d.severity,
                    "timestamp": d.timestamp.isoformat() if hasattr(d.timestamp, 'isoformat') else str(d.timestamp),
                    "hostname": d.hostname,
                    "description": d.description,
                    "evidence": d.evidence or [],
                    "mitre_technique_id": d.mitre_technique_id,
                    "mitre_technique_name": d.mitre_technique_name,
                    "incident_id": d.incident_id
                }
                for d in self.detections
            ]
        if self.ai_analyses and not self.ai_analysis:
            self.ai_analysis = self.ai_analyses[-1]

