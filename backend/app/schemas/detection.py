from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class DetectionResponse(BaseModel):
    id: int
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    mitre_technique_id: str
    mitre_technique_name: str
    evidence_event_ids: List[int] = Field(default_factory=list)
    hostname: str
    agent_id: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    timestamp: datetime
    incident_id: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)
