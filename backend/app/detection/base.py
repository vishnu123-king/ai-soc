from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from backend.app.models.event import Event

class DetectionResult(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    mitre_technique_id: str
    mitre_technique_name: str
    evidence_event_ids: List[int]
    hostname: str
    agent_id: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    timestamp: datetime
    metadata: Dict[str, Any] = {}

class BaseDetectionRule(ABC):
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    mitre_technique_id: str
    mitre_technique_name: str

    @abstractmethod
    def evaluate(self, event: Event, db) -> List[DetectionResult]:
        """Evaluates rule against single event and historical context"""
        pass
