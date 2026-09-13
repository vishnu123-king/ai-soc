from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class DashboardSummaryResponse(BaseModel):
    total_events: int
    events_today: int
    active_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    connected_agents: int
    overall_risk_score: float
    status_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]

class TimelinePoint(BaseModel):
    timestamp: str
    events: int
    detections: int
    incidents: int

class MitreDistributionItem(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    count: int

class AgentHealthItem(BaseModel):
    agent_id: str
    hostname: str
    status: str
    last_seen: datetime
    events_count: int
