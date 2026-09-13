from datetime import datetime, timedelta
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database.connection import get_db
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.models.incident import Incident
from backend.app.models.agent import Agent
from backend.app.schemas.dashboard import DashboardSummaryResponse, TimelinePoint, MitreDistributionItem, AgentHealthItem

router = APIRouter()

@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    
    total_events = db.query(func.count(Event.id)).scalar() or 0
    events_today = db.query(func.count(Event.id)).filter(Event.timestamp >= today_start).scalar() or 0
    
    # Active incidents (not resolved or false positive)
    active_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["NEW", "INVESTIGATING", "CONTAINED"])
    ).scalar() or 0

    critical_count = db.query(func.count(Incident.id)).filter(Incident.severity == "CRITICAL", Incident.status != "RESOLVED").scalar() or 0
    high_count = db.query(func.count(Incident.id)).filter(Incident.severity == "HIGH", Incident.status != "RESOLVED").scalar() or 0
    medium_count = db.query(func.count(Incident.id)).filter(Incident.severity == "MEDIUM", Incident.status != "RESOLVED").scalar() or 0
    low_count = db.query(func.count(Incident.id)).filter(Incident.severity == "LOW", Incident.status != "RESOLVED").scalar() or 0

    # Agents connected within the last 5 minutes
    connected_agents = db.query(func.count(Agent.id)).filter(
        Agent.last_seen >= now - timedelta(minutes=5),
        Agent.status == "ONLINE"
    ).scalar() or 0

    # Overall system risk score
    max_risk = db.query(func.max(Incident.risk_score)).filter(Incident.status.in_(["NEW", "INVESTIGATING"])).scalar() or 0.0
    avg_risk = db.query(func.avg(Incident.risk_score)).filter(Incident.status.in_(["NEW", "INVESTIGATING"])).scalar() or 0.0
    overall_risk = round((max_risk * 0.6) + (avg_risk * 0.4), 1) if max_risk > 0 else 12.0

    # Status breakdown
    statuses = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
    status_breakdown = {}
    for st in statuses:
        cnt = db.query(func.count(Incident.id)).filter(Incident.status == st).scalar() or 0
        status_breakdown[st] = cnt

    severity_breakdown = {
        "CRITICAL": critical_count,
        "HIGH": high_count,
        "MEDIUM": medium_count,
        "LOW": low_count
    }

    return DashboardSummaryResponse(
        total_events=total_events,
        events_today=events_today,
        active_incidents=active_incidents,
        critical_incidents=critical_count,
        high_incidents=high_count,
        medium_incidents=medium_count,
        low_incidents=low_count,
        connected_agents=connected_agents,
        overall_risk_score=overall_risk,
        status_breakdown=status_breakdown,
        severity_breakdown=severity_breakdown
    )

@router.get("/timeline", response_model=List[TimelinePoint])
def get_dashboard_timeline(hours: int = 12, db: Session = Depends(get_db)):
    """Provides time-series data for telemetry, detections, and incidents."""
    now = datetime.utcnow()
    points = []

    for i in range(hours - 1, -1, -1):
        bucket_start = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(hours=1)
        time_label = bucket_start.strftime("%H:00")

        ev_count = db.query(func.count(Event.id)).filter(
            Event.timestamp >= bucket_start, Event.timestamp < bucket_end
        ).scalar() or 0

        det_count = db.query(func.count(Detection.id)).filter(
            Detection.timestamp >= bucket_start, Detection.timestamp < bucket_end
        ).scalar() or 0

        inc_count = db.query(func.count(Incident.id)).filter(
            Incident.created_at >= bucket_start, Incident.created_at < bucket_end
        ).scalar() or 0

        points.append(TimelinePoint(
            timestamp=time_label,
            events=ev_count,
            detections=det_count,
            incidents=inc_count
        ))

    return points

@router.get("/mitre-distribution", response_model=List[MitreDistributionItem])
def get_mitre_distribution(db: Session = Depends(get_db)):
    """Returns frequency counts grouped by MITRE ATT&CK technique."""
    detections = db.query(Detection).all()
    freq = {}

    for d in detections:
        tid = d.mitre_technique_id
        if tid not in freq:
            freq[tid] = {
                "technique_id": tid,
                "technique_name": d.mitre_technique_name,
                "tactic": "Credential Access" if "1110" in tid else "Execution" if "1059" in tid else "Privilege Escalation" if "1548" in tid else "Discovery",
                "count": 0
            }
        freq[tid]["count"] += 1

    sorted_items = sorted(freq.values(), key=lambda x: x["count"], reverse=True)
    return [MitreDistributionItem(**item) for item in sorted_items]

@router.get("/agent-health", response_model=List[AgentHealthItem])
def get_agent_health(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    results = []
    for a in agents:
        ev_count = db.query(func.count(Event.id)).filter(Event.agent_id == a.agent_id).scalar() or 0
        results.append(AgentHealthItem(
            agent_id=a.agent_id,
            hostname=a.hostname,
            status=a.status,
            last_seen=a.last_seen,
            events_count=ev_count
        ))
    return results
