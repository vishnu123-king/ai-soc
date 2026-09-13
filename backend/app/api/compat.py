from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional, Dict, Any

from backend.app.database.connection import get_db
from backend.app.api.dashboard import get_dashboard_summary, get_dashboard_timeline
from backend.app.api.events import list_events, _process_single_event
from backend.app.api.simulation import run_attack_simulation, SimulationRunRequest
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.models.incident import Incident
from backend.app.models.ai_analysis import AIAnalysis
from backend.app.schemas.event import EventCreate
from backend.app.websocket_manager import ws_manager

router = APIRouter()

@router.get("/stats")
def compat_stats(db: Session = Depends(get_db)):
    summary = get_dashboard_summary(db)
    timeline = get_dashboard_timeline(hours=8, db=db)
    detections = db.query(Detection).order_by(Detection.timestamp.desc()).limit(10).all()

    threat_dist = [
        {"name": k, "count": v}
        for k, v in summary.severity_breakdown.items()
    ]

    return {
        "total_events": summary.total_events,
        "total_alerts": db.query(Detection).count(),
        "active_incidents": summary.active_incidents,
        "critical_incidents": summary.critical_incidents,
        "high_incidents": summary.high_incidents,
        "medium_incidents": summary.medium_incidents,
        "low_incidents": summary.low_incidents,
        "security_score": max(0, int(100 - summary.overall_risk_score)),
        "threat_distribution": threat_dist,
        "timeline_stats": [
            {"time": p.timestamp, "events": p.events, "alerts": p.detections}
            for p in timeline
        ],
        "recent_alerts": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "rule_name": d.title,
                "severity": d.severity,
                "timestamp": d.timestamp.isoformat() if hasattr(d.timestamp, 'isoformat') else str(d.timestamp),
                "hostname": d.hostname,
                "description": d.description,
                "evidence": [f"Event #{eid}" for eid in (d.evidence_event_ids or [])],
                "mitre_technique_id": d.mitre_technique_id,
                "mitre_technique_name": d.mitre_technique_name,
                "incident_id": d.incident_id
            }
            for d in detections
        ]
    }

@router.get("/logs")
def compat_logs(limit: int = 100, event_type: Optional[str] = None, db: Session = Depends(get_db)):
    events = list_events(limit=limit, offset=0, event_type=event_type, db=db)
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp),
            "hostname": e.hostname,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "username": e.username,
            "event_type": e.event_type,
            "action": e.action,
            "status": e.status,
            "process": e.process,
            "command": e.command,
            "raw_message": e.raw_message or f"{e.event_type}:{e.action} on {e.hostname}",
            "metadata": e.event_metadata or {}
        }
        for e in events
    ]

@router.post("/logs")
async def compat_ingest_log(payload: Dict[str, Any], db: Session = Depends(get_db)):
    ev_create = EventCreate(
        agent_id=payload.get("agent_id", "web-console"),
        hostname=payload.get("hostname", "prod-db-01.corp.internal"),
        event_type=payload.get("event_type", "generic"),
        action=payload.get("action", "event"),
        status=payload.get("status", "info"),
        source_ip=payload.get("source_ip"),
        destination_ip=payload.get("destination_ip"),
        username=payload.get("username"),
        process=payload.get("process"),
        command=payload.get("command"),
        raw_message=payload.get("raw_message"),
        metadata=payload.get("metadata", {})
    )
    saved = await _process_single_event(ev_create, db)
    return {"status": "ingested", "id": saved.id, "event": saved}

@router.post("/seed")
async def compat_seed(db: Session = Depends(get_db)):
    req = SimulationRunRequest(scenario="full_kill_chain", hostname="srv-linux-prod-01", agent_id="srv-linux-prod-01")
    res = await run_attack_simulation(req, db)
    await ws_manager.broadcast("SEED_COMPLETED", {"scenario": "full_kill_chain"})
    return res

@router.post("/reset")
async def reset_db_events(db: Session = Depends(get_db)):
    """Clears events, detections, incidents, and analyses for fresh testing."""
    db.query(AIAnalysis).delete()
    db.query(Detection).delete()
    db.execute(text("DELETE FROM incident_events"))
    db.query(Incident).delete()
    db.query(Event).delete()
    db.commit()
    await ws_manager.broadcast("DATABASE_RESET", {})
    return {"status": "reset_completed", "message": "Telemetry and incident tables reset."}
