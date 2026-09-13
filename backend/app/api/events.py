import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from backend.app.database.connection import get_db
from backend.app.models.event import Event
from backend.app.models.agent import Agent
from backend.app.schemas.event import EventCreate, EventBatchCreate, EventResponse
from backend.app.detection.engine import detection_engine
from backend.app.correlation.engine import correlation_engine
from backend.app.websocket_manager import ws_manager

logger = logging.getLogger("aisoc.events")
router = APIRouter()

async def _process_single_event(payload: EventCreate, db: Session) -> Event:
    """Internal helper to ingest, detect, correlate, and persist an event."""
    event = Event(
        agent_id=payload.agent_id,
        hostname=payload.hostname,
        timestamp=payload.timestamp or datetime.utcnow(),
        event_type=payload.event_type,
        action=payload.action,
        status=payload.status,
        username=payload.username,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        process=payload.process,
        parent_process=payload.parent_process,
        command=payload.command,
        raw_message=payload.raw_message,
        event_metadata=payload.metadata or {},
        is_simulation=payload.simulation or False
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # If associated with an agent, refresh last_seen and online status
    if event.agent_id:
        agent = db.query(Agent).filter(Agent.agent_id == event.agent_id).first()
        if agent:
            agent.last_seen = event.timestamp
            agent.status = "ONLINE"
            db.commit()

    # WebSocket broadcast
    await ws_manager.broadcast("EVENT_INGESTED", {
        "id": event.id,
        "event_type": event.event_type,
        "action": event.action,
        "status": event.status,
        "hostname": event.hostname,
        "source_ip": event.source_ip,
        "username": event.username,
        "timestamp": event.timestamp.isoformat(),
        "is_simulation": event.is_simulation
    })

    # Execute deterministic Detection Engine
    new_detections = detection_engine.process_event(event, db)
    
    if new_detections:
        for det in new_detections:
            await ws_manager.broadcast("DETECTION_TRIGGERED", {
                "id": det.id,
                "rule_id": det.rule_id,
                "title": det.title,
                "severity": det.severity,
                "hostname": det.hostname,
                "mitre_id": det.mitre_technique_id,
                "timestamp": det.timestamp.isoformat()
            })

        # Execute Correlation Engine
        impacted_incidents = correlation_engine.correlate_detections(new_detections, db)
        for inc in impacted_incidents:
            await ws_manager.broadcast("INCIDENT_UPDATED", {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "status": inc.status,
                "hostname": inc.hostname,
                "updated_at": inc.updated_at.isoformat()
            })

    return event

@router.post("", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(payload: EventCreate, db: Session = Depends(get_db)):
    """
    Ingests a single normalized Linux security telemetry event.
    Evaluates detection rules, correlates alerts into incidents, and persists in database.
    """
    event = await _process_single_event(payload, db)
    return event

@router.post("/batch", status_code=status.HTTP_201_CREATED)
async def ingest_events_batch(payload: EventBatchCreate, db: Session = Depends(get_db)):
    """
    Ingests a batch of events (optimized for aisoc-agent buffering).
    """
    ingested_count = 0
    for ev in payload.events:
        await _process_single_event(ev, db)
        ingested_count += 1
    return {"status": "ok", "ingested": ingested_count}

@router.get("", response_model=List[EventResponse])
def list_events(
    search: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    hostname: Optional[str] = None,
    source_ip: Optional[str] = None,
    agent_id: Optional[str] = None,
    is_simulation: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Paginated Event Explorer endpoint with full-text search and field filtering.
    """
    query = db.query(Event)

    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            or_(
                Event.raw_message.ilike(search_filter),
                Event.command.ilike(search_filter),
                Event.process.ilike(search_filter),
                Event.username.ilike(search_filter),
                Event.source_ip.ilike(search_filter),
                Event.hostname.ilike(search_filter)
            )
        )
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if status:
        query = query.filter(Event.status == status)
    if hostname:
        query = query.filter(Event.hostname == hostname)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if agent_id:
        query = query.filter(Event.agent_id == agent_id)
    if is_simulation is not None:
        query = query.filter(Event.is_simulation == is_simulation)

    events = query.order_by(desc(Event.timestamp)).offset(offset).limit(limit).all()
    return events
