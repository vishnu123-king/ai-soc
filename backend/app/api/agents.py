from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database.connection import get_db
from backend.app.models.agent import Agent
from backend.app.models.event import Event
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.agent import AgentRegisterRequest, AgentRegisterResponse, AgentResponse, AgentUpdate
from backend.app.auth.security import generate_agent_token, hash_agent_token
from backend.app.auth.jwt import verify_agent_token_header
from backend.app.websocket_manager import ws_manager

router = APIRouter()

@router.post("/register", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(payload: AgentRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a new Linux host running the future aisoc-agent component.
    Generates a secure bearer token for subsequent telemetry transmissions.
    """
    existing = db.query(Agent).filter(Agent.agent_id == payload.agent_id).first()
    raw_token = generate_agent_token()
    token_hash = hash_agent_token(raw_token)

    if existing:
        # Update existing agent registration
        existing.hostname = payload.hostname
        existing.operating_system = payload.operating_system
        existing.ip_address = payload.ip_address
        existing.agent_version = payload.agent_version
        existing.auth_token_hash = token_hash
        existing.status = "ONLINE"
        existing.last_seen = datetime.utcnow()
        if payload.metadata:
            existing.agent_metadata = payload.metadata
        db.commit()
        db.refresh(existing)
        agent = existing
        msg = "Agent registration re-enrolled and auth token refreshed."
    else:
        agent = Agent(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            operating_system=payload.operating_system,
            ip_address=payload.ip_address,
            agent_version=payload.agent_version,
            status="ONLINE",
            auth_token_hash=token_hash,
            last_seen=datetime.utcnow(),
            registered_at=datetime.utcnow(),
            agent_metadata=payload.metadata or {}
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)
        msg = "New agent registered successfully."

    # Record audit log
    audit = AuditLog(
        action="AGENT_REGISTER",
        resource_type="agent",
        resource_id=agent.agent_id,
        details={"hostname": agent.hostname, "ip": agent.ip_address},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    # Broadcast via WebSocket
    await ws_manager.broadcast("AGENT_REGISTERED", {
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "status": agent.status
    })

    return AgentRegisterResponse(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        status=agent.status,
        token=raw_token,
        registered_at=agent.registered_at,
        message=msg
    )

@router.get("", response_model=List[AgentResponse])
def list_agents(db: Session = Depends(get_db)):
    """Lists all registered agents and dynamically verifies online/offline status."""
    now = datetime.utcnow()
    stale_threshold = now - timedelta(minutes=5)
    
    agents = db.query(Agent).order_by(Agent.last_seen.desc()).all()
    results = []

    for a in agents:
        # If agent hasn't sent telemetry or heartbeat in 5 minutes, mark offline
        if a.last_seen < stale_threshold and a.status == "ONLINE":
            a.status = "OFFLINE"
            db.commit()
        
        # Count total events reported by this agent
        ev_count = db.query(func.count(Event.id)).filter(Event.agent_id == a.agent_id).scalar() or 0
        
        results.append(
            AgentResponse(
                id=a.id,
                agent_id=a.agent_id,
                hostname=a.hostname,
                operating_system=a.operating_system,
                ip_address=a.ip_address,
                agent_version=a.agent_version,
                status=a.status,
                last_seen=a.last_seen,
                registered_at=a.registered_at,
                agent_metadata=a.agent_metadata or {},
                event_count=ev_count
            )
        )
    return results

@router.get("/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    ev_count = db.query(func.count(Event.id)).filter(Event.agent_id == agent.agent_id).scalar() or 0
    return AgentResponse(
        id=agent.id,
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        operating_system=agent.operating_system,
        ip_address=agent.ip_address,
        agent_version=agent.agent_version,
        status=agent.status,
        last_seen=agent.last_seen,
        registered_at=agent.registered_at,
        agent_metadata=agent.agent_metadata or {},
        event_count=ev_count
    )

@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    authenticated_agent: Optional[Agent] = Depends(verify_agent_token_header),
    db: Session = Depends(get_db)
):
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.last_seen = datetime.utcnow()
    agent.status = "ONLINE"
    db.commit()

    await ws_manager.broadcast("AGENT_HEARTBEAT", {
        "agent_id": agent.agent_id,
        "last_seen": agent.last_seen.isoformat(),
        "status": "ONLINE"
    })
    return {"status": "ok", "timestamp": agent.last_seen.isoformat()}
