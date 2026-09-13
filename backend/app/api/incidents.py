from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from backend.app.database.connection import get_db
from backend.app.models.incident import Incident
from backend.app.models.ai_analysis import AIAnalysis
from backend.app.models.audit_log import AuditLog
from backend.app.models.user import User
from backend.app.schemas.incident import IncidentResponse, IncidentDetailResponse, IncidentStatusUpdate
from backend.app.schemas.ai import AIAnalysisSchema
from backend.app.ai import analyze_incident_safely
from backend.app.auth.jwt import get_current_user
from backend.app.websocket_manager import ws_manager

router = APIRouter()

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    hostname: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)

    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if hostname:
        query = query.filter(Incident.hostname == hostname)
    if search:
        s = f"%{search}%"
        query = query.filter(
            or_(
                Incident.title.ilike(s),
                Incident.description.ilike(s),
                Incident.source_ip.ilike(s),
                Incident.username.ilike(s),
                Incident.hostname.ilike(s)
            )
        )

    incidents = query.order_by(desc(Incident.risk_score), desc(Incident.last_seen)).offset(offset).limit(limit).all()
    
    results = []
    for inc in incidents:
        results.append(
            IncidentResponse(
                id=inc.id,
                title=inc.title,
                description=inc.description,
                severity=inc.severity,
                risk_score=inc.risk_score,
                risk_explanation=inc.risk_explanation,
                confidence=inc.confidence,
                status=inc.status,
                agent_id=inc.agent_id,
                hostname=inc.hostname,
                source_ip=inc.source_ip,
                username=inc.username,
                mitre_techniques=inc.mitre_techniques or [],
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                detections_count=len(inc.detections),
                events_count=len(inc.events),
                ai_analyzed=len(inc.ai_analyses) > 0
            )
        )
    return results

@router.get("/{id}", response_model=IncidentDetailResponse)
def get_incident(id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    return IncidentDetailResponse(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        risk_score=inc.risk_score,
        risk_explanation=inc.risk_explanation,
        confidence=inc.confidence,
        status=inc.status,
        agent_id=inc.agent_id,
        hostname=inc.hostname,
        source_ip=inc.source_ip,
        username=inc.username,
        mitre_techniques=inc.mitre_techniques or [],
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        detections_count=len(inc.detections),
        events_count=len(inc.events),
        ai_analyzed=len(inc.ai_analyses) > 0,
        detections=inc.detections,
        events=inc.events,
        ai_analyses=inc.ai_analyses
    )

@router.patch("/{id}/status", response_model=IncidentResponse)
async def update_incident_status(
    id: int,
    payload: IncidentStatusUpdate,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    valid_statuses = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
    new_status = payload.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}")

    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = inc.status
    inc.status = new_status
    inc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inc)

    # Log audit
    audit = AuditLog(
        user_id=str(current_user.id) if current_user else None,
        username=current_user.username if current_user else "anonymous_analyst",
        action="INCIDENT_STATUS_CHANGE",
        resource_type="incident",
        resource_id=str(inc.id),
        details={"old_status": old_status, "new_status": new_status},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    # Broadcast on WebSocket
    await ws_manager.broadcast("INCIDENT_UPDATED", {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "status": inc.status,
        "updated_at": inc.updated_at.isoformat()
    })

    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        risk_score=inc.risk_score,
        risk_explanation=inc.risk_explanation,
        confidence=inc.confidence,
        status=inc.status,
        agent_id=inc.agent_id,
        hostname=inc.hostname,
        source_ip=inc.source_ip,
        username=inc.username,
        mitre_techniques=inc.mitre_techniques or [],
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        detections_count=len(inc.detections),
        events_count=len(inc.events),
        ai_analyzed=len(inc.ai_analyses) > 0
    )

@router.post("/{id}/analyze", response_model=AIAnalysisSchema)
async def analyze_incident(id: int, db: Session = Depends(get_db)):
    """
    Executes AI-assisted incident investigation.
    Passes structured incident data to the configured AIProvider (Gemini/Local LLM/Mock).
    Persists structured AI findings in the database.
    """
    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_context = {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "risk_explanation": inc.risk_explanation,
        "hostname": inc.hostname,
        "agent_id": inc.agent_id,
        "source_ip": inc.source_ip,
        "username": inc.username,
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "mitre_techniques": inc.mitre_techniques or [],
        "detections": [
            {
                "rule_id": d.rule_id,
                "title": d.title,
                "severity": d.severity,
                "mitre_technique_id": d.mitre_technique_id,
                "mitre_technique_name": d.mitre_technique_name,
                "timestamp": d.timestamp.isoformat()
            } for d in inc.detections
        ],
        "events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "action": e.action,
                "status": e.status,
                "hostname": e.hostname,
                "username": e.username,
                "source_ip": e.source_ip,
                "command": e.command,
                "raw_message": e.raw_message
            } for e in inc.events
        ]
    }

    # Safely perform analysis with anti-crash fallback
    analysis_result = await analyze_incident_safely(incident_context)

    # Persist in DB
    ai_record = AIAnalysis(
        incident_id=inc.id,
        model_provider=analysis_result.model_provider or "ai-provider",
        summary=analysis_result.summary,
        attack_type=analysis_result.attack_type,
        severity_assessment=analysis_result.severity_assessment,
        confidence=analysis_result.confidence,
        attack_progression=analysis_result.attack_progression,
        observed_evidence=analysis_result.observed_evidence,
        hypotheses=analysis_result.hypotheses,
        mitre_analysis=analysis_result.mitre_analysis,
        investigation_steps=analysis_result.investigation_steps,
        containment_recommendations=analysis_result.containment_recommendations,
        created_at=datetime.utcnow()
    )
    db.add(ai_record)
    db.commit()
    db.refresh(ai_record)

    await ws_manager.broadcast("AI_ANALYSIS_COMPLETED", {
        "incident_id": inc.id,
        "summary": ai_record.summary,
        "attack_type": ai_record.attack_type,
        "provider": ai_record.model_provider
    })

    return analysis_result

@router.get("/{id}/report")
def get_incident_report(id: int, db: Session = Depends(get_db)):
    from backend.app.api.reports import generate_incident_html_report
    return generate_incident_html_report(id, db)

