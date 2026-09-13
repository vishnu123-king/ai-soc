from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database.connection import get_db
from backend.app.models.detection import Detection
from backend.app.schemas.detection import DetectionResponse

router = APIRouter()

@router.get("", response_model=List[DetectionResponse])
def list_detections(
    severity: Optional[str] = None,
    hostname: Optional[str] = None,
    rule_id: Optional[str] = None,
    incident_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Detection)
    if severity:
        query = query.filter(Detection.severity == severity.upper())
    if hostname:
        query = query.filter(Detection.hostname == hostname)
    if rule_id:
        query = query.filter(Detection.rule_id == rule_id)
    if incident_id:
        query = query.filter(Detection.incident_id == incident_id)

    detections = query.order_by(desc(Detection.timestamp)).offset(offset).limit(limit).all()
    return detections

@router.get("/{id}", response_model=DetectionResponse)
def get_detection(id: int, db: Session = Depends(get_db)):
    det = db.query(Detection).filter(Detection.id == id).first()
    if not det:
        raise HTTPException(status_code=404, detail="Detection not found")
    return det
