import logging
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.app.models.incident import Incident
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.mitre.mapper import mitre_mapper
from backend.app.risk.engine import risk_engine

logger = logging.getLogger("aisoc.correlation")

class CorrelationEngine:
    def correlate_detections(self, detections: List[Detection], db: Session) -> List[Incident]:
        """
        Groups new detections into existing open incidents or creates new incidents.
        Returns list of impacted or created incidents.
        """
        impacted_incidents: List[Incident] = []

        for det in detections:
            incident = self._find_matching_incident(det, db)
            if incident:
                # Link detection to existing incident
                det.incident_id = incident.id
                incident.last_seen = max(incident.last_seen, det.timestamp)
                incident.updated_at = datetime.utcnow()
                
                # Link underlying evidence events to the incident
                if det.evidence_event_ids:
                    events = db.query(Event).filter(Event.id.in_(det.evidence_event_ids)).all()
                    for ev in events:
                        if ev not in incident.events:
                            incident.events.append(ev)

                # Update consolidated MITRE ATT&CK techniques
                technique_ids = [d.mitre_technique_id for d in incident.detections] + [det.mitre_technique_id]
                incident.mitre_techniques = mitre_mapper.consolidate_techniques(technique_ids)

                # Recompute dynamic risk score & severity
                all_incident_detections = incident.detections + [det]
                score, sev, explanation = risk_engine.calculate_risk(all_incident_detections, incident.mitre_techniques)
                incident.risk_score = score
                incident.severity = sev
                incident.risk_explanation = explanation

                db.commit()
                db.refresh(incident)
                if incident not in impacted_incidents:
                    impacted_incidents.append(incident)
                logger.info(f"Appended detection {det.id} to incident {incident.id} (Risk: {score})")
            else:
                # Create brand new incident
                new_incident = self._create_new_incident(det, db)
                impacted_incidents.append(new_incident)

        return impacted_incidents

    def _find_matching_incident(self, det: Detection, db: Session) -> Optional[Incident]:
        """
        Looks for an active (non-resolved) incident within 30 minutes on the same host or source IP.
        """
        window_start = det.timestamp - timedelta(minutes=30)
        query = db.query(Incident).filter(
            Incident.status.in_(["NEW", "INVESTIGATING", "CONTAINED"]),
            Incident.last_seen >= window_start
        )

        if det.source_ip:
            match = query.filter(
                or_(
                    Incident.hostname == det.hostname,
                    Incident.source_ip == det.source_ip
                )
            ).order_by(Incident.last_seen.desc()).first()
        else:
            match = query.filter(Incident.hostname == det.hostname).order_by(Incident.last_seen.desc()).first()

        return match

    def _create_new_incident(self, det: Detection, db: Session) -> Incident:
        mitre_list = mitre_mapper.consolidate_techniques([det.mitre_technique_id])
        score, sev, explanation = risk_engine.calculate_risk([det], mitre_list)

        title = f"Security Incident: {det.title} on {det.hostname}"
        if det.source_ip:
            title += f" from {det.source_ip}"

        description = (
            f"Automated incident generated following detection rule '{det.rule_id}'. "
            f"Initial trigger: {det.description}"
        )

        incident = Incident(
            title=title,
            description=description,
            severity=sev,
            risk_score=score,
            risk_explanation=explanation,
            confidence=det.confidence,
            status="NEW",
            agent_id=det.agent_id,
            hostname=det.hostname,
            source_ip=det.source_ip,
            username=det.username,
            mitre_techniques=mitre_list,
            first_seen=det.timestamp,
            last_seen=det.timestamp,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Attach detection to incident
        det.incident_id = incident.id
        
        # Attach evidence events
        if det.evidence_event_ids:
            events = db.query(Event).filter(Event.id.in_(det.evidence_event_ids)).all()
            for ev in events:
                incident.events.append(ev)

        db.commit()
        db.refresh(incident)
        logger.warning(f"Created Incident #{incident.id}: {incident.title} (Severity: {sev}, Risk: {score})")
        return incident

correlation_engine = CorrelationEngine()
