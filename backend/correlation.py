from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.models import Alert, Incident
from backend.risk_scoring import calculate_incident_risk_score
from backend.mitre import enrich_mitre_data

CORRELATION_WINDOW_MINUTES = 30

class CorrelationEngine:
    def correlate_alert(self, alert: Alert, db: Session) -> Incident:
        """
        Correlates a newly fired Alert with an existing open Incident,
        or spawns a new Incident if no related incident is within the time window.
        """
        time_threshold = alert.timestamp - timedelta(minutes=CORRELATION_WINDOW_MINUTES)

        # Query candidates among OPEN or INVESTIGATING incidents
        candidate_incidents = (
            db.query(Incident)
            .filter(
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
                Incident.updated_at >= time_threshold,
            )
            .order_by(Incident.updated_at.desc())
            .all()
        )

        matched_incident: Optional[Incident] = None

        for inc in candidate_incidents:
            # 1. Same host and same attacker source IP
            if inc.affected_host == alert.hostname and inc.source_ip and alert.source_ip and inc.source_ip == alert.source_ip:
                matched_incident = inc
                break
            # 2. Same host and same targeted username
            if inc.affected_host == alert.hostname and inc.username and alert.username and inc.username == alert.username:
                matched_incident = inc
                break
            # 3. Same source IP attacking within time window
            if inc.source_ip and alert.source_ip and inc.source_ip == alert.source_ip:
                matched_incident = inc
                break

        if matched_incident:
            alert.incident_id = matched_incident.id
            db.flush()

            # Refresh alerts relationship
            related_alerts = db.query(Alert).filter(Alert.incident_id == matched_incident.id).all()

            # Recalculate deterministic risk score
            score, severity, explanation = calculate_incident_risk_score(related_alerts)
            matched_incident.risk_score = score
            matched_incident.severity = severity
            matched_incident.risk_explanation = explanation
            matched_incident.updated_at = datetime.utcnow()

            # Sync MITRE techniques
            existing_tech_ids = {t["id"] for t in (matched_incident.mitre_techniques or [])}
            if alert.mitre_technique_id and alert.mitre_technique_id not in existing_tech_ids:
                techniques = list(matched_incident.mitre_techniques or [])
                techniques.append(enrich_mitre_data(alert.mitre_technique_id))
                matched_incident.mitre_techniques = techniques

            # Escalate title if critical stage reached
            if alert.severity == "CRITICAL" and not matched_incident.title.startswith("[CRITICAL]"):
                matched_incident.title = f"[CRITICAL] Compromise on {matched_incident.affected_host} - {alert.rule_name}"

            db.commit()
            db.refresh(matched_incident)
            return matched_incident
        else:
            # Create a brand new incident
            techniques = []
            if alert.mitre_technique_id:
                techniques.append(enrich_mitre_data(alert.mitre_technique_id))

            new_incident = Incident(
                title=f"Incident on {alert.hostname}: {alert.rule_name}",
                severity=alert.severity,
                status="OPEN",
                risk_score=50.0,
                risk_explanation=f"Initial detection: {alert.rule_name} triggered.",
                affected_host=alert.hostname,
                source_ip=alert.source_ip,
                username=alert.username,
                mitre_techniques=techniques,
                created_at=alert.timestamp,
                updated_at=alert.timestamp,
            )
            db.add(new_incident)
            db.flush()

            alert.incident_id = new_incident.id
            db.flush()

            # Score single alert incident
            score, severity, explanation = calculate_incident_risk_score([alert])
            new_incident.risk_score = score
            new_incident.severity = severity
            new_incident.risk_explanation = explanation

            db.commit()
            db.refresh(new_incident)
            return new_incident

correlation_engine = CorrelationEngine()
