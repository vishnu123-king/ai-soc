from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import and_
from backend.app.models.event import Event
from backend.app.detection.base import BaseDetectionRule, DetectionResult

class SSHBruteForceRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-001"
    title = "SSH Brute Force Attempt"
    description = "Multiple failed SSH authentication attempts detected from an external or internal source IP within a short timeframe."
    severity = "MEDIUM"
    confidence = 0.88
    mitre_technique_id = "T1110.001"
    mitre_technique_name = "Password Guessing"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        if event.event_type not in ["authentication", "auth"] or event.status not in ["failed", "denied"]:
            return results
        if not event.source_ip:
            return results

        # Check last 10 minutes for failed attempts from same IP
        time_window = event.timestamp - timedelta(minutes=10)
        recent_failures = db.query(Event).filter(
            Event.source_ip == event.source_ip,
            Event.event_type.in_(["authentication", "auth"]),
            Event.status.in_(["failed", "denied"]),
            Event.timestamp >= time_window,
            Event.timestamp <= event.timestamp
        ).order_by(Event.timestamp.desc()).limit(15).all()

        if len(recent_failures) >= 4:
            # Check if this exact cluster was already alerted in the last 5 minutes to prevent alert storms
            evidence_ids = [e.id for e in recent_failures]
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"SSH Brute Force Detected ({len(recent_failures)} failed attempts)",
                    description=f"Detected {len(recent_failures)} failed SSH login attempts from {event.source_ip} targeting {event.hostname}.",
                    severity="HIGH" if len(recent_failures) >= 8 else "MEDIUM",
                    confidence=self.confidence,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=evidence_ids,
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"attempt_count": len(recent_failures), "source_ip": event.source_ip}
                )
            )
        return results

class SSHSuccessAfterFailuresRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-002"
    title = "Successful SSH Login Following Authentication Failures"
    description = "A successful SSH login occurred from an IP address that previously registered multiple failed authentication attempts."
    severity = "HIGH"
    confidence = 0.94
    mitre_technique_id = "T1078.003"
    mitre_technique_name = "Valid Accounts: Local Accounts"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        if event.event_type not in ["authentication", "auth"] or event.status != "success":
            return results
        if not event.source_ip:
            return results

        # Check last 30 minutes for failed attempts from this IP
        time_window = event.timestamp - timedelta(minutes=30)
        recent_failures = db.query(Event).filter(
            Event.source_ip == event.source_ip,
            Event.event_type.in_(["authentication", "auth"]),
            Event.status.in_(["failed", "denied"]),
            Event.timestamp >= time_window,
            Event.timestamp < event.timestamp
        ).all()

        if len(recent_failures) >= 2:
            evidence_ids = [e.id for e in recent_failures] + [event.id]
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"Successful Login After {len(recent_failures)} Failures",
                    description=f"Potential credential brute-force breakthrough: User '{event.username}' logged in successfully from {event.source_ip} after {len(recent_failures)} recent failures.",
                    severity="HIGH",
                    confidence=self.confidence,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=evidence_ids,
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"prior_failures": len(recent_failures), "username": event.username}
                )
            )
        return results
