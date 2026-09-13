from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.base import BaseRule, AlertCandidate

class SSHBruteForceRule(BaseRule):
    rule_id = "RULE-001"
    rule_name = "SSH Brute Force Attack"
    severity = "HIGH"
    mitre_technique_id = "T1110"
    mitre_technique_name = "Brute Force"

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        # Only evaluate on failed authentication/login events from a source IP
        if not (log.event_type in ["auth", "authentication", "ssh"] and log.status in ["failure", "failed", "denied"]):
            return None
        
        if not log.source_ip:
            return None

        # Check if this is an SSH or login event
        msg = (log.raw_message or "").lower()
        action = (log.action or "").lower()
        proc = (log.process or "").lower()
        if not ("ssh" in msg or "ssh" in action or "ssh" in proc or "login" in action or "login" in msg):
            return None

        time_window = log.timestamp - timedelta(minutes=5)

        # Count failed logins from same source_ip in the past 5 minutes
        recent_failures = (
            db.query(SecurityLog)
            .filter(
                SecurityLog.source_ip == log.source_ip,
                SecurityLog.status.in_(["failure", "failed", "denied"]),
                SecurityLog.timestamp >= time_window,
                SecurityLog.timestamp <= log.timestamp,
            )
            .order_by(SecurityLog.timestamp.desc())
            .all()
        )

        if len(recent_failures) >= 5:
            evidence_items = [
                {
                    "log_id": item.id,
                    "timestamp": item.timestamp.isoformat(),
                    "username": item.username,
                    "source_ip": item.source_ip,
                    "raw_message": item.raw_message,
                }
                for item in recent_failures[:8]
            ]
            return AlertCandidate(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                hostname=log.hostname,
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                username=log.username,
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                description=f"Detected SSH Brute Force: {len(recent_failures)} failed login attempts from source IP {log.source_ip} within 5 minutes.",
                evidence=evidence_items,
                confidence=0.95,
            )
        return None
