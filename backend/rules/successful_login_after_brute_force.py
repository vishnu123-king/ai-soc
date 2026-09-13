from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.base import BaseRule, AlertCandidate

class SuccessfulLoginAfterBruteForceRule(BaseRule):
    rule_id = "RULE-002"
    rule_name = "Successful Login After Brute Force"
    severity = "CRITICAL"
    mitre_technique_id = "T1078"
    mitre_technique_name = "Valid Accounts"

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        # Must be a SUCCESSFUL login / authentication
        if not (log.event_type in ["auth", "authentication", "ssh"] and log.status in ["success", "successful"]):
            return None
        
        if not log.source_ip:
            return None

        # Look back up to 30 minutes prior to this successful login for failed attempts from same source IP
        time_window = log.timestamp - timedelta(minutes=30)

        failures = (
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

        # If at least 3 previous failures occurred before this success from same IP
        if len(failures) >= 3:
            evidence_items = [
                {
                    "log_id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "username": log.username,
                    "source_ip": log.source_ip,
                    "event": "Successful authentication",
                    "raw_message": log.raw_message,
                }
            ] + [
                {
                    "log_id": f.id,
                    "timestamp": f.timestamp.isoformat(),
                    "username": f.username,
                    "source_ip": f.source_ip,
                    "event": "Prior failed attempt",
                    "raw_message": f.raw_message,
                }
                for f in failures[:5]
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
                description=f"Potential account compromise! User '{log.username}' successfully authenticated via SSH from {log.source_ip} following {len(failures)} failed login attempts.",
                evidence=evidence_items,
                confidence=0.98,
            )
        return None
