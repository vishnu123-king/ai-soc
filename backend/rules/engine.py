from typing import List
from sqlalchemy.orm import Session
from backend.models import SecurityLog, Alert
from backend.rules.base import BaseRule, AlertCandidate
from backend.rules.ssh_brute_force import SSHBruteForceRule
from backend.rules.successful_login_after_brute_force import SuccessfulLoginAfterBruteForceRule
from backend.rules.suspicious_privilege_escalation import SuspiciousPrivilegeEscalationRule
from backend.rules.suspicious_process import SuspiciousProcessRule
from backend.rules.suspicious_outbound import SuspiciousOutboundConnectionRule

class DetectionEngine:
    def __init__(self):
        self.rules: List[BaseRule] = [
            SSHBruteForceRule(),
            SuccessfulLoginAfterBruteForceRule(),
            SuspiciousPrivilegeEscalationRule(),
            SuspiciousProcessRule(),
            SuspiciousOutboundConnectionRule(),
        ]

    def register_rule(self, rule: BaseRule):
        self.rules.append(rule)

    def evaluate_log(self, log: SecurityLog, db: Session) -> List[Alert]:
        """
        Runs all detection rules on the ingested log.
        Creates and returns any new persisted Alert objects.
        """
        generated_alerts: List[Alert] = []

        for rule in self.rules:
            try:
                candidate: AlertCandidate = rule.evaluate(log, db)
                if candidate:
                    alert = Alert(
                        rule_id=candidate.rule_id,
                        rule_name=candidate.rule_name,
                        severity=candidate.severity,
                        timestamp=log.timestamp,
                        hostname=candidate.hostname,
                        source_ip=candidate.source_ip,
                        destination_ip=candidate.destination_ip,
                        username=candidate.username,
                        mitre_technique_id=candidate.mitre_technique_id,
                        mitre_technique_name=candidate.mitre_technique_name,
                        description=candidate.description,
                        evidence=candidate.evidence,
                    )
                    db.add(alert)
                    db.flush()
                    generated_alerts.append(alert)
            except Exception as e:
                # Rule execution failure should not crash log ingestion pipeline
                print(f"[DetectionEngine] Error in rule {rule.rule_id}: {e}")

        return generated_alerts

detection_engine = DetectionEngine()
