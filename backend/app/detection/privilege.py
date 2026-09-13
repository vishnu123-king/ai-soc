from datetime import datetime
from typing import List
from sqlalchemy.orm import Session
from backend.app.models.event import Event
from backend.app.detection.base import BaseDetectionRule, DetectionResult

class PrivilegeEscalationRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-003"
    title = "Sudo Privilege Escalation Anomaly"
    description = "Suspicious privilege escalation command executed via sudo or failed sudo attempts."
    severity = "HIGH"
    confidence = 0.90
    mitre_technique_id = "T1548.003"
    mitre_technique_name = "Sudo and Sudo Caching"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        cmd = (event.command or "").lower()
        raw = (event.raw_message or "").lower()
        proc = (event.process or "").lower()

        # Check for sudo abuse or root shells spawned via sudo
        is_priv_event = (
            event.event_type in ["privilege", "process"] or
            "sudo" in proc or "sudo" in raw or "sudo" in cmd
        )
        if not is_priv_event:
            return results

        suspicious_cmds = [
            "sudo su", "sudo -i", "sudo /bin/bash", "sudo /bin/sh", 
            "sudoers", "visudo", "sudo chmod 777", "sudo chown root"
        ]

        if event.status in ["failed", "denied"] and ("sudo" in raw or "sudo" in cmd):
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title="Failed Sudo Authentication or Unauthorized Sudo Attempt",
                    description=f"User '{event.username}' failed sudo privilege escalation: {event.command or event.raw_message}",
                    severity="MEDIUM",
                    confidence=0.85,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=[event.id],
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"command": event.command}
                )
            )
        elif any(s in cmd or s in raw for s in suspicious_cmds):
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title="Privileged Root Shell or Sudoers Manipulation via Sudo",
                    description=f"User '{event.username}' executed high-risk privileged operation: {event.command or event.raw_message}",
                    severity="HIGH",
                    confidence=self.confidence,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=[event.id],
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"command": event.command}
                )
            )
        return results

class SensitiveFileAccessRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-004"
    title = "Credential Vault or Sensitive File Access"
    description = "Unauthorized access, modification, or reading of /etc/shadow, /etc/passwd, or private keys."
    severity = "HIGH"
    confidence = 0.92
    mitre_technique_id = "T1003.008"
    mitre_technique_name = "OS Credential Dumping: /etc/passwd and /etc/shadow"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        cmd = (event.command or "").lower()
        raw = (event.raw_message or "").lower()

        targets = ["/etc/shadow", "/etc/gshadow", "id_rsa", "/root/.ssh", "/etc/sudoers"]
        matched_target = None
        for t in targets:
            if t in cmd or t in raw:
                matched_target = t
                break

        if matched_target and ("cat" in cmd or "grep" in cmd or "tail" in cmd or "nano" in cmd or "vi" in cmd or "cp" in cmd or "read" in raw):
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"Sensitive File Access: {matched_target}",
                    description=f"Process '{event.process}' by user '{event.username}' accessed sensitive credential store {matched_target}.",
                    severity="HIGH",
                    confidence=self.confidence,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=[event.id],
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"file": matched_target, "command": event.command}
                )
            )
        return results
