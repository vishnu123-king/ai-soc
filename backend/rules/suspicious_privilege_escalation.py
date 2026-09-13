import re
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.base import BaseRule, AlertCandidate

class SuspiciousPrivilegeEscalationRule(BaseRule):
    rule_id = "RULE-003"
    rule_name = "Suspicious Privilege Escalation via Sudo"
    severity = "HIGH"
    mitre_technique_id = "T1548"
    mitre_technique_name = "Abuse Elevation Control Mechanism"

    SHELL_PATTERNS = [
        r"\bsudo\s+(?:su\b|-i\b|-s\b|bash\b|sh\b|zsh\b|dash\b|/bin/bash\b|/bin/sh\b)",
        r"\bsudo\s+.*(?:python|perl|ruby|php|node)\s+-c\s+.*(?:spawn|system|exec|shell)",
        r"\bsudo\s+visudo\b",
        r"\bsudo\s+chmod\s+[0-7]*4755\b",  # SUID bit addition
    ]

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        cmd = (log.command or "").strip()
        raw = (log.raw_message or "").strip()
        action = (log.action or "").lower()
        evt_type = (log.event_type or "").lower()
        proc = (log.process or "").lower()

        full_text = f"{cmd} {raw} {action} {proc}"

        matched_pattern = None
        for pattern in self.SHELL_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                matched_pattern = pattern
                break

        # Also check if action is 'sudo' and process is a shell
        if not matched_pattern:
            if action in ["sudo", "privilege_escalation"] or "sudo" in proc:
                if any(shell in cmd.lower() for shell in ["bash", "/bin/sh", "sh", "zsh", "su -", "/bin/bash"]):
                    matched_pattern = "sudo shell invocation"

        # Check multi-event pattern: recent sudo authorization within 1 minute followed by root shell execution
        if not matched_pattern and proc in ["bash", "sh", "zsh"] and (log.username == "root" or log.status == "success"):
            time_window = log.timestamp - timedelta(minutes=2)
            recent_sudo = (
                db.query(SecurityLog)
                .filter(
                    SecurityLog.hostname == log.hostname,
                    SecurityLog.action.in_(["sudo", "elevation"]),
                    SecurityLog.timestamp >= time_window,
                    SecurityLog.timestamp <= log.timestamp,
                )
                .first()
            )
            if recent_sudo:
                matched_pattern = f"sudo execution by {recent_sudo.username} preceding root shell"

        if matched_pattern:
            evidence_items = [
                {
                    "log_id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "username": log.username,
                    "hostname": log.hostname,
                    "process": log.process,
                    "command": log.command,
                    "raw_message": log.raw_message,
                    "pattern_matched": str(matched_pattern),
                }
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
                description=f"Suspicious privilege escalation detected on {log.hostname}: User '{log.username}' executed privileged shell command: '{log.command or log.raw_message}'",
                evidence=evidence_items,
                confidence=0.92,
            )
        return None
