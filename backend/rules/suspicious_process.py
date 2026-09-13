from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.base import BaseRule, AlertCandidate

class SuspiciousProcessRule(BaseRule):
    rule_id = "RULE-004"
    rule_name = "Suspicious Parent-Child Process Relationship"
    severity = "HIGH"
    mitre_technique_id = "T1059"
    mitre_technique_name = "Command and Scripting Interpreter"

    # Suspicious parent processes that should NOT spawn interactive shells or download tools
    SUSPICIOUS_PARENTS = [
        "nginx", "apache2", "httpd", "caddy", "php-fpm", "tomcat",
        "mysqld", "postgres", "sqlservr.exe", "w3wp.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"
    ]

    SUSPICIOUS_CHILDREN = [
        "bash", "sh", "zsh", "dash", "nc", "ncat", "netcat",
        "cmd.exe", "powershell.exe", "pwsh", "curl", "wget"
    ]

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        if log.event_type not in ["process", "exec", "system"]:
            return None

        metadata = log.log_metadata or {}
        parent = str(metadata.get("parent_process", "")).lower()
        child = str(log.process or "").lower()
        cmd = str(log.command or "").lower()

        # Check explicit parent-child link if provided in metadata
        detected = False
        reason = ""

        if parent:
            for bad_parent in self.SUSPICIOUS_PARENTS:
                if bad_parent in parent:
                    for bad_child in self.SUSPICIOUS_CHILDREN:
                        if bad_child in child or bad_child in cmd:
                            detected = True
                            reason = f"Web server or service daemon '{parent}' spawned suspicious child '{child}'"
                            break
                    if detected:
                        break

        # Also check if raw_message or command contains classic web shell execution patterns
        if not detected:
            if any(p in cmd for p in ["base64 -d | sh", "base64 --decode | bash", "mkfifo /tmp/f", "nc -e /bin/sh", "nc -e /bin/bash"]):
                detected = True
                reason = "Command contains signature of reverse shell or obfuscated execution pipeline"
            elif any(parent_sig in str(log.raw_message).lower() for parent_sig in ["parent: nginx", "parent: apache", "parent: httpd", "parent: php-fpm"]):
                if any(child_sig in child for child_sig in ["bash", "sh", "python"]):
                    detected = True
                    reason = f"Web daemon spawned interactive process: '{child}'"

        if detected:
            evidence_items = [
                {
                    "log_id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "hostname": log.hostname,
                    "username": log.username,
                    "parent_process": parent or "unknown",
                    "child_process": child,
                    "command": log.command,
                    "detection_reason": reason,
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
                description=f"Suspicious process execution on {log.hostname}: {reason}. Command: '{log.command or child}'",
                evidence=evidence_items,
                confidence=0.94,
            )
        return None
