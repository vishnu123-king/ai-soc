from datetime import datetime
from typing import List
from sqlalchemy.orm import Session
from backend.app.models.event import Event
from backend.app.detection.base import BaseDetectionRule, DetectionResult

class ReverseShellRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-005"
    title = "Interactive Reverse Shell Execution"
    description = "Command line patterns matching standard Linux reverse shell payloads (netcat, bash /dev/tcp, socat, python/perl socket spawn)."
    severity = "CRITICAL"
    confidence = 0.98
    mitre_technique_id = "T1059.004"
    mitre_technique_name = "Command and Scripting Interpreter: Unix Shell"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        cmd = (event.command or "").lower()
        raw = (event.raw_message or "").lower()

        patterns = [
            "/dev/tcp/",
            "nc -e /bin/",
            "nc -c /bin/",
            "ncat -e",
            "socat exec:",
            "python -c 'import socket",
            "python3 -c 'import socket",
            "pty.spawn",
            "mkfifo /tmp/",
            "perl -e 'use socket;",
            "bash -i >& /dev/tcp",
            "sh -i >& /dev/tcp"
        ]

        if any(p in cmd or p in raw for p in patterns):
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title="Interactive Reverse Shell Spawning Detected",
                    description=f"CRITICAL: Attacker reverse shell payload initiated on {event.hostname}: {event.command or event.raw_message}",
                    severity="CRITICAL",
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

class ReconnaissanceToolRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-006"
    title = "Automated Reconnaissance / Privilege Audit Tool"
    description = "Execution of known security audit/reconnaissance scripts or enumeration binaries (linpeas, linenum, nmap, masscan)."
    severity = "HIGH"
    confidence = 0.95
    mitre_technique_id = "T1082"
    mitre_technique_name = "System Information Discovery"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        cmd = (event.command or "").lower()
        proc = (event.process or "").lower()

        recon_signatures = [
            "linpeas.sh", "linenum.sh", "linuxprivchecker", "nmap", "masscan",
            "mimipenguin", "chisel", "frpc", "ngrok"
        ]

        matched = [s for s in recon_signatures if s in cmd or s in proc]
        if matched:
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"Reconnaissance / Penetration Tool Execution: {matched[0]}",
                    description=f"Host enumeration or offensive tunneling binary '{matched[0]}' executed by '{event.username}' on {event.hostname}.",
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
                    metadata={"tool": matched[0], "command": event.command}
                )
            )
        return results

class PersistenceCrontabRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-007"
    title = "Persistence via Scheduled Task or Cron"
    description = "Modification of cron jobs (/etc/cron*, crontab) or systemd service units to establish reboot persistence."
    severity = "MEDIUM"
    confidence = 0.89
    mitre_technique_id = "T1053.003"
    mitre_technique_name = "Scheduled Task/Job: Cron"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        cmd = (event.command or "").lower()
        raw = (event.raw_message or "").lower()
        proc = (event.process or "").lower()

        is_cron = (
            "crontab -e" in cmd or "crontab" in proc or
            "/etc/cron" in cmd or "/etc/cron" in raw or
            "/etc/systemd/system" in cmd or "/etc/systemd/system" in raw
        )

        if is_cron and ("edit" in raw or "write" in raw or "add" in raw or ">" in cmd or "curl" in cmd or "wget" in cmd):
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title="Cron or Systemd Persistence Established",
                    description=f"Potential persistence mechanism installed in cron or systemd: {event.command or event.raw_message}",
                    severity="MEDIUM",
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
