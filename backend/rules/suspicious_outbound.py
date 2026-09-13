import ipaddress
from typing import Optional
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.base import BaseRule, AlertCandidate

class SuspiciousOutboundConnectionRule(BaseRule):
    rule_id = "RULE-005"
    rule_name = "Suspicious Outbound Network Connection"
    severity = "HIGH"
    mitre_technique_id = "T1071"
    mitre_technique_name = "Application Layer Protocol"

    KNOWN_C2_PORTS = {4444, 1337, 6667, 7777, 8888, 9001, 31337, 5555, 8443, 9999}
    SUSPICIOUS_C2_HOSTS = ["c2.", "malware.", "evil.", "pastebin.com/raw", "raw.githubusercontent.com"]

    def is_external_ip(self, ip_str: Optional[str]) -> bool:
        if not ip_str:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str.split(":")[0])
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        except ValueError:
            return False

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        if log.event_type not in ["network", "net", "connect", "process"]:
            return None

        metadata = log.log_metadata or {}
        dest_port = metadata.get("destination_port") or metadata.get("port")
        dest_ip = log.destination_ip or str(metadata.get("destination_ip", ""))
        action = (log.action or "").lower()
        cmd = (log.command or "").lower()
        raw = (log.raw_message or "").lower()

        detected = False
        reason = ""

        # Check port in metadata or extracted from command/destination
        port_num = None
        if dest_port:
            try:
                port_num = int(dest_port)
            except (ValueError, TypeError):
                port_num = None

        if port_num and port_num in self.KNOWN_C2_PORTS:
            detected = True
            reason = f"Outbound connection established to high-risk C2 port {port_num} on {dest_ip}"
        elif any(f":{p}" in dest_ip or f":{p}" in cmd or f":{p}" in raw for p in self.KNOWN_C2_PORTS):
            detected = True
            reason = f"Outbound connection activity matching known C2 or reverse shell port signature"
        elif self.is_external_ip(dest_ip) and ("c2" in raw or "beacon" in raw or "reverse" in raw):
            detected = True
            reason = f"Outbound communication to external host {dest_ip} flagged as command-and-control telemetry"
        elif any(sh_sig in cmd for sh_sig in ["nc -e", "bash -i >& /dev/tcp", "curl -s http", "wget -qO-"]):
            if any(ext in cmd for ext in [".sh", "c2", "sh | bash", "eval"]):
                detected = True
                reason = f"Suspicious script download or reverse shell command targeting external endpoint: {cmd}"

        if detected:
            evidence_items = [
                {
                    "log_id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "hostname": log.hostname,
                    "source_ip": log.source_ip,
                    "destination_ip": dest_ip,
                    "destination_port": port_num,
                    "process": log.process,
                    "command": log.command,
                    "raw_message": log.raw_message,
                    "detection_reason": reason,
                }
            ]
            return AlertCandidate(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                hostname=log.hostname,
                source_ip=log.source_ip,
                destination_ip=dest_ip or log.destination_ip,
                username=log.username,
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                description=f"Suspicious outbound connection on {log.hostname}: {reason}",
                evidence=evidence_items,
                confidence=0.91,
            )
        return None
