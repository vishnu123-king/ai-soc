from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session
from backend.app.models.event import Event
from backend.app.detection.base import BaseDetectionRule, DetectionResult

class SuspiciousOutboundC2Rule(BaseDetectionRule):
    rule_id = "AISOC-RULE-008"
    title = "Suspicious Outbound C2 Network Activity"
    description = "Outbound connection attempt directed to standard adversary Command and Control ports (e.g. 4444, 1337, 8888, 31337)."
    severity = "HIGH"
    confidence = 0.91
    mitre_technique_id = "T1071"
    mitre_technique_name = "Application Layer Protocol"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        if event.event_type not in ["network", "socket"]:
            return results

        suspicious_ports = [4444, 1337, 8888, 31337, 6667, 4445, 5555]
        dst_port = event.destination_port
        
        # Also check raw or command if port is parsed there
        if not dst_port and event.raw_message:
            for p in suspicious_ports:
                if f":{p}" in event.raw_message:
                    dst_port = p
                    break

        if dst_port in suspicious_ports:
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"Suspicious Outbound Connection to Port {dst_port}",
                    description=f"Outbound network connection initiated from {event.hostname} to suspicious C2 port {dst_port} (IP: {event.destination_ip or 'Unknown'}).",
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
                    metadata={"dst_port": dst_port, "dst_ip": event.destination_ip}
                )
            )
        return results

class PortScanActivityRule(BaseDetectionRule):
    rule_id = "AISOC-RULE-009"
    title = "Inbound Network Port Sweep"
    description = "Rapid probing across multiple destination ports originating from the same source IP."
    severity = "MEDIUM"
    confidence = 0.86
    mitre_technique_id = "T1046"
    mitre_technique_name = "Network Service Discovery"

    def evaluate(self, event: Event, db: Session) -> List[DetectionResult]:
        results = []
        if event.event_type not in ["network", "socket"] or not event.source_ip:
            return results

        # Check last 5 minutes for distinct destination ports from same IP
        time_window = event.timestamp - timedelta(minutes=5)
        recent_events = db.query(Event).filter(
            Event.source_ip == event.source_ip,
            Event.event_type.in_(["network", "socket"]),
            Event.timestamp >= time_window,
            Event.timestamp <= event.timestamp
        ).all()

        distinct_ports = {e.destination_port for e in recent_events if e.destination_port}
        if len(distinct_ports) >= 5:
            evidence_ids = [e.id for e in recent_events]
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    title=f"Port Scan Activity from {event.source_ip}",
                    description=f"Detected network scan probe across {len(distinct_ports)} ports from {event.source_ip} targeting {event.hostname}.",
                    severity="MEDIUM",
                    confidence=self.confidence,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence_event_ids=evidence_ids[:10],
                    hostname=event.hostname,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    username=event.username,
                    timestamp=event.timestamp,
                    metadata={"scanned_ports_count": len(distinct_ports)}
                )
            )
        return results
