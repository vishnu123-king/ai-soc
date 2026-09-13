import logging
from typing import List
from datetime import timedelta
from sqlalchemy.orm import Session
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.detection.base import BaseDetectionRule, DetectionResult
from backend.app.detection.ssh import SSHBruteForceRule, SSHSuccessAfterFailuresRule
from backend.app.detection.privilege import PrivilegeEscalationRule, SensitiveFileAccessRule
from backend.app.detection.process import ReverseShellRule, ReconnaissanceToolRule, PersistenceCrontabRule
from backend.app.detection.network import SuspiciousOutboundC2Rule, PortScanActivityRule

logger = logging.getLogger("aisoc.detection")

class DetectionEngine:
    def __init__(self):
        self.rules: List[BaseDetectionRule] = [
            SSHBruteForceRule(),
            SSHSuccessAfterFailuresRule(),
            PrivilegeEscalationRule(),
            SensitiveFileAccessRule(),
            ReverseShellRule(),
            ReconnaissanceToolRule(),
            PersistenceCrontabRule(),
            SuspiciousOutboundC2Rule(),
            PortScanActivityRule(),
        ]

    def process_event(self, event: Event, db: Session) -> List[Detection]:
        """Runs all detection rules against a newly ingested event and records detections."""
        new_detections: List[Detection] = []
        for rule in self.rules:
            try:
                results: List[DetectionResult] = rule.evaluate(event, db)
                for res in results:
                    # Check for recent duplicate detection (within 3 minutes) to prevent alert flooding
                    recent_dupe = db.query(Detection).filter(
                        Detection.rule_id == res.rule_id,
                        Detection.hostname == res.hostname,
                        Detection.source_ip == res.source_ip,
                        Detection.timestamp >= res.timestamp - timedelta(minutes=3)
                    ).first()

                    if recent_dupe:
                        # Append evidence without creating duplicate alert
                        curr_evidence = set(recent_dupe.evidence_event_ids or [])
                        curr_evidence.update(res.evidence_event_ids)
                        recent_dupe.evidence_event_ids = list(curr_evidence)
                        db.commit()
                        continue

                    det = Detection(
                        rule_id=res.rule_id,
                        title=res.title,
                        description=res.description,
                        severity=res.severity,
                        confidence=res.confidence,
                        mitre_technique_id=res.mitre_technique_id,
                        mitre_technique_name=res.mitre_technique_name,
                        evidence_event_ids=res.evidence_event_ids,
                        hostname=res.hostname,
                        agent_id=res.agent_id,
                        source_ip=res.source_ip,
                        username=res.username,
                        timestamp=res.timestamp
                    )
                    db.add(det)
                    db.commit()
                    db.refresh(det)
                    new_detections.append(det)
                    logger.warning(f"Detection triggered: [{det.severity}] {det.title} on {det.hostname}")
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}", exc_info=True)

        return new_detections

detection_engine = DetectionEngine()
