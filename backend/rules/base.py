from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.models import SecurityLog

class AlertCandidate:
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        hostname: str,
        description: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        username: Optional[str] = None,
        mitre_technique_id: Optional[str] = None,
        mitre_technique_name: Optional[str] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.9,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.hostname = hostname
        self.description = description
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.username = username
        self.mitre_technique_id = mitre_technique_id
        self.mitre_technique_name = mitre_technique_name
        self.evidence = evidence or []
        self.confidence = confidence

class BaseRule(ABC):
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique_id: str
    mitre_technique_name: str

    @abstractmethod
    def evaluate(self, log: SecurityLog, db: Session) -> Optional[AlertCandidate]:
        """
        Evaluate the newly ingested log against detection logic.
        Can query recent historical logs within time windows using db.
        Returns AlertCandidate if detection criteria are met, else None.
        """
        pass
