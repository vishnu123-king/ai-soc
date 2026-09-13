from datetime import datetime
from backend.app.models.detection import Detection
from backend.app.risk.engine import risk_engine

def test_single_detection_risk_score():
    det = Detection(
        rule_id="RULE-AUTH-001",
        title="SSH Brute Force",
        severity="HIGH",
        confidence=0.9,
        hostname="test-host",
        mitre_technique_id="T1110.001",
        mitre_technique_name="Password Guessing",
        timestamp=datetime.utcnow()
    )
    score, severity, explanation = risk_engine.calculate_risk([det], [{"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}])
    assert 20.0 <= score <= 90.0
    assert "Base severity" in explanation

def test_multi_stage_kill_chain_risk_score():
    det1 = Detection(
        rule_id="RULE-AUTH-001",
        title="SSH Brute Force",
        severity="HIGH",
        confidence=0.9,
        hostname="test-host",
        mitre_technique_id="T1110.001",
        timestamp=datetime.utcnow()
    )
    det2 = Detection(
        rule_id="RULE-PROC-001",
        title="Reverse Shell",
        severity="CRITICAL",
        confidence=0.95,
        hostname="test-host",
        mitre_technique_id="T1059.004",
        timestamp=datetime.utcnow()
    )
    det3 = Detection(
        rule_id="RULE-CRED-001",
        title="Sensitive File Access: /etc/shadow",
        severity="CRITICAL",
        confidence=0.95,
        hostname="test-host",
        mitre_technique_id="T1003.008",
        timestamp=datetime.utcnow()
    )

    mitre_list = [
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
        {"id": "T1003.008", "name": "Shadow", "tactic": "Credential Access"}
    ]

    score, severity, explanation = risk_engine.calculate_risk([det1, det2, det3], mitre_list)
    assert score >= 80.0
    assert severity in ["HIGH", "CRITICAL"]
    assert "Base severity" in explanation
