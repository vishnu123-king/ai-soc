import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import SecurityLog
from backend.rules.ssh_brute_force import SSHBruteForceRule
from backend.rules.successful_login_after_brute_force import SuccessfulLoginAfterBruteForceRule
from backend.rules.suspicious_privilege_escalation import SuspiciousPrivilegeEscalationRule
from backend.rules.suspicious_process import SuspiciousProcessRule
from backend.rules.suspicious_outbound import SuspiciousOutboundConnectionRule
from backend.risk_scoring import calculate_incident_risk_score
from backend.correlation import CorrelationEngine

# In-memory SQLite for testing
@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()

def test_ssh_brute_force_rule(db_session):
    rule = SSHBruteForceRule()
    now = datetime.utcnow()
    attacker_ip = "192.0.2.1"

    # Insert 4 failed logins (should not trigger)
    for i in range(4):
        log = SecurityLog(
            timestamp=now - timedelta(minutes=4 - i),
            hostname="host-01",
            source_ip=attacker_ip,
            event_type="auth",
            action="ssh_login",
            status="failure",
            process="sshd",
            raw_message="Failed password for user admin"
        )
        db_session.add(log)
    db_session.commit()

    # 5th failed login (should trigger)
    fifth_log = SecurityLog(
        timestamp=now,
        hostname="host-01",
        source_ip=attacker_ip,
        event_type="auth",
        action="ssh_login",
        status="failure",
        process="sshd",
        raw_message="Failed password for user admin"
    )
    db_session.add(fifth_log)
    db_session.commit()

    alert = rule.evaluate(fifth_log, db_session)
    assert alert is not None
    assert alert.rule_id == "RULE-001"
    assert alert.mitre_technique_id == "T1110"
    assert "Brute Force" in alert.rule_name

def test_successful_login_after_brute_force(db_session):
    rule = SuccessfulLoginAfterBruteForceRule()
    now = datetime.utcnow()
    attacker_ip = "192.0.2.20"

    # 3 failures followed by 1 success
    for i in range(3):
        log = SecurityLog(
            timestamp=now - timedelta(minutes=10 - i),
            hostname="host-02",
            source_ip=attacker_ip,
            username="victim_user",
            event_type="auth",
            action="ssh_login",
            status="failure",
            raw_message="Failed password for victim_user"
        )
        db_session.add(log)
    db_session.commit()

    success_log = SecurityLog(
        timestamp=now,
        hostname="host-02",
        source_ip=attacker_ip,
        username="victim_user",
        event_type="auth",
        action="ssh_login",
        status="success",
        raw_message="Accepted password for victim_user"
    )
    db_session.add(success_log)
    db_session.commit()

    alert = rule.evaluate(success_log, db_session)
    assert alert is not None
    assert alert.rule_id == "RULE-002"
    assert alert.severity == "CRITICAL"
    assert alert.mitre_technique_id == "T1078"

def test_suspicious_privilege_escalation_rule(db_session):
    rule = SuspiciousPrivilegeEscalationRule()
    now = datetime.utcnow()

    log = SecurityLog(
        timestamp=now,
        hostname="host-03",
        username="john",
        event_type="privilege",
        action="sudo",
        status="success",
        command="sudo /bin/bash",
        raw_message="sudo: john : USER=root ; COMMAND=/bin/bash"
    )
    db_session.add(log)
    db_session.commit()

    alert = rule.evaluate(log, db_session)
    assert alert is not None
    assert alert.rule_id == "RULE-003"
    assert alert.mitre_technique_id == "T1548"

def test_suspicious_process_rule(db_session):
    rule = SuspiciousProcessRule()
    now = datetime.utcnow()

    log = SecurityLog(
        timestamp=now,
        hostname="web-01",
        username="www-data",
        event_type="process",
        action="exec",
        status="success",
        process="bash",
        command="bash -c 'whoami'",
        log_metadata={"parent_process": "nginx", "parent_pid": 100}
    )
    db_session.add(log)
    db_session.commit()

    alert = rule.evaluate(log, db_session)
    assert alert is not None
    assert alert.rule_id == "RULE-004"
    assert alert.mitre_technique_id == "T1059"

def test_suspicious_outbound_connection(db_session):
    rule = SuspiciousOutboundConnectionRule()
    now = datetime.utcnow()

    log = SecurityLog(
        timestamp=now,
        hostname="web-01",
        source_ip="10.0.0.5",
        destination_ip="203.0.113.88",
        event_type="network",
        action="connect",
        status="success",
        command="nc 203.0.113.88 4444",
        log_metadata={"destination_port": 4444}
    )
    db_session.add(log)
    db_session.commit()

    alert = rule.evaluate(log, db_session)
    assert alert is not None
    assert alert.rule_id == "RULE-005"
    assert alert.mitre_technique_id == "T1071"

def test_correlation_and_risk_scoring(db_session):
    corr = CorrelationEngine()
    now = datetime.utcnow()

    from backend.models import Alert
    alert1 = Alert(
        rule_id="RULE-001",
        rule_name="SSH Brute Force Attack",
        severity="HIGH",
        timestamp=now,
        hostname="db-server",
        source_ip="198.51.100.99",
        username="admin",
        mitre_technique_id="T1110",
        description="SSH Brute force",
        evidence=[]
    )
    db_session.add(alert1)
    db_session.commit()

    inc1 = corr.correlate_alert(alert1, db_session)
    assert inc1 is not None
    assert inc1.affected_host == "db-server"
    assert inc1.risk_score > 0

    # Correlate second alert from same host/attacker
    alert2 = Alert(
        rule_id="RULE-002",
        rule_name="Successful Login After Brute Force",
        severity="CRITICAL",
        timestamp=now + timedelta(minutes=2),
        hostname="db-server",
        source_ip="198.51.100.99",
        username="admin",
        mitre_technique_id="T1078",
        description="Successful login after brute force",
        evidence=[]
    )
    db_session.add(alert2)
    db_session.commit()

    inc2 = corr.correlate_alert(alert2, db_session)
    assert inc2.id == inc1.id  # Merged into single incident!
    assert inc2.severity == "CRITICAL"
    assert inc2.risk_score >= 80.0
