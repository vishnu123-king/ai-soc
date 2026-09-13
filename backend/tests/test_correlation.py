import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database.connection import Base
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.models.incident import Incident
from backend.app.correlation.engine import correlation_engine

TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_incident_correlation_same_host():
    db = TestingSessionLocal()
    now = datetime.utcnow()

    # Create first detection
    det1 = Detection(
        rule_id="RULE-AUTH-001",
        title="SSH Brute Force",
        description="Multiple failed SSH authentication attempts detected from source IP.",
        severity="HIGH",
        confidence=0.9,
        hostname="web-prod-01",
        source_ip="198.51.100.50",
        mitre_technique_id="T1110.001",
        mitre_technique_name="Password Guessing",
        timestamp=now
    )
    db.add(det1)
    db.commit()

    incidents = correlation_engine.correlate_detections([det1], db)
    assert len(incidents) == 1
    inc1_id = incidents[0].id

    # Create second detection 5 minutes later on the same host
    det2 = Detection(
        rule_id="RULE-PROC-001",
        title="Reverse Shell",
        description="Interactive bash socket redirection spawned in background.",
        severity="CRITICAL",
        confidence=0.95,
        hostname="web-prod-01",
        source_ip="198.51.100.50",
        mitre_technique_id="T1059.004",
        mitre_technique_name="Unix Shell",
        timestamp=now + timedelta(minutes=5)
    )
    db.add(det2)
    db.commit()

    incidents2 = correlation_engine.correlate_detections([det2], db)
    assert len(incidents2) == 1
    # Should correlate to the SAME existing incident
    assert incidents2[0].id == inc1_id
    assert incidents2[0].severity == "CRITICAL"

    db.close()
