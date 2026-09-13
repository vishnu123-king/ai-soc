import os
import uuid
import shutil
import tempfile
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.connection import SessionLocal
from backend.app.models.agent import Agent
from backend.app.models.event import Event
from backend.app.models.detection import Detection
from backend.app.models.incident import Incident

from aisoc_agent.config import AgentConfig
from aisoc_agent.transport.client import TransportClient
from aisoc_agent.parsers.ssh import SSHParser
from aisoc_agent.buffer.spool import EventSpool
from aisoc_agent.transport.shipper import BatchShipper

@pytest.fixture
def temp_agent_env():
    temp_dir = tempfile.mkdtemp(prefix="aisoc_integration_")
    token_path = os.path.join(temp_dir, "token")
    buffer_dir = os.path.join(temp_dir, "buffer")
    unique_id = f"test-linux-{uuid.uuid4().hex[:8]}"
    
    config = AgentConfig()
    config.agent_id = unique_id
    config.central_soc_url = "http://testserver"
    config.token_path = token_path
    config.buffer_directory = buffer_dir
    
    yield config
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_full_agent_to_central_platform_pipeline(temp_agent_env):
    """
    End-to-End Integration Verification:
    Real Linux Event -> Agent Parser -> Buffer Spool -> Batch Shipper ->
    FastAPI API -> Database -> Detection Engine -> Incident Correlation -> Risk Engine.
    """
    client = TestClient(app)
    config = temp_agent_env

    # 1. Agent Registration via FastAPI TestClient
    reg_payload = {
        "agent_id": config.agent_id,
        "hostname": "test-linux-srv-01.internal",
        "operating_system": "Ubuntu 22.04 LTS (Linux 5.15.0)",
        "ip_address": "192.0.2.77",
        "agent_version": "1.0.0",
        "metadata": {"kernel": "5.15.0", "architecture": "x86_64"}
    }
    reg_res = client.post("/api/agents/register", json=reg_payload)
    assert reg_res.status_code == 201
    token = reg_res.json()["token"]
    assert token is not None and len(token) >= 32
    
    # Save token securely
    config.save_token(token)
    assert os.path.exists(config.token_path)

    # 2. Authenticated Heartbeat
    hb_res = client.post(
        f"/api/agents/{config.agent_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "ok"

    # 3. Simulate Real Linux Auth Log Stream -> Parse into Normalizer
    ssh_parser = SSHParser(hostname=config.agent_id, agent_id=config.agent_id)
    spool = EventSpool(config.buffer_directory)

    base_time = datetime.utcnow()
    raw_auth_logs = [
        "sshd[1001]: Failed password for root from 198.51.100.44 port 40001 ssh2",
        "sshd[1002]: Failed password for admin from 198.51.100.44 port 40002 ssh2",
        "sshd[1003]: Failed password for invalid user oracle from 198.51.100.44 port 40003 ssh2",
        "sshd[1004]: Failed password for root from 198.51.100.44 port 40004 ssh2"
    ]

    for i, line in enumerate(raw_auth_logs):
        ts = (base_time + timedelta(seconds=i * 10)).isoformat() + "Z"
        ev = ssh_parser.parse_line(line, timestamp=ts)
        assert ev is not None
        assert ev.simulation is False
        spool.push(ev.to_dict())

    assert spool.count() == 4

    # 4. Batch Transmit to Central SOC API
    batch_items = spool.peek_batch(limit=50)
    spool_ids = [item[0] for item in batch_items]
    events_payload = [item[1] for item in batch_items]

    batch_res = client.post(
        "/api/events/batch",
        json={"events": events_payload},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert batch_res.status_code == 201
    assert batch_res.json()["ingested"] == 4

    # Spool acknowledgement
    spool.ack_batch(spool_ids)
    assert spool.count() == 0

    # 5. Verify Central Platform Detections & Incidents
    db = SessionLocal()
    
    # Verify Events in DB
    db_events = db.query(Event).filter(Event.agent_id == config.agent_id).all()
    assert len(db_events) == 4

    # Verify SSH Brute Force Detection triggered (RULE-AUTH-001)
    detections = db.query(Detection).filter(Detection.hostname == config.agent_id).all()
    assert len(detections) > 0
    ssh_det = detections[0]
    assert ssh_det.mitre_technique_id == "T1110.001"
    assert ssh_det.severity in ["MEDIUM", "HIGH", "CRITICAL"]

    # Verify Incident creation and correlation
    assert ssh_det.incident_id is not None
    inc = db.query(Incident).filter(Incident.id == ssh_det.incident_id).first()
    assert inc is not None
    assert inc.risk_score > 0
    assert inc.mitre_techniques is not None

    db.close()
