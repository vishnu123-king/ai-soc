import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_api_health():
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "active_incidents" in data

def test_rules_catalog():
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) >= 6
    rule_ids = [r["rule_id"] for r in rules]
    assert any("RULE" in rid for rid in rule_ids)

def test_agent_registration_and_heartbeat():
    payload = {
        "agent_id": "test-agent-99",
        "hostname": "test-agent-host",
        "operating_system": "Linux Test",
        "ip_address": "10.0.99.1",
        "agent_version": "1.0.0"
    }
    res = client.post("/api/agents/register", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["agent_id"] == "test-agent-99"
    assert "token" in data
    token = data["token"]

    # Heartbeat
    hb_res = client.post(
        "/api/agents/test-agent-99/heartbeat",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert hb_res.status_code == 200

def test_simulation_run():
    sim_payload = {
        "scenario": "ssh_brute_force",
        "hostname": "sim-test-host",
        "agent_id": "sim-test-agent",
        "attacker_ip": "198.51.100.77"
    }
    res = client.post("/api/simulation/run", json=sim_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "simulation_completed"
    assert data["events_ingested"] >= 6
