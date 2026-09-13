import re
from datetime import datetime, timezone
from aisoc_agent.normalizer.events import NormalizedEvent, normalize_timestamp, create_event

def test_normalize_timestamp_formats():
    # 1. None returns UTC ISO format with trailing Z
    ts1 = normalize_timestamp(None)
    assert ts1.endswith("Z")
    assert "T" in ts1

    # 2. Datetime object
    now = datetime(2026, 9, 12, 14, 30, 0, tzinfo=timezone.utc)
    ts2 = normalize_timestamp(now)
    assert ts2 == "2026-09-12T14:30:00Z"

    # 3. Syslog standard format "Sep 12 08:22:15"
    ts3 = normalize_timestamp("Sep 12 08:22:15")
    assert ts3.endswith("Z")
    assert "08:22:15" in ts3

def test_normalized_event_schema_contract():
    ev = create_event(
        hostname="srv-web-01",
        agent_id="agent-web-01",
        event_type="authentication",
        action="ssh_login",
        status="failed",
        username="root",
        source_ip="198.51.100.25",
        source_port=55123,
        destination_port=22,
        process="/usr/sbin/sshd",
        raw_message="sshd[999]: Failed password for root from 198.51.100.25 port 55123 ssh2",
        metadata={"auth_method": "password"}
    )
    
    d = ev.to_dict()
    assert d["simulation"] is False  # Must strictly be False on real agent
    assert d["hostname"] == "srv-web-01"
    assert d["agent_id"] == "agent-web-01"
    assert d["event_type"] == "authentication"
    assert d["action"] == "ssh_login"
    assert d["status"] == "failed"
    assert d["username"] == "root"
    assert d["source_ip"] == "198.51.100.25"
    assert d["destination_port"] == 22
    assert d["timestamp"].endswith("Z")
