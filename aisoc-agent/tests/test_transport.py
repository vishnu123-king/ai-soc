import pytest
from unittest.mock import MagicMock, patch
from aisoc_agent.config import AgentConfig
from aisoc_agent.transport.client import TransportClient
from aisoc_agent.transport.shipper import BatchShipper
from aisoc_agent.buffer.spool import EventSpool

def test_transport_auth_headers():
    config = AgentConfig()
    config.agent_token = "agt_test_secret_token_12345"
    transport = TransportClient(config)

    headers = transport._get_auth_headers()
    assert headers["Authorization"] == "Bearer agt_test_secret_token_12345"
    assert headers["X-Agent-Token"] == "agt_test_secret_token_12345"
    assert headers["Content-Type"] == "application/json"
    transport.close()

def test_transport_no_token():
    config = AgentConfig()
    config.agent_token = None
    transport = TransportClient(config)

    headers = transport._get_auth_headers()
    assert "Authorization" not in headers
    assert headers["Content-Type"] == "application/json"
    transport.close()

@patch("httpx.Client.post")
def test_transport_batch_shipment_success(mock_post):
    mock_post.return_value = MagicMock(
        status_code=201,
        json=lambda: {"status": "ok", "ingested": 2}
    )

    config = AgentConfig()
    config.agent_token = "agt_test_123"
    transport = TransportClient(config)

    events = [
        {"hostname": "srv-1", "raw_message": "test 1"},
        {"hostname": "srv-1", "raw_message": "test 2"}
    ]
    success, count, err = transport.send_batch(events)

    assert success is True
    assert count == 2
    assert err is None
    transport.close()
