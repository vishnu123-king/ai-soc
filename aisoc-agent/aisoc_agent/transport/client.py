import logging
import time
import httpx
from typing import Dict, Any, List, Optional, Tuple
from ..config import AgentConfig

logger = logging.getLogger("aisoc-agent.transport")

class TransportClient:
    """
    HTTP/HTTPS communication client for the AI-SOC Central Platform.
    Handles agent enrollment, authenticated telemetry batch shipping, and heartbeats.
    """
    def __init__(self, config: AgentConfig):
        self.config = config
        self.base_url = config.central_soc_url.rstrip("/")
        
        # Configure TLS verification
        verify: Any = config.verify_tls
        if config.ca_cert:
            verify = config.ca_cert
        elif not config.verify_tls:
            verify = False
            logger.warning("TLS verification is DISABLED. Not recommended for production environments.")

        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify,
            timeout=config.request_timeout,
            headers={
                "User-Agent": f"aisoc-agent/{config.agent_version} ({config.agent_id})",
                "Accept": "application/json"
            }
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.agent_token:
            headers["Authorization"] = f"Bearer {self.config.agent_token}"
            headers["X-Agent-Token"] = self.config.agent_token
        return headers

    def ping(self) -> bool:
        """Verifies basic reachability of the Central SOC server."""
        try:
            r = self._client.get("/api/rules", timeout=5.0)
            return r.status_code in [200, 401, 403]
        except Exception as e:
            logger.debug(f"Central SOC ping failed: {e}")
            return False

    def register(self, metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Enrolls this endpoint with the Central SOC platform via POST /api/agents/register.
        Returns: (success, token, error_message)
        """
        meta = metadata or self.config.get_system_metadata()
        payload = {
            "agent_id": self.config.agent_id,
            "hostname": meta.get("hostname", self.config.agent_id),
            "operating_system": meta.get("operating_system", "Linux"),
            "ip_address": meta.get("primary_ip", "127.0.0.1"),
            "agent_version": self.config.agent_version,
            "enrollment_key": self.config.enrollment_key,
            "metadata": meta
        }

        try:
            logger.info(f"Registering agent '{self.config.agent_id}' with Central SOC at {self.base_url}...")
            res = self._client.post(
                "/api/agents/register",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            if res.status_code in [200, 201]:
                data = res.json()
                token = data.get("token")
                if token:
                    self.config.save_token(token)
                    logger.info("Agent registration succeeded. Bearer token secured.")
                    return True, token, None
                else:
                    return False, None, "Server did not return an authentication token."
            else:
                err = f"Registration rejected (HTTP {res.status_code}): {res.text}"
                logger.error(err)
                return False, None, err
        except Exception as e:
            err = f"Registration connection error: {e}"
            logger.error(err)
            return False, None, err

    def send_batch(self, events: List[Dict[str, Any]]) -> Tuple[bool, int, Optional[str]]:
        """
        Transmits a batch of normalized events via POST /api/events/batch.
        Returns: (success, ingested_count, error_message)
        """
        if not events:
            return True, 0, None

        payload = {"events": events}
        try:
            res = self._client.post(
                "/api/events/batch",
                json=payload,
                headers=self._get_auth_headers()
            )
            if res.status_code in [200, 201]:
                data = res.json()
                ingested = data.get("ingested", len(events))
                return True, ingested, None
            elif res.status_code in [401, 403]:
                err = f"Authentication failed (HTTP {res.status_code}). Check agent token."
                logger.error(err)
                return False, 0, err
            else:
                err = f"Batch ingestion failed (HTTP {res.status_code}): {res.text}"
                return False, 0, err
        except Exception as e:
            err = f"Transport network error during batch upload: {e}"
            return False, 0, err

    def send_single_event(self, event: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Transmits a single normalized event via POST /api/events.
        Returns: (success, response_json, error_message)
        """
        try:
            res = self._client.post(
                "/api/events",
                json=event,
                headers=self._get_auth_headers()
            )
            if res.status_code in [200, 201]:
                return True, res.json(), None
            elif res.status_code in [401, 403]:
                err = f"Authentication failed (HTTP {res.status_code})"
                return False, None, err
            else:
                err = f"Single event ingestion failed (HTTP {res.status_code}): {res.text}"
                return False, None, err
        except Exception as e:
            err = f"Transport network error: {e}"
            return False, None, err

    def send_heartbeat(self) -> Tuple[bool, Optional[str]]:
        """
        Transmits keep-alive heartbeat via POST /api/agents/{agent_id}/heartbeat.
        Returns: (success, error_message)
        """
        try:
            res = self._client.post(
                f"/api/agents/{self.config.agent_id}/heartbeat",
                headers=self._get_auth_headers()
            )
            if res.status_code == 200:
                return True, None
            elif res.status_code in [401, 403]:
                return False, f"Heartbeat unauthorized (HTTP {res.status_code})"
            elif res.status_code == 404:
                return False, "Agent ID not registered on server. Re-registration required."
            else:
                return False, f"Heartbeat failed (HTTP {res.status_code}): {res.text}"
        except Exception as e:
            return False, f"Heartbeat connection error: {e}"

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
