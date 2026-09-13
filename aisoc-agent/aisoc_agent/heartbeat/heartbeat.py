import time
import threading
import logging
from typing import Optional
from ..config import AgentConfig
from ..transport.client import TransportClient

logger = logging.getLogger("aisoc-agent.heartbeat")

class HeartbeatManager:
    """
    Background worker that transmits periodic keep-alive heartbeats to the Central SOC.
    """
    def __init__(self, config: AgentConfig, transport: TransportClient):
        self.config = config
        self.transport = transport
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_heartbeat_time: Optional[float] = None
        self.last_success: bool = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="aisoc-heartbeat", daemon=True)
        self._thread.start()
        logger.info(f"Heartbeat service started (interval: {self.config.heartbeat_interval}s)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Heartbeat service stopped.")

    def _run_loop(self) -> None:
        # Initial heartbeat immediately on boot
        self._send_one()
        
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.config.heartbeat_interval):
                break
            self._send_one()

    def _send_one(self) -> None:
        if not self.config.agent_token:
            logger.debug("Skipping heartbeat: agent token not configured.")
            return

        success, err = self.transport.send_heartbeat()
        self.last_heartbeat_time = time.time()
        self.last_success = success
        if success:
            logger.debug(f"Heartbeat sent successfully for agent '{self.config.agent_id}'.")
        else:
            logger.warning(f"Heartbeat warning for agent '{self.config.agent_id}': {err}")
