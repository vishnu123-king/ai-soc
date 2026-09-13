import os
import time
import threading
import logging
from typing import Set, Optional
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from ..parsers.network import NetworkParser

logger = logging.getLogger("aisoc-agent.collectors.network")

class NetworkCollector:
    """
    Conservative network telemetry collector inspecting Linux /proc/net/tcp.
    Detects outbound connections, remote C2 attempts, and socket establishment.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool, poll_interval: float = 3.0):
        self.config = config
        self.spool = spool
        self.poll_interval = poll_interval
        self.parser = NetworkParser(hostname=config.agent_id, agent_id=config.agent_id)
        self._known_sockets: Set[str] = set()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._known_sockets = self._scan_active_sockets()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, name="aisoc-net-scan", daemon=True)
        self._thread.start()
        logger.info(f"NetworkCollector started (sample rate: {self.poll_interval}s)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("NetworkCollector stopped.")

    def _scan_active_sockets(self) -> Set[str]:
        sockets = set()
        for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) > 3 and parts[0] != "sl":
                            key = f"{parts[1]}-{parts[2]}-{parts[3]}"
                            sockets.add(key)
            except Exception:
                pass
        return sockets

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.poll_interval):
                break

            current_sockets = set()
            for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
                if not os.path.exists(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) > 3 and parts[0] != "sl":
                                key = f"{parts[1]}-{parts[2]}-{parts[3]}"
                                current_sockets.add(key)
                                if key not in self._known_sockets:
                                    # Newly observed connection -> parse and buffer
                                    ev = self.parser.parse_proc_net_tcp_line(line)
                                    if ev:
                                        self.spool.push(ev.to_dict())
                except Exception as e:
                    logger.debug(f"Network scan error: {e}")

            self._known_sockets = current_sockets
