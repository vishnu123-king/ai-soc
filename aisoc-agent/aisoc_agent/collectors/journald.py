import shutil
import subprocess
import threading
import time
import logging
from typing import Optional
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from ..parsers.ssh import SSHParser
from ..parsers.sudo import SudoParser

logger = logging.getLogger("aisoc-agent.collectors.journald")

class JournaldCollector:
    """
    Streams live authentication and security unit logs directly from systemd-journald.
    Serves as the primary or fallback telemetry stream for modern Linux distributions.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool):
        self.config = config
        self.spool = spool
        self.ssh_parser = SSHParser(hostname=config.agent_id, agent_id=config.agent_id)
        self.sudo_parser = SudoParser(hostname=config.agent_id, agent_id=config.agent_id)
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None

    def is_available(self) -> bool:
        return shutil.which("journalctl") is not None

    def start(self) -> None:
        if not self.is_available():
            logger.info("systemd journalctl binary not found. Skipping JournaldCollector.")
            return

        if self._thread and self._thread.is_alive():
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._stream_loop, name="aisoc-journald", daemon=True)
        self._thread.start()
        logger.info("JournaldCollector started monitoring ssh, sshd, and sudo units.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("JournaldCollector stopped.")

    def _stream_loop(self) -> None:
        cmd = [
            "journalctl",
            "-u", "ssh",
            "-u", "sshd",
            "-u", "sudo",
            "-f",
            "-n", "0",
            "--no-tail"
        ]

        while not self._stop_event.is_set():
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1
                )
                
                for line in iter(self._proc.stdout.readline, ''):
                    if self._stop_event.is_set():
                        break
                    line = line.strip()
                    if line:
                        ev = self.ssh_parser.parse_line(line)
                        if not ev:
                            ev = self.sudo_parser.parse_line(line)
                        if ev:
                            self.spool.push(ev.to_dict())
                
                self._proc.stdout.close()
                self._proc.wait()
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.debug(f"journalctl stream restart: {e}")
                    time.sleep(3.0)
