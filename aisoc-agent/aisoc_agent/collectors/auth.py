import os
import time
import threading
import logging
from typing import Optional
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from ..parsers.ssh import SSHParser
from ..parsers.sudo import SudoParser

logger = logging.getLogger("aisoc-agent.collectors.auth")

class AuthLogCollector:
    """
    Tails Linux authentication logs (/var/log/auth.log, /var/log/secure).
    Detects SSH brute force attempts, logins, and sudo executions.
    Supports file inode rotation detection.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool):
        self.config = config
        self.spool = spool
        self.log_path = self._find_auth_log()
        self.ssh_parser = SSHParser(hostname=config.agent_id, agent_id=config.agent_id)
        self.sudo_parser = SudoParser(hostname=config.agent_id, agent_id=config.agent_id)
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _find_auth_log(self) -> str:
        candidates = [
            self.config.auth_log_path,
            "/var/log/auth.log",
            "/var/log/secure"
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return self.config.auth_log_path

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tail_loop, name="aisoc-auth-tail", daemon=True)
        self._thread.start()
        logger.info(f"AuthLogCollector started on source: {self.log_path}")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("AuthLogCollector stopped.")

    def process_raw_line(self, line: str) -> bool:
        """Parses a single auth log line and buffers if a match is found."""
        line = line.strip()
        if not line:
            return False

        # Attempt SSH parsing
        ev = self.ssh_parser.parse_line(line)
        if not ev:
            # Attempt Sudo parsing
            ev = self.sudo_parser.parse_line(line)

        if ev:
            self.spool.push(ev.to_dict())
            logger.debug(f"Auth event captured: {ev.event_type}/{ev.action} - {ev.status} ({ev.username or 'anon'})")
            return True
        return False

    def _tail_loop(self) -> None:
        if not os.path.exists(self.log_path):
            logger.warning(f"Auth log file {self.log_path} does not exist. Waiting for creation...")

        current_file = None
        current_inode = None

        while not self._stop_event.is_set():
            if not os.path.exists(self.log_path):
                time.sleep(2.0)
                continue

            try:
                stat_info = os.stat(self.log_path)
                # Check if file rotated or needs opening
                if current_file is None or current_inode != stat_info.st_ino:
                    if current_file:
                        current_file.close()
                    current_file = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    # On initial start, seek to end of file to prevent replaying stale history
                    current_file.seek(0, os.SEEK_END)
                    current_inode = stat_info.st_ino
                    logger.info(f"Opened auth log {self.log_path} (inode: {current_inode})")

                line = current_file.readline()
                if line:
                    self.process_raw_line(line)
                else:
                    # No new line, sleep briefly
                    time.sleep(0.2)
            except PermissionError:
                logger.error(f"Permission denied reading {self.log_path}. Check agent user groups or permissions.")
                time.sleep(5.0)
            except Exception as e:
                logger.error(f"Error reading auth log: {e}")
                time.sleep(2.0)

        if current_file:
            try:
                current_file.close()
            except Exception:
                pass
