import os
import time
import threading
import logging
from typing import Optional
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from ..parsers.audit import AuditParser

logger = logging.getLogger("aisoc-agent.collectors.auditd")

class AuditdCollector:
    """
    Tails Linux auditd logs (/var/log/audit/audit.log).
    Collects syscalls, execve executions, sensitive file access, and kernel audit telemetry.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool):
        self.config = config
        self.spool = spool
        self.log_path = config.audit_log_path
        self.parser = AuditParser(hostname=config.agent_id, agent_id=config.agent_id)
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not os.path.exists(self.log_path):
            logger.info(f"Auditd log ({self.log_path}) not detected. AuditdCollector idle.")
            return

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tail_loop, name="aisoc-audit-tail", daemon=True)
        self._thread.start()
        logger.info(f"AuditdCollector active on {self.log_path}")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("AuditdCollector stopped.")

    def process_raw_line(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return False
        ev = self.parser.parse_line(line)
        if ev:
            self.spool.push(ev.to_dict())
            logger.debug(f"Auditd event captured: {ev.event_type}/{ev.action} - {ev.command or ev.process}")
            return True
        return False

    def _tail_loop(self) -> None:
        current_file = None
        current_inode = None

        while not self._stop_event.is_set():
            if not os.path.exists(self.log_path):
                time.sleep(3.0)
                continue

            try:
                stat_info = os.stat(self.log_path)
                if current_file is None or current_inode != stat_info.st_ino:
                    if current_file:
                        current_file.close()
                    current_file = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    current_file.seek(0, os.SEEK_END)
                    current_inode = stat_info.st_ino

                line = current_file.readline()
                if line:
                    self.process_raw_line(line)
                else:
                    time.sleep(0.25)
            except PermissionError:
                logger.warning(f"Permission denied reading {self.log_path}. Requires root/adm group.")
                time.sleep(10.0)
            except Exception as e:
                logger.debug(f"Auditd tail warning: {e}")
                time.sleep(2.0)

        if current_file:
            try:
                current_file.close()
            except Exception:
                pass
