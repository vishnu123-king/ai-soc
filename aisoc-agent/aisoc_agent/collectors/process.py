import os
import pwd
import time
import threading
import logging
from typing import Set, Optional, Dict, Tuple
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from ..normalizer.events import create_event

logger = logging.getLogger("aisoc-agent.collectors.process")

class ProcessCollector:
    """
    Conservative, lightweight Linux process collector using /proc filesystem.
    Tracks newly spawned process execution lifecycles with minimal CPU overhead.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool, poll_interval: float = 2.0):
        self.config = config
        self.spool = spool
        self.poll_interval = poll_interval
        self._known_pids: Set[int] = set()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        # Initialize known PIDs on boot so we don't spam events for existing system daemons
        self._known_pids = self._get_current_pids()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, name="aisoc-proc-scan", daemon=True)
        self._thread.start()
        logger.info(f"ProcessCollector started (tracked {len(self._known_pids)} initial PIDs, sample rate: {self.poll_interval}s)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("ProcessCollector stopped.")

    def _get_current_pids(self) -> Set[int]:
        pids = set()
        if not os.path.exists("/proc"):
            return pids
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pids.add(int(entry))
        except Exception:
            pass
        return pids

    def _get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        pid_dir = f"/proc/{pid}"
        if not os.path.exists(pid_dir):
            return None

        cmdline_path = f"{pid_dir}/cmdline"
        exe_path = f"{pid_dir}/exe"
        status_path = f"{pid_dir}/status"

        try:
            # 1. Command line
            cmd = ""
            if os.path.exists(cmdline_path):
                with open(cmdline_path, "rb") as f:
                    raw_cmd = f.read()
                    cmd = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()

            # 2. Executable path
            exe = ""
            try:
                exe = os.readlink(exe_path)
            except Exception:
                pass

            # 3. User & Parent PID
            username = "unknown"
            ppid = None
            if os.path.exists(status_path):
                with open(status_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            parts = line.split()
                            if len(parts) > 1 and parts[1].isdigit():
                                uid = int(parts[1])
                                try:
                                    username = pwd.getpwuid(uid).pw_name
                                except Exception:
                                    username = str(uid)
                        elif line.startswith("PPid:"):
                            parts = line.split()
                            if len(parts) > 1 and parts[1].isdigit():
                                ppid = int(parts[1])

            if not cmd and not exe:
                return None

            return {
                "pid": pid,
                "ppid": ppid,
                "command": cmd or exe,
                "process": exe or cmd.split()[0] if cmd else "unknown",
                "username": username
            }
        except Exception:
            return None

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.poll_interval):
                break

            current_pids = self._get_current_pids()
            new_pids = current_pids - self._known_pids

            for pid in new_pids:
                details = self._get_process_details(pid)
                if details:
                    ev = create_event(
                        hostname=self.config.agent_id,
                        agent_id=self.config.agent_id,
                        event_type="process",
                        action="execve",
                        status="success",
                        process=details["process"],
                        command=details["command"],
                        username=details["username"],
                        raw_message=f"Process spawned [PID {pid} PPID {details['ppid']}] user={details['username']}: {details['command']}",
                        metadata={"pid": pid, "ppid": details["ppid"]}
                    )
                    self.spool.push(ev.to_dict())

            # Update known PIDs (retaining existing alive PIDs)
            self._known_pids = current_pids
