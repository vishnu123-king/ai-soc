import re
from typing import Optional
from ..normalizer.events import NormalizedEvent, create_event

# Sudo regex patterns
RE_SUDO_COMMAND = re.compile(
    r'sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)',
    re.IGNORECASE
)

RE_SUDO_INCORRECT_PW = re.compile(
    r'sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+(\d+)\s+incorrect password attempt',
    re.IGNORECASE
)

RE_SUDO_NOT_IN_SUDOERS = re.compile(
    r'sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+user NOT in sudoers\s+;\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)',
    re.IGNORECASE
)

RE_SUDO_AUTH_FAILURE = re.compile(
    r'sudo(?:\[\d+\])?:\s+pam_unix\(sudo:auth\):\s+authentication failure;\s+logname=(\S*)\s+uid=(\d+)\s+euid=(\d+)\s+tty=(\S*)\s+ruser=(\S*)\s+rhost=(\S*)\s+user=(\S*)',
    re.IGNORECASE
)

# SU regex patterns
RE_SU_SUCCESS = re.compile(
    r'su(?:\[\d+\])?:\s+Successful su for (\S+) by (\S+)',
    re.IGNORECASE
)

RE_SU_FAILED = re.compile(
    r'su(?:\[\d+\])?:\s+FAILED SU \(to (\S+)\) (\S+) on (\S+)',
    re.IGNORECASE
)

RE_SU_AUTH_FAILURE = re.compile(
    r'su(?:\[\d+\])?:\s+pam_unix\(su(?:-l)?:auth\):\s+authentication failure;\s+logname=(\S*)\s+uid=(\d+).*?\s+user=(\S*)',
    re.IGNORECASE
)

class SudoParser:
    """
    Parser for Sudo and SU privilege escalation logs.
    """
    def __init__(self, hostname: str, agent_id: Optional[str] = None):
        self.hostname = hostname
        self.agent_id = agent_id

    def parse_line(self, line: str, timestamp: Optional[str] = None) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line or ("sudo" not in line and "su" not in line):
            return None

        # 1. Sudo Successful Command Execution
        match = RE_SUDO_COMMAND.search(line)
        if match:
            invoking_user, tty, pwd, target_user, command = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="sudo_exec",
                status="success",
                username=invoking_user,
                command=command.strip(),
                process="/usr/bin/sudo",
                raw_message=line,
                metadata={
                    "tty": tty,
                    "pwd": pwd,
                    "target_user": target_user
                }
            )

        # 2. Sudo NOT in sudoers attempt
        match = RE_SUDO_NOT_IN_SUDOERS.search(line)
        if match:
            invoking_user, tty, pwd, target_user, command = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="sudo_exec",
                status="denied",
                username=invoking_user,
                command=command.strip(),
                process="/usr/bin/sudo",
                raw_message=line,
                metadata={
                    "reason": "user_not_in_sudoers",
                    "tty": tty,
                    "pwd": pwd,
                    "target_user": target_user
                }
            )

        # 3. Sudo Incorrect Password
        match = RE_SUDO_INCORRECT_PW.search(line)
        if match:
            invoking_user, attempts = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="sudo_auth",
                status="failed",
                username=invoking_user,
                process="/usr/bin/sudo",
                raw_message=line,
                metadata={"attempts": int(attempts), "reason": "incorrect_password"}
            )

        # 4. Sudo PAM Auth Failure
        match = RE_SUDO_AUTH_FAILURE.search(line)
        if match:
            logname, uid, euid, tty, ruser, rhost, user = match.groups()
            username = user or logname or "unknown"
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="sudo_auth",
                status="failed",
                username=username,
                process="/usr/bin/sudo",
                raw_message=line,
                metadata={"uid": uid, "euid": euid, "tty": tty}
            )

        # 5. SU Successful
        match = RE_SU_SUCCESS.search(line)
        if match:
            target_user, invoking_user = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="su_exec",
                status="success",
                username=invoking_user,
                process="/usr/bin/su",
                raw_message=line,
                metadata={"target_user": target_user}
            )

        # 6. SU Failed
        match = RE_SU_FAILED.search(line)
        if match:
            target_user, invoking_user, tty = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="su_exec",
                status="failed",
                username=invoking_user,
                process="/usr/bin/su",
                raw_message=line,
                metadata={"target_user": target_user, "tty": tty}
            )

        # 7. SU PAM failure
        match = RE_SU_AUTH_FAILURE.search(line)
        if match:
            logname, uid, user = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="su_exec",
                status="failed",
                username=user or logname or "unknown",
                process="/usr/bin/su",
                raw_message=line,
                metadata={"uid": uid}
            )

        return None
