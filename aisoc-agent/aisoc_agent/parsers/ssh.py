import re
from typing import Optional, Tuple
from ..normalizer.events import NormalizedEvent, create_event

# Regex patterns for SSH telemetry
RE_FAILED_PASSWORD = re.compile(
    r'sshd(?:\[\d+\])?:\s+Failed\s+(?:password|none|publickey|keyboard-interactive)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F:\.]+)\s+port\s+(\d+)\s+ssh2',
    re.IGNORECASE
)

RE_INVALID_USER = re.compile(
    r'sshd(?:\[\d+\])?:\s+Invalid\s+user\s+(\S+)\s+from\s+([0-9a-fA-F:\.]+)\s+port\s+(\d+)',
    re.IGNORECASE
)

RE_ACCEPTED_LOGIN = re.compile(
    r'sshd(?:\[\d+\])?:\s+Accepted\s+(password|publickey|keyboard-interactive)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F:\.]+)\s+port\s+(\d+)\s+ssh2',
    re.IGNORECASE
)

RE_PAM_FAILURE = re.compile(
    r'sshd(?:\[\d+\])?:\s+pam_unix\(sshd:auth\):\s+authentication\s+failure;\s+logname=.*?\s+rhost=([0-9a-fA-F:\.]+)(?:\s+user=(\S+))?',
    re.IGNORECASE
)

RE_SESSION_OPENED = re.compile(
    r'sshd(?:\[\d+\])?:\s+pam_unix\(sshd:session\):\s+session\s+opened\s+for\s+user\s+(\S+)\s+by\s+\(uid=\d+\)',
    re.IGNORECASE
)

class SSHParser:
    """
    Parser for OpenSSH server logs (auth.log / journald).
    Extracts authentication events, credentials, and connection metadata.
    """
    def __init__(self, hostname: str, agent_id: Optional[str] = None):
        self.hostname = hostname
        self.agent_id = agent_id

    def parse_line(self, line: str, timestamp: Optional[str] = None) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line or "sshd" not in line:
            return None

        # 1. Failed Password
        match = RE_FAILED_PASSWORD.search(line)
        if match:
            username, src_ip, src_port = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="authentication",
                action="ssh_login",
                status="failed",
                username=username,
                source_ip=src_ip,
                source_port=int(src_port),
                destination_port=22,
                process="/usr/sbin/sshd",
                raw_message=line,
                metadata={"service": "sshd", "auth_protocol": "ssh2", "failure_reason": "bad_credentials"}
            )

        # 2. Invalid User probe
        match = RE_INVALID_USER.search(line)
        if match:
            username, src_ip, src_port = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="authentication",
                action="ssh_login",
                status="failed",
                username=username,
                source_ip=src_ip,
                source_port=int(src_port),
                destination_port=22,
                process="/usr/sbin/sshd",
                raw_message=line,
                metadata={"service": "sshd", "failure_reason": "invalid_user"}
            )

        # 3. Accepted SSH Login
        match = RE_ACCEPTED_LOGIN.search(line)
        if match:
            auth_method, username, src_ip, src_port = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="authentication",
                action="ssh_login",
                status="success",
                username=username,
                source_ip=src_ip,
                source_port=int(src_port),
                destination_port=22,
                process="/usr/sbin/sshd",
                raw_message=line,
                metadata={"service": "sshd", "auth_method": auth_method, "auth_protocol": "ssh2"}
            )

        # 4. PAM Unix Auth Failure
        match = RE_PAM_FAILURE.search(line)
        if match:
            src_ip, username = match.groups()
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="authentication",
                action="ssh_login",
                status="failed",
                username=username or "unknown",
                source_ip=src_ip,
                destination_port=22,
                process="/usr/sbin/sshd",
                raw_message=line,
                metadata={"service": "sshd", "pam_module": "pam_unix"}
            )

        return None
