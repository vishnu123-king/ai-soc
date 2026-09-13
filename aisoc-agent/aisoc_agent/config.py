import os
import sys
import socket
import platform
import uuid
import stat
from pathlib import Path
from typing import Dict, Any, Optional

class AgentConfig:
    """
    Configuration manager for aisoc-agent.
    Loads settings from configuration file, environment variables, and defaults.
    Manages secure token storage on the Linux filesystem.
    """
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._find_default_config_file()
        self._raw_config: Dict[str, str] = {}
        if self.config_file and os.path.exists(self.config_file):
            self._load_file(self.config_file)

        # Core Central SOC Connection Settings
        self.central_soc_url = self._get_opt(
            "CENTRAL_SOC_URL",
            default="http://localhost:3000"
        ).rstrip("/")

        # Agent Identity
        agent_id_opt = self._get_opt("AGENT_ID", default="")
        if not agent_id_opt or len(agent_id_opt.strip()) < 3:
            self.agent_id = self._get_default_agent_id()
        else:
            self.agent_id = agent_id_opt.strip()
        self.agent_version = self._get_opt("AGENT_VERSION", default="1.0.0")
        self.enrollment_key = self._get_opt("AGENT_ENROLLMENT_KEY", default=None)

        # Timing & Batching
        self.heartbeat_interval = int(self._get_opt("HEARTBEAT_INTERVAL", default="30"))
        self.batch_size = int(self._get_opt("BATCH_SIZE", default="50"))
        self.batch_interval = float(self._get_opt("BATCH_INTERVAL", default="5.0"))
        self.request_timeout = float(self._get_opt("REQUEST_TIMEOUT", default="10.0"))

        # TLS & Security
        verify_tls_raw = self._get_opt("VERIFY_TLS", default="true").lower()
        self.verify_tls = verify_tls_raw in ["1", "true", "yes", "on"]
        self.ca_cert = self._get_opt("CA_CERT", default=None)

        # File Paths & Permissions
        default_var_dir = "/var/lib/aisoc" if os.geteuid() == 0 or os.access("/var/lib", os.W_OK) else os.path.abspath("./var_aisoc")
        self.buffer_directory = self._get_opt("BUFFER_DIRECTORY", default=os.path.join(default_var_dir, "buffer"))
        self.token_path = self._get_opt("TOKEN_PATH", default=os.path.join(default_var_dir, "token"))
        self.log_level = self._get_opt("LOG_LEVEL", default="INFO").upper()

        # Telemetry Sources
        self.auth_log_path = self._get_opt("AUTH_LOG_PATH", default="/var/log/auth.log")
        self.audit_log_path = self._get_opt("AUDIT_LOG_PATH", default="/var/log/audit/audit.log")

        # Load token from token_path if present, else fallback to env/config
        self.agent_token = self._load_persisted_token() or self._get_opt("AGENT_TOKEN", default=None)

    def _find_default_config_file(self) -> Optional[str]:
        candidates = [
            "/etc/aisoc/agent.conf",
            os.path.expanduser("~/.config/aisoc/agent.conf"),
            os.path.abspath("./config/agent.conf"),
            os.path.abspath("./agent.conf")
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def _load_file(self, filepath: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip().upper()
                        v = v.strip().strip('"').strip("'")
                        self._raw_config[k] = v
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load config file {filepath}: {e}\n")

    def _get_opt(self, key: str, default: Any = None) -> Any:
        # Environment variables take precedence over config file
        if key in os.environ and os.environ[key].strip() != "":
            return os.environ[key].strip()
        if key in self._raw_config and self._raw_config[key].strip() != "":
            return self._raw_config[key].strip()
        return default

    def _get_default_agent_id(self) -> str:
        h = socket.gethostname()
        if h and h != "localhost":
            return h
        return f"linux-node-{uuid.uuid4().hex[:8]}"

    def _load_persisted_token(self) -> Optional[str]:
        if not os.path.exists(self.token_path):
            return None
        try:
            # Check file permissions (warn if not 0600 on unix)
            try:
                mode = stat.S_IMODE(os.stat(self.token_path).st_mode)
                if mode & 0o077 != 0 and os.name == 'posix':
                    sys.stderr.write(f"Security Notice: Token file {self.token_path} has loose permissions ({oct(mode)}). Recommended is 0600.\n")
            except Exception:
                pass

            with open(self.token_path, "r", encoding="utf-8") as f:
                tok = f.read().strip()
                return tok if tok else None
        except Exception as e:
            sys.stderr.write(f"Warning: Unable to read token file {self.token_path}: {e}\n")
            return None

    def save_token(self, token: str) -> None:
        """Persists the authentication token securely with 0600 permissions."""
        token_dir = os.path.dirname(self.token_path)
        if token_dir:
            os.makedirs(token_dir, mode=0o700, exist_ok=True)
            try:
                os.chmod(token_dir, 0o700)
            except Exception:
                pass

        # Write to temp file then atomic rename
        temp_path = f"{self.token_path}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        
        fd = os.open(temp_path, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token.strip() + "\n")
        
        os.replace(temp_path, self.token_path)
        self.agent_token = token.strip()

    def get_system_metadata(self) -> Dict[str, Any]:
        """Gathers system inventory details for registration telemetry."""
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        arch = platform.machine()
        kernel = platform.release()

        # Primary IP discovery
        primary_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                primary_ip = socket.gethostbyname(hostname)
            except Exception:
                pass

        # MAC address discovery
        mac_address = "unknown"
        try:
            mac_num = uuid.getnode()
            mac_hex = f"{mac_num:012x}"
            mac_address = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
        except Exception:
            pass

        # Monitored sources detection
        sources = []
        if os.path.exists(self.auth_log_path) and os.access(self.auth_log_path, os.R_OK):
            sources.append(self.auth_log_path)
        if os.path.exists(self.audit_log_path) and os.access(self.audit_log_path, os.R_OK):
            sources.append(self.audit_log_path)
        if os.path.exists("/proc/net/tcp"):
            sources.append("/proc/net/tcp")
        if os.path.exists("/proc"):
            sources.append("/proc")

        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "operating_system": os_info,
            "architecture": arch,
            "kernel": kernel,
            "primary_ip": primary_ip,
            "mac_address": mac_address,
            "monitored_sources": sources,
            "agent_version": self.agent_version
        }

    def dump_safe(self) -> Dict[str, Any]:
        """Returns configuration dictionary with secrets masked."""
        return {
            "CENTRAL_SOC_URL": self.central_soc_url,
            "AGENT_ID": self.agent_id,
            "AGENT_VERSION": self.agent_version,
            "AGENT_TOKEN": "***PRESENT***" if self.agent_token else "<NOT_SET>",
            "HEARTBEAT_INTERVAL": self.heartbeat_interval,
            "BATCH_SIZE": self.batch_size,
            "BATCH_INTERVAL": self.batch_interval,
            "REQUEST_TIMEOUT": self.request_timeout,
            "VERIFY_TLS": self.verify_tls,
            "CA_CERT": self.ca_cert or "<NONE>",
            "BUFFER_DIRECTORY": self.buffer_directory,
            "TOKEN_PATH": self.token_path,
            "LOG_LEVEL": self.log_level,
            "AUTH_LOG_PATH": self.auth_log_path,
            "AUDIT_LOG_PATH": self.audit_log_path
        }
