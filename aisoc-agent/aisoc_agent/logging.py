import logging
import re
import sys
from datetime import datetime

# Regex pattern to scrub tokens and sensitive keys from log output
TOKEN_PATTERN = re.compile(r'(agt_[a-zA-Z0-9_\-]{16,}|Bearer\s+[a-zA-Z0-9_\-\.]{16,}|password[:=]\s*\S+)', re.IGNORECASE)

class RedactingFormatter(logging.Formatter):
    """
    Log formatter that intercepts and scrubs sensitive authentication tokens and credentials.
    """
    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        # Redact any matched token patterns
        redacted = TOKEN_PATTERN.sub(r'[REDACTED_CREDENTIAL]', orig)
        return redacted

def setup_agent_logger(name: str = "aisoc-agent", level: str = "INFO") -> logging.Logger:
    """
    Configures a structured, safe logger for the endpoint agent.
    """
    logger = logging.getLogger(name)
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Avoid duplicate handlers if already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s.%(module)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
