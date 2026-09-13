import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any

def normalize_timestamp(ts: Optional[Any] = None) -> str:
    """
    Normalizes any datetime or timestamp string to UTC ISO-8601 with trailing 'Z'.
    Example: 2026-09-12T07:15:22.124560Z
    """
    if ts is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.isoformat().replace("+00:00", "Z")
    
    if isinstance(ts, str):
        # If string ends with Z or timezone offset, parse it
        ts_clean = ts.strip()
        try:
            # Handle standard syslog format without year: "Sep 12 07:15:22"
            syslog_match = re.match(r'^([A-Za-z]{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})', ts_clean)
            if syslog_match:
                now = datetime.now(timezone.utc)
                month_str, day_str, hour_str, min_str, sec_str = syslog_match.groups()
                # Parse month
                months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
                if month_str in months:
                    month_num = months.index(month_str) + 1
                    parsed_dt = datetime(
                        year=now.year,
                        month=month_num,
                        day=int(day_str),
                        hour=int(hour_str),
                        minute=int(min_str),
                        second=int(sec_str),
                        tzinfo=timezone.utc
                    )
                    return parsed_dt.isoformat().replace("+00:00", "Z")
            
            # Try ISO 8601 parsing
            dt = datetime.fromisoformat(ts_clean.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            pass

    # Fallback to current UTC time
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

@dataclass
class NormalizedEvent:
    """
    Canonical security event schema matching the AI-SOC Central Platform API contract.
    """
    hostname: str
    event_type: str
    status: str
    raw_message: str
    agent_id: Optional[str] = None
    timestamp: str = field(default_factory=normalize_timestamp)
    action: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    simulation: bool = False  # Real endpoint telemetry is ALWAYS simulation=False

    def to_dict(self) -> Dict[str, Any]:
        """Converts to API-compatible JSON dictionary."""
        d = asdict(self)
        # Ensure timestamp is normalized ISO string
        d["timestamp"] = normalize_timestamp(d["timestamp"])
        d["simulation"] = False
        return d

def create_event(
    hostname: str,
    event_type: str,
    status: str,
    raw_message: str,
    agent_id: Optional[str] = None,
    timestamp: Optional[Any] = None,
    action: Optional[str] = None,
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    process: Optional[str] = None,
    parent_process: Optional[str] = None,
    command: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> NormalizedEvent:
    return NormalizedEvent(
        hostname=hostname,
        event_type=event_type,
        status=status,
        raw_message=raw_message,
        agent_id=agent_id,
        timestamp=normalize_timestamp(timestamp),
        action=action,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        process=process,
        parent_process=parent_process,
        command=command,
        metadata=metadata or {},
        simulation=False
    )
