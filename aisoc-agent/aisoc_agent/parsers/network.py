import socket
import struct
from typing import Optional, Tuple
from ..normalizer.events import NormalizedEvent, create_event

# TCP Connection States in /proc/net/tcp
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING"
}

def decode_proc_net_ipv4(hex_addr: str) -> Tuple[str, int]:
    """Decodes little-endian hexadecimal IPv4 address and port from /proc/net/tcp."""
    ip_hex, port_hex = hex_addr.split(":")
    # IP is in little-endian binary format
    ip_bytes = bytes.fromhex(ip_hex)
    ip_str = socket.inet_ntoa(ip_bytes[::-1] if len(ip_bytes) == 4 else struct.pack("<I", int(ip_hex, 16)))
    port_int = int(port_hex, 16)
    return ip_str, port_int

class NetworkParser:
    """
    Parser for Linux network connections and socket activities (/proc/net/tcp, ss).
    """
    def __init__(self, hostname: str, agent_id: Optional[str] = None):
        self.hostname = hostname
        self.agent_id = agent_id

    def parse_proc_net_tcp_line(self, line: str, timestamp: Optional[str] = None) -> Optional[NormalizedEvent]:
        line = line.strip()
        parts = line.split()
        if len(parts) < 10 or parts[0] == "sl":
            return None

        try:
            local_raw = parts[1]
            rem_raw = parts[2]
            state_hex = parts[3]
            state_name = TCP_STATES.get(state_hex, "UNKNOWN")

            # Ignore LISTEN and non-active states for telemetry volume control
            if state_name not in ["ESTABLISHED", "SYN_SENT"]:
                return None

            src_ip, src_port = decode_proc_net_ipv4(local_raw)
            dst_ip, dst_port = decode_proc_net_ipv4(rem_raw)

            # Ignore loopback connections (127.0.0.1 to 127.0.0.1) unless specified
            if src_ip.startswith("127.") and dst_ip.startswith("127."):
                return None

            # If rem_address is 0.0.0.0:0, it's a listening socket
            if dst_ip == "0.0.0.0" and dst_port == 0:
                return None

            action = "outbound_socket" if state_name == "ESTABLISHED" else "socket_connect"

            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="network",
                action=action,
                status="success",
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                raw_message=f"TCP connection {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{state_name}]",
                metadata={"state": state_name, "inode": parts[9] if len(parts) > 9 else None}
            )
        except Exception:
            return None
