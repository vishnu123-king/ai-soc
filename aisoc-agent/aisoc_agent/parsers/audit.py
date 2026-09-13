import re
from typing import Optional, Dict
from ..normalizer.events import NormalizedEvent, create_event

class AuditParser:
    """
    Parser for Linux Audit daemon (auditd) log records.
    Parses key-value formatted entries: type=... msg=audit(...): ...
    """
    def __init__(self, hostname: str, agent_id: Optional[str] = None):
        self.hostname = hostname
        self.agent_id = agent_id

    def _parse_kv(self, line: str) -> Dict[str, str]:
        """Extracts key=value, key="value", and key='value' pairs from an audit line."""
        kv = {}
        # First check for msg='...' wrapper and unwrap it
        msg_match = re.search(r"msg='([^']+)'", line)
        if msg_match:
            inner = msg_match.group(1)
            inner_tokens = re.findall(r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))', inner)
            for k, v_dquote, v_squote, v_unquoted in inner_tokens:
                kv[k] = v_dquote or v_squote or v_unquoted

        tokens = re.findall(r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))', line)
        for k, v_dquote, v_squote, v_unquoted in tokens:
            if k not in kv or not kv[k]:
                kv[k] = v_dquote or v_squote or v_unquoted
        return kv

    def parse_line(self, line: str, timestamp: Optional[str] = None) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line or "type=" not in line:
            return None

        # Extract audit record type
        type_match = re.search(r'type=([A-Z_]+)', line)
        if not type_match:
            return None
        
        record_type = type_match.group(1)
        kv = self._parse_kv(line)

        # 1. EXECVE (Command Execution)
        if record_type == "EXECVE":
            argc = int(kv.get("argc", 0))
            args = []
            for i in range(argc):
                a_key = f"a{i}"
                if a_key in kv:
                    val = kv[a_key]
                    # Check if hex-encoded
                    if re.match(r'^[0-9a-fA-F]{4,}$', val) and len(val) % 2 == 0:
                        try:
                            val = bytes.fromhex(val).decode("utf-8", errors="ignore")
                        except Exception:
                            pass
                    args.append(val)
            
            cmd = " ".join(args) if args else None
            exe = args[0] if args else None
            
            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="process",
                action="execve",
                status="success",
                process=exe,
                command=cmd,
                raw_message=line,
                metadata={"audit_type": "EXECVE", "argc": argc}
            )

        # 2. USER_AUTH / USER_LOGIN
        elif record_type in ["USER_AUTH", "USER_LOGIN"]:
            acct = kv.get("acct")
            addr = kv.get("addr")
            exe = kv.get("exe")
            res = kv.get("res")
            status = "success" if res == "success" or res == "1" else "failed"

            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="authentication",
                action="audit_auth",
                status=status,
                username=acct,
                source_ip=addr if addr and addr != "?" else None,
                process=exe,
                raw_message=line,
                metadata={"audit_type": record_type, "res": res}
            )

        # 3. USER_CMD (Sudo commands logged by auditd)
        elif record_type == "USER_CMD":
            cmd = kv.get("cmd")
            acct = kv.get("acct")
            cwd = kv.get("cwd")
            res = kv.get("res")
            status = "success" if res == "success" or res == "1" else "failed"

            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="privilege",
                action="sudo_exec",
                status=status,
                username=acct,
                command=cmd,
                process="/usr/bin/sudo",
                raw_message=line,
                metadata={"audit_type": "USER_CMD", "cwd": cwd}
            )

        # 4. SYSCALL (Syscall executions, sensitive file tampering)
        elif record_type == "SYSCALL":
            comm = kv.get("comm")
            exe = kv.get("exe")
            success = kv.get("success")
            status = "success" if success == "yes" else "failed"
            key = kv.get("key")

            return create_event(
                hostname=self.hostname,
                agent_id=self.agent_id,
                timestamp=timestamp,
                event_type="process",
                action="syscall",
                status=status,
                username=kv.get("AUID") or kv.get("uid"),
                process=exe or comm,
                raw_message=line,
                metadata={"audit_type": "SYSCALL", "key": key, "arch": kv.get("arch")}
            )

        return None
