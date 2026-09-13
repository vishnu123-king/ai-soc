# AI-SOC Agent API Specification

**Target Component:** Linux Endpoint Agent (`aisoc-agent`)  
**Base URL:** `http://<CENTRAL_SOC_SERVER>:3000/api` (or directly `http://<CENTRAL_SOC_SERVER>:8088/api`)  
**Protocol:** HTTP/1.1 or HTTP/2, JSON Payload  
**Security:** Bearer Token via `Authorization: Bearer <AGENT_AUTH_TOKEN>` or `X-Agent-Token: <AGENT_AUTH_TOKEN>`

---

## 1. Agent Enrollment & Registration

### Endpoint: `POST /api/agents/register`

Used by `aisoc-agent` on initial installation or re-enrollment to register the endpoint and receive an authentication bearer token.

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{
  "agent_id": "srv-ubuntu-dmz-01",
  "hostname": "srv-ubuntu-dmz-01.internal.corp",
  "operating_system": "Ubuntu 22.04.4 LTS (Linux 5.15.0-101-generic x86_64)",
  "ip_address": "10.0.4.15",
  "agent_version": "1.0.0",
  "metadata": {
    "kernel": "5.15.0-101-generic",
    "architecture": "x86_64",
    "mac_address": "00:16:3e:4a:2b:81",
    "monitored_sources": ["/var/log/auth.log", "/var/log/audit/audit.log", "/proc/net/tcp"]
  }
}
```

#### Response: `201 Created`
```json
{
  "agent_id": "srv-ubuntu-dmz-01",
  "hostname": "srv-ubuntu-dmz-01.internal.corp",
  "status": "ONLINE",
  "token": "agt_8f4d92e10a7b45c3891d0f2a4e671b5c90234def12ab4567c8901234567890ab",
  "registered_at": "2026-09-12T07:15:00.000Z",
  "message": "New agent registered successfully."
}
```

> **Note on Token Storage:** The agent MUST persist this `token` locally (e.g., in `/etc/aisoc/agent.conf` or `/var/lib/aisoc/token` with `chmod 600` permissions). Central platform stores only the cryptographic SHA256 hash `auth_token_hash`.

---

## 2. Telemetry Event Ingestion (Single Event)

### Endpoint: `POST /api/events`

Used to stream individual normalized security events from Linux collectors (e.g. `auditd`, `sshd`, `iptables`, `procfs`).

#### Request Headers
```http
Content-Type: application/json
Authorization: Bearer <AGENT_AUTH_TOKEN>
```

#### Request Body
```json
{
  "agent_id": "srv-ubuntu-dmz-01",
  "hostname": "srv-ubuntu-dmz-01",
  "timestamp": "2026-09-12T07:15:22.124Z",
  "event_type": "authentication",
  "action": "ssh_login",
  "status": "failed",
  "username": "root",
  "source_ip": "198.51.100.88",
  "destination_ip": "10.0.4.15",
  "source_port": 54312,
  "destination_port": 22,
  "process": "/usr/sbin/sshd",
  "parent_process": "systemd",
  "command": null,
  "raw_message": "sshd[29841]: Failed password for invalid user root from 198.51.100.88 port 54312 ssh2",
  "metadata": {
    "auth_method": "password",
    "ssh_protocol": "2.0"
  },
  "simulation": false
}
```

#### Response: `201 Created`
```json
{
  "id": 1042,
  "agent_id": "srv-ubuntu-dmz-01",
  "hostname": "srv-ubuntu-dmz-01",
  "timestamp": "2026-09-12T07:15:22.124Z",
  "event_type": "authentication",
  "action": "ssh_login",
  "status": "failed",
  "username": "root",
  "source_ip": "198.51.100.88",
  "destination_ip": "10.0.4.15",
  "source_port": 54312,
  "destination_port": 22,
  "process": "/usr/sbin/sshd",
  "parent_process": "systemd",
  "command": null,
  "raw_message": "sshd[29841]: Failed password for invalid user root from 198.51.100.88 port 54312 ssh2",
  "is_simulation": false
}
```

---

## 3. Batch Telemetry Event Ingestion (Buffered)

### Endpoint: `POST /api/events/batch`

High-throughput endpoint optimized for agent disk-buffering when network connectivity was temporarily interrupted or for batching high-frequency audit logs.

#### Request Headers
```http
Content-Type: application/json
Authorization: Bearer <AGENT_AUTH_TOKEN>
```

#### Request Body
```json
{
  "events": [
    {
      "agent_id": "srv-ubuntu-dmz-01",
      "hostname": "srv-ubuntu-dmz-01",
      "timestamp": "2026-09-12T07:15:20.000Z",
      "event_type": "network",
      "action": "socket_connect",
      "status": "success",
      "source_ip": "198.51.100.88",
      "destination_port": 22,
      "raw_message": "kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.88 DST=10.0.4.15 DPT=22"
    },
    {
      "agent_id": "srv-ubuntu-dmz-01",
      "hostname": "srv-ubuntu-dmz-01",
      "timestamp": "2026-09-12T07:15:22.000Z",
      "event_type": "authentication",
      "action": "ssh_login",
      "status": "failed",
      "username": "root",
      "source_ip": "198.51.100.88",
      "raw_message": "sshd[29841]: Failed password for root from 198.51.100.88 port 54312"
    }
  ]
}
```

#### Response: `201 Created`
```json
{
  "status": "ok",
  "ingested": 2
}
```

---

## 4. Agent Heartbeat & Liveness Verification

### Endpoint: `POST /api/agents/{agent_id}/heartbeat`

Sent by `aisoc-agent` periodically (every 30 to 60 seconds) to maintain `ONLINE` status in the SOC console. If no heartbeat or event is received for 5 minutes, the central platform automatically transitions the agent status to `OFFLINE`.

#### Request Headers
```http
Authorization: Bearer <AGENT_AUTH_TOKEN>
```

#### Response: `200 OK`
```json
{
  "status": "ok",
  "timestamp": "2026-09-12T07:16:00.123456"
}
```

---

## 5. Event Schema Standards

The agent must normalize collected Linux system logs into one of the following canonical `event_type` categories:

| Event Type | Typical Sources | Common Actions | Status Values |
| :--- | :--- | :--- | :--- |
| `authentication` | `/var/log/auth.log`, `journalctl -u ssh`, PAM | `ssh_login`, `sudo_auth`, `su`, `console_login` | `success`, `failed` |
| `privilege` | `/var/log/auth.log`, `auditd` (USER_AUTH, USER_CMD) | `sudo_exec`, `su_exec`, `cap_set` | `success`, `failed` |
| `process` | `auditd` (SYSCALL execve), eBPF, `/proc` monitor | `execve`, `fork`, `ptrace` | `success`, `failed` |
| `file` | `auditd` (PATH `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`) | `open`, `read`, `write`, `unlink`, `chmod` | `success`, `failed` |
| `network` | `iptables`, `ufw`, `conntrack`, `ss -tulpn` | `socket_connect`, `inbound_connection`, `outbound_socket` | `success`, `failed` |
| `persistence` | `/etc/cron*`, `/var/spool/cron`, systemd services | `crontab_modify`, `systemd_service_add` | `success`, `failed` |
| `discovery` | `auditd` commands (`uname -a`, `nmap`, `linpeas`, `netstat`) | `tool_exec`, `scan_exec` | `success`, `failed` |
