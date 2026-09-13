# AI-SOC Linux Endpoint Agent (`aisoc-agent`)

`aisoc-agent` is a high-performance, lightweight Linux security telemetry collector and secure transport agent engineered to pair seamlessly with the **AI-SOC Central Platform**.

---

## 1. Key Capabilities

- **Lightweight Footprint:** Built on Python 3.11+ using standard library primitives and `httpx`. Consumes minimal RAM and CPU.
- **Multi-Source Telemetry Collection:**
  - OpenSSH authentication failures and successful logins (`/var/log/auth.log`, `journald`)
  - Sudo privilege escalations, unauthorized root access, and failed PAM attempts
  - Linux Auditd daemon events (`USER_AUTH`, `USER_CMD`, `EXECVE`, `SYSCALL`)
  - Real-time `/proc` execution monitoring
  - Dynamic socket tracking (`/proc/net/tcp`, `/proc/net/tcp6`)
- **Offline Durability & Resilient Spooling:**
  - Local persistent SQLite WAL-mode buffer preserving events during network blackouts or server maintenance.
  - Exponential backoff transmission retry with zero telemetry loss.
  - Strict maximum spool size enforcement to prevent disk exhaustion.
- **Security & Least Privilege:**
  - One-way cryptographically hashed bearer token authentication.
  - Tokens stored exclusively in mode `0600` under `/var/lib/aisoc/token`.
  - Systemd sandboxing profile (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`).

---

## 2. Quick Installation (Debian/Ubuntu)

```bash
# Clone or transfer aisoc-agent onto the endpoint
cd aisoc-agent
sudo ./install.sh
```

---

## 3. Configuration & Registration

Edit `/etc/aisoc/agent.conf` to configure your Central AI-SOC URL:

```ini
CENTRAL_SOC_URL=https://soc.example.internal
AGENT_ID=srv-ubuntu-prod-01
HEARTBEAT_INTERVAL=30
BATCH_SIZE=50
LOG_LEVEL=INFO
```

### Enroll the Endpoint:
```bash
sudo aisoc-agent register
```

### Verify Agent Diagnostic Health:
```bash
sudo aisoc-agent test
```

### Start Systemd Background Service:
```bash
sudo systemctl enable --now aisoc-agent
sudo systemctl status aisoc-agent
```

---

## 4. CLI Reference

| Command | Purpose |
| :--- | :--- |
| `aisoc-agent register` | Registers or re-enrolls the host with the Central SOC and saves token |
| `aisoc-agent start` | Launches telemetry collectors, buffer shipper, and heartbeat daemon |
| `aisoc-agent status` | Displays agent version, token status, buffer queue backlog, and reachability |
| `aisoc-agent test` | Executes end-to-end diagnostics (ping, auth, heartbeat, test event) |
| `aisoc-agent config-check`| Audits configuration parameters and filesystem permissions |
| `aisoc-agent version` | Outputs agent version |
