# AI-SOC Linux Endpoint Agent Deployment Guide

This guide covers step-by-step production deployment, enrollment, and operational lifecycle management of the `aisoc-agent`.

---

## 1. Prerequisites

- **Supported Linux Distributions:** Ubuntu 20.04+, Debian 11+, RHEL/CentOS/Rocky 8+, Fedora 38+, Amazon Linux 2023.
- **Runtime:** Python 3.11 or higher.
- **Privileges:** Root access (or sudo) to configure `/etc/aisoc`, `/var/lib/aisoc`, and systemd unit.

---

## 2. Automated Installation

Run the installer on the target host:

```bash
git clone https://github.com/aisoc/aisoc-agent.git /tmp/aisoc-agent
cd /tmp/aisoc-agent
sudo ./install.sh
```

The script automatically:
1. Validates Python 3.11+ and installs `httpx`.
2. Creates isolated directories:
   - `/etc/aisoc` (mode `0700`)
   - `/var/lib/aisoc/buffer` (mode `0700`)
3. Installs the binary wrapper to `/usr/local/bin/aisoc-agent`.
4. Copies the default configuration template to `/etc/aisoc/agent.conf` (mode `0600`).
5. Configures and registers the systemd unit `/etc/systemd/system/aisoc-agent.service`.

---

## 3. Configuration & Enrollment

1. Edit `/etc/aisoc/agent.conf`:
   ```ini
   CENTRAL_SOC_URL=https://soc.company.internal
   AGENT_ID=srv-web-prod-01
   HEARTBEAT_INTERVAL=30
   BATCH_SIZE=50
   LOG_LEVEL=INFO
   ```

2. Enroll the agent with the Central SOC platform:
   ```bash
   sudo aisoc-agent register
   ```
   *Output:*
   ```text
   [*] Enrolling agent 'srv-web-prod-01' with Central SOC (https://soc.company.internal)...
   [+] SUCCESS: Agent enrolled successfully.
   [+] Bearer token securely persisted to /var/lib/aisoc/token (mode 0600).
   ```

3. Execute End-to-End Diagnostics:
   ```bash
   sudo aisoc-agent test
   ```
   *Output:*
   ```text
   [*] Running AI-SOC Agent Diagnostic Pipeline for 'srv-web-prod-01'...
   [+] Step 1: Local token detected and loaded.
   [+] Step 2: Central SOC endpoint reachability confirmed.
   [+] Step 3: Heartbeat successfully authenticated and acknowledged.
   [+] Step 4: Telemetry event successfully ingested.
   [✓] ALL DIAGNOSTIC TESTS PASSED: aisoc-agent is ready for production service.
   ```

---

## 4. Service Lifecycle Management

Enable and start the systemd daemon:

```bash
sudo systemctl enable --now aisoc-agent
```

Check status and live logs:

```bash
# Check service status
sudo systemctl status aisoc-agent

# Inspect live journal logs
sudo journalctl -u aisoc-agent -f
```

---

## 5. Uninstallation

To cleanly decommission the agent:

```bash
sudo /opt/aisoc-agent/uninstall.sh
```
