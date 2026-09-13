# AI-SOC Linux Endpoint Agent Testing & Verification Guide

This guide describes how to run automated unit and integration tests, as well as simulate real security events on a Linux host to verify end-to-end detection in the AI-SOC Central Platform.

---

## 1. Automated Test Suite

To run all agent unit tests, parser verification, buffer spool tests, and Central Platform integration tests:

```bash
PYTHONPATH=. python3 -m pytest aisoc-agent/tests backend/tests -v
```

### Test Coverage Highlights:
- **Parser Tests (`test_parsers.py`):** Validates SSH password failures, invalid usernames, publickey logins, sudo execution, unauthorized sudoers attempts, auditd execve, auditd user auth, and `/proc/net/tcp` hex decoding.
- **Normalizer Tests (`test_normalizer.py`):** Ensures timestamps strictly follow UTC ISO-8601 formatting and `simulation=False` flags are enforced.
- **Buffer Tests (`test_buffer.py`):** Confirms SQLite transactional consistency, batch acknowledgement, FIFO ordering, persistence across process crashes, and queue capacity caps.
- **Transport Tests (`test_transport.py`):** Tests Bearer token headers, batch serialization, and network retry logic.
- **Integration Tests (`test_integration.py`):** End-to-end enrollment, heartbeat validation, SSH brute force log parsing, batch transport, Central SOC rule matching (`RULE-AUTH-001`), and Incident creation.

---

## 2. Live Linux Security Telemetry Scenarios

Once `aisoc-agent` is running on a live Linux system, you can verify real detections by generating simulated security events.

### Scenario A: SSH Brute Force Attack
Execute 4 failed SSH attempts from a test machine:
```bash
for i in {1..4}; do
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no invaliduser@<ENDPOINT_IP>
done
```
**Expected SOC Result:**
- Agent parses `Failed password for invalid user` from `/var/log/auth.log` or `journald`.
- Ingested via `/api/events/batch`.
- Central SOC triggers `RULE-AUTH-001` (MITRE `T1110.001 - Brute Force: Password Guessing`).
- Creates correlated Incident with risk score and MITRE matrix visualization.

---

### Scenario B: Unauthorized Sudo Privilege Escalation
Attempt an unauthorized sudo execution:
```bash
sudo -u root whoami
```
**Expected SOC Result:**
- Agent captures `sudo: ... user NOT in sudoers` or failed sudo auth.
- Central SOC triggers `RULE-PRIV-001` (MITRE `T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudoers`).
- Correlated with existing host activity in the SOC incident graph.
