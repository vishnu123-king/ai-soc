# AI-SOC: Automated Security Incident Detection, Correlation, and Analysis Framework

> **Academic Final-Year Engineering Project & Production Blueprint**  
> *A Hybrid Rule-Based and Local/Cloud LLM Framework for Automated Security Incident Detection, Correlation, and Analysis with an Autonomous Linux Endpoint Telemetry Agent.*

---

## 1. Executive Summary & Problem Statement

Modern Security Operations Centers (SOCs) face three critical bottlenecks:
1. **Alert Fatigue**: Tier-1 analysts are flooded with thousands of disconnected low-fidelity alerts daily.
2. **Correlation Delays**: Manual pivoting across auth logs, auditd process spawns, and network traces takes hours, allowing attackers dwell time to escalate privileges and exfiltrate data.
3. **Unchecked AI Hallucination & Risk**: Recklessly connecting autonomous LLMs to system shells introduces prompt injection, non-deterministic reasoning, and execution hazards.

**AI-SOC** solves these challenges with an architecturally grounded **hybrid pipeline**:
* **Deterministic Detection**: Evaluates raw telemetry streams at sub-millisecond speeds against modular rules mapped to MITRE ATT&CK techniques.
* **Deterministic Correlation**: Unifies cross-vector alerts within sliding time windows across shared identities, IP addresses, and hostnames into consolidated Incidents.
* **Deterministic Risk Scoring**: Mathematically scores threat severity (0–100) using MITRE weights, kill-chain progression, and event velocity.
* **Read-Only AI Analyst Guardrails**: Cloud (Google Gemini 2.5 Flash) or Local LLMs (Qwen 2.5) act strictly as read-only analytical synthesizers given structured JSON telemetry context. The AI cannot execute operating system commands or hallucinate unverified evidence.
* **Real-Time Endpoint Agent**: A lightweight Python agent (`aisoc-agent`) running as a systemd service monitors Linux authentication, Linux auditd processes, and socket events, automatically spooling offline when disconnected.

---

## 2. System Architecture & Working Principle

```
+---------------------------------------------------------------------------------------------------------+
|                                        AI-SOC SYSTEM ARCHITECTURE                                       |
|                                                                                                         |
|   +---------------------------------------+               +-----------------------------------------+   |
|   |          LINUX MONITORED HOST         |               |           CENTRAL AI-SOC SERVER         |   |
|   |  (/var/log/auth.log, auditd, sockets) |               |               (Port 3000)               |   |
|   |                                       |               |                                         |   |
|   |         +-------------------+         |               |   +---------------------------------+   |   |
|   |         |    aisoc-agent    |         |    HTTPS /    |   |    Log Ingestion & Normalizer   |   |   |
|   |         | (auditd / auth /  | --------+-- REST Batch -+-> |    - Schema Validation              |   |   |
|   |         |  system spool)    |         |   (Port 3000) |   |    - Severity Normalization         |   |   |
|   |         +-------------------+         |               |   +---------------------------------+   |   |
|   +---------------------------------------+               |                   |                     |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |   |     Rule Detection Engine       |   |   |
|                                                           |   |  - RULE-001: SSH Brute Force    |   |   |
|                                                           |   |  - RULE-002: Login After Brute  |   |   |
|                                                           |   |  - RULE-003: Priv Escalation    |   |   |
|                                                           |   |  - RULE-004: Suspicious Process |   |   |
|                                                           |   |  - RULE-005: Outbound C2 Socket |   |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |                   | (Alert Pool)        |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |   |   Sliding Correlation Engine    |   |   |
|                                                           |   |  - Correlate by Host/IP/User    |   |   |
|                                                           |   |  - Time Window: 15-30 mins      |   |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |                   |                     |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |   |   Deterministic Risk Scorer     |   |   |
|                                                           |   |   Score = Base + KillChain +    |   |   |
|                                                           |   |           Velocity (0 - 100)    |   |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |                   |                     |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |   |      SQLite / SQLAlchemy        |   |   |
|                                                           |   |  (Endpoints, Alerts, Incidents) |   |   |
|                                                           |   +---------------------------------+   |   |
|                                                           |             |               |           |   |
|                                                           |             v               v           |   |
|                                                           |   +-------------------+  +----------+   |   |
|                                                           |   | Read-Only AI      |  | React    |   |   |
|                                                           |   | Analyst           |  | Single   |   |   |
|                                                           |   | (Gemini / Qwen)   |  | Page App |   |   |
|                                                           |   +-------------------+  +----------+   |   |
+---------------------------------------------------------------------------------------------------------+
```

### End-to-End Working Lifecycle

1. **Log Collection & Normalization**:
   - Monitored Linux machines run `aisoc-agent`.
   - The agent tails `/var/log/auth.log`, queries the kernel via `auditd` / `ausearch`, monitors open network sockets, and collects hardware telemetry (CPU, memory, disk).
   - Events are batched into a standard JSON schema and transmitted over secure HTTP/HTTPS to `POST /api/events`.
   - If network connectivity to the central server is lost, events are saved to a durable SQLite spool on the endpoint (`/var/lib/aisoc/spool.db`) and flushed automatically upon reconnection.

2. **Rule-Based Detection (Sub-millisecond)**:
   - Ingested events flow through the rule engine (`backend/app/rules/`).
   - Each rule evaluates criteria against stateful sliding windows (e.g. 5 failed SSH attempts within 5 minutes).
   - Matched rules emit high-fidelity **Alerts** tagged with MITRE ATT&CK Technique IDs (e.g. `T1110`, `T1078`, `T1548`, `T1059`, `T1071`).

3. **Multi-Vector Correlation**:
   - The correlation engine evaluates newly generated alerts against open active **Incidents**.
   - If an alert shares an asset hostname, attacker IP, or targeted username within a 15–30 minute sliding window, it is grouped into the existing Incident; otherwise, a new incident entity is created.

4. **Multi-Factor Risk Scoring (0–100)**:
   - An objective formula calculates severity without AI guessing:
     $$\text{Risk Score} = \min(100, \text{Base Weight} + \text{Kill-Chain Progression Multiplier} + \text{Event Velocity Penalty})$$
   - Critical thresholds automatically trigger alerts on the live analyst dashboard.

5. **Read-Only AI Analyst Synthesis**:
   - When an analyst selects an incident, the system serializes the incident graph and verified event evidence into a strict JSON payload.
   - The prompt explicitly instructs the LLM (Google Gemini or Local Qwen):
     - Generate an Executive Summary.
     - Formulate a Hypothesized Threat Progression.
     - Cite exact evidence IDs without hallucination.
     - Produce prioritized Containment and Remediation action items.
   - If no LLM API key is present, a deterministic rule-augmented synthesis engine automatically generates standard containment steps.

---

## 3. Detection Rules & MITRE ATT&CK Matrix

| Rule ID | Detection Name | Severity | MITRE Technique | Detection Logic & Trigger Threshold |
| :--- | :--- | :--- | :--- | :--- |
| **RULE-001** | **SSH Brute Force** | `HIGH` | `T1110` Brute Force | $\ge 5$ failed authentication attempts from the same source IP within a 5-minute sliding window. |
| **RULE-002** | **Compromise After Brute Force** | `CRITICAL` | `T1078` Valid Accounts | Successful login from an IP address that generated $\ge 3$ authentication failures in the prior 30 minutes. |
| **RULE-003** | **Suspicious Privilege Escalation** | `HIGH` | `T1548` Abuse Elevation Mechanism | Invocation of `sudo` spawning an interactive shell (`/bin/bash -i`, `/bin/sh`, `su -`, or python/perl pty spawn). |
| **RULE-004** | **Suspicious Process Lineage** | `HIGH` | `T1059` Command & Scripting | Web daemon (`nginx`, `apache2`, `php-fpm`) spawning shell processes or utilities (`bash`, `nc`, `curl`, `wget`). |
| **RULE-005** | **Outbound C2 Reverse Shell** | `CRITICAL` | `T1071` Application Protocol | Direct TCP/UDP socket opened to known offensive ports (`4444`, `1337`, `6667`, `9001`) with interactive terminal piping. |

---

## 4. Multi-Stage Attack Chain Simulation

AI-SOC includes a built-in multi-stage adversarial attack simulation that triggers the full detection, correlation, and analysis pipeline in seconds:

1. **Stage 1 (Reconnaissance / Credential Access)**:
   6 consecutive failed SSH authentication attempts from `198.51.100.42` targeting host `prod-db-01.corp.internal` $\rightarrow$ Triggers `RULE-001`.
2. **Stage 2 (Initial Access & Compromise)**:
   Successful SSH password authentication for account `deploy` from the identical IP $\rightarrow$ Triggers `RULE-002`.
3. **Stage 3 (Privilege Escalation)**:
   User `deploy` invokes `sudo /bin/bash -i` to gain root access $\rightarrow$ Triggers `RULE-003`.
4. **Stage 4 (Execution & Persistence)**:
   Web service `nginx` spawns `/bin/bash` downloading a secondary remote script $\rightarrow$ Triggers `RULE-004`.
5. **Stage 5 (Command & Control / Exfiltration)**:
   Outbound connection established from internal host to `198.51.100.42:4444` $\rightarrow$ Triggers `RULE-005`.
6. **Correlation & AI Result**:
   All 5 events are linked into a single **CRITICAL Incident** with a risk score of `95/100`. Gemini produces an executive narrative explaining the lateral movement and recommended containment actions.

---

## 5. Single-Command Installation Guide

### Prerequisites
- **Supported Platforms**: Ubuntu 22.04/24.04 LTS, Debian 12, Kali Linux (2023–2026), or CentOS/RHEL 9.
- **Privileges**: Root access (`sudo`).
- **Gemini API Key**: (Optional but recommended) Free from [Google AI Studio](https://aistudio.google.com/app/apikey).

---

### Complete One-Step Automated Install

Run this single command on your server/machine:

```bash
git clone https://github.com/vishnu123-king/ai-soc.git
cd ai-soc
export GEMINI_API_KEY="your-gemini-api-key-here"
sudo -E ./install.sh
```

#### What `install.sh` Automatically Executes:
1. **OS Packages**: Updates repositories and installs `python3`, `python3-venv`, `python3-pip`, `build-essential`, `curl`, `sqlite3`, `openssl`, and `auditd`.
2. **Node.js**: Automatically installs Node.js 20 LTS via NodeSource if missing or older than v18.
3. **Python Virtual Environment**: Creates `.venv` and installs FastAPI, SQLAlchemy, Uvicorn, Google GenAI SDK, and Pydantic.
4. **Environment Secrets**: Generates `.env` with cryptographically secure random keys for JWT and agent authentication, and injects your `GEMINI_API_KEY`.
5. **Asset Compilation**: Compiles the React + Vite frontend and bundles the Express production server into `dist/`.
6. **Database Seeding**: Initializes SQLite and provisions default administrative credentials (`admin` / `admin123`).
7. **Platform Service (`aisoc.service`)**: Generates and enables the central background systemd unit on port `3000`.
8. **Endpoint Agent (`aisoc-agent.service`)**: Installs the telemetry agent into `/opt/aisoc-agent`, creates CLI symlinks, enrolls the host with the Central SOC, validates health tests, and activates the background service.

---

## 6. Accessing & Using the Platform

### Dashboard & API Access
* **Web Dashboard**: Open [http://localhost:3000](http://localhost:3000)
* **Default Credentials**:
  - **Username**: `admin`
  - **Password**: `admin123`
* **Interactive OpenAPI Docs**: [http://localhost:3000/api/docs](http://localhost:3000/api/docs)

### Primary Dashboard Views
1. **Incident Triage**: Consolidated incidents ranked by risk score, with kill-chain visualization and status controls (Open, In Investigation, Contained, Closed).
2. **MITRE ATT&CK Matrix**: Dynamic heatmap highlighting active techniques observed across monitored endpoints.
3. **Endpoint Health & Inventory**: Real-time status of all enrolled nodes (OS, IP, CPU, Memory, Heartbeat latency).
4. **Live Telemetry Stream**: Real-time event log viewer streaming authentication events, process executions, and socket connections.
5. **Attack Simulator**: Interactive 1-click trigger to simulate the 5-stage attack chain and watch real-time correlation in action.
6. **Audit Reports**: One-click printable HTML compliance reports summarizing incident findings, timestamps, and containment audit trails.

---

## 7. Endpoint Agent (`aisoc-agent`) Operations

The endpoint agent runs autonomously on any Linux system to gather and stream security telemetry.

### Useful CLI Commands
```bash
# View agent operational status and offline spool queue size
sudo aisoc-agent status

# Run the 4-step diagnostic verification pipeline
sudo aisoc-agent test

# Re-register or enroll with Central SOC
sudo aisoc-agent register

# View live systemd service logs
sudo journalctl -u aisoc-agent -f
```

### Configuration File (`/etc/aisoc/agent.conf`)
```ini
# Central SOC URL
CENTRAL_SOC_URL=http://localhost:3000

# Host Identifier (defaults to hostname if commented out)
# AGENT_ID=kali-workstation

# Heartbeat interval in seconds
HEARTBEAT_INTERVAL=30

# Maximum batch size before flushing
BATCH_SIZE=50
```

---

## 8. Development & Manual Execution

If you prefer running components manually during development:

### 1. Start Both Services in Development Mode
```bash
npm run dev
```
Starts:
- Python FastAPI Backend on `http://127.0.0.1:8000`
- Vite + Express Reverse Proxy on `http://localhost:3000`

### 2. Run Backend Tests
```bash
npm run test:backend
# or directly with pytest
source .venv/bin/activate
PYTHONPATH=. pytest tests/ -v
```

### 3. Production Build
```bash
npm run build
npm run start
```

---

## 9. Technology Stack

* **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts, Framer Motion.
* **Backend**: Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy 2.0, SQLite (WAL mode).
* **AI Providers**:
  - `GeminiProvider`: Google GenAI SDK (`gemini-2.5-flash`).
  - `LocalLLMProvider`: OpenAI / Ollama compatible endpoint (`Qwen/Qwen2.5-7B-Instruct`).
  - `DeterministicFallback`: Rule-augmented containment engine when offline.
* **Endpoint Telemetry**: Linux `/var/log/auth.log`, Linux `auditd` netlink/ausearch, `/proc/net`, `/proc/stat`.
* **Process Management**: Linux systemd (`aisoc.service` and `aisoc-agent.service`).

---

## 10. License & Academic Attribution

Developed as a Cyber Threat Intelligence & Automated SOC Final-Year Academic Engineering Project.  
Released under the MIT License.



## Full Installation
git clone https://github.com/vishnu123-king/ai-soc.git
cd ai-soc
export GEMINI_API_KEY="your-gemini-key"
sudo -E ./install.sh
