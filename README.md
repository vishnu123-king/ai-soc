# AI-SOC: Automated Security Incident Detection, Correlation, and Analysis Framework

> **Final-Year Academic Project Prototype**  
> *A Hybrid Rule-Based and Local/Cloud LLM Framework for Automated Security Incident Detection, Correlation, and Analysis*

---

## 1. Executive Overview

Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue, fragmented telemetry, and manual correlation delays. **AI-SOC** is a high-performance, modular monolithic framework engineered to solve this challenge through a **hybrid detection and analysis pipeline**:

1. **Deterministic Rule-Based Detection**: Evaluates raw endpoint, authentication, and network telemetry at sub-millisecond speeds against modular MITRE ATT&CK-aligned heuristics.
2. **Deterministic Correlation Engine**: Groups cross-vector alerts by affected assets, threat actors (IPs), and identity into unified incident entities within sliding time windows.
3. **Deterministic Multi-Factor Risk Scoring**: Calculates an explainable 0–100 risk score and severity level based on kill-chain progression, event velocity, and MITRE weights.
4. **Read-Only AI Analyst (Gemini & Local Qwen)**: Synthesizes structured incident graphs into executive summaries, hypothesized attack progressions, and prioritized remediation actions without hallucinations or command injection risk.
5. **Interactive SOC Dashboard & Live Telemetry Bus**: Real-time event streaming via WebSockets, MITRE ATT&CK matrix visualization, interactive incident triage, and automated one-click HTML audit reports.

---

## 2. Architecture & Design Principles

```
+-----------------------------------------------------------------------------------+
|                                AI-SOC MONOLITH                                    |
|                                                                                   |
|  [Security Event Streams]  --->  [Log Ingestion & Normalization]                  |
|                                             |                                     |
|                                  [Rule Detection Engine]                          |
|                               (5x MITRE ATT&CK Rules)                             |
|                                             |                                     |
|                                  [Alert Generation Pool]                          |
|                                             |                                     |
|                                  [Correlation Engine]                             |
|                                (Asset / IP / Time Window)                         |
|                                             |                                     |
|                                  [Deterministic Risk Scorer]                      |
|                                        (0 - 100)                                  |
|                                             |                                     |
|                                  [Incident Data Store]                            |
|                                    (SQLite / Models)                              |
|                                             |                                     |
|                  +--------------------------+--------------------------+          |
|                  |                                                     |          |
|        [AIProvider Abstraction]                             [WebSocket Telemetry]  |
|       /                       \                                        |          |
| [GeminiProvider]     [LocalLLMProvider (Qwen)]                 [React Dashboard]  |
| (Google GenAI)       (Ollama / vLLM Endpoint)                  (Recharts / MITRE) |
+-----------------------------------------------------------------------------------+
```

### Key Architectural Constraints
* **No Over-Engineering**: Single modular monolith with zero external queue or distributed infrastructure dependencies (no Kafka, Redis, Elasticsearch, or Kubernetes required).
* **Deterministic Guardrails**: AI never acts as an unconstrained agent. AI is purely an analytical reader given structured context, strictly forbidden from executing shell commands or interacting directly with operating system tools.
* **Grounding & Anti-Hallucination**: Telemetry evidence is provided verbatim in JSON context; AI must cite verified evidence items.

---

## 3. Detection Rules & MITRE ATT&CK Matrix

| Rule ID | Detection Name | Severity | MITRE Technique | Detection Logic & Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **RULE-001** | **SSH Brute Force** | HIGH | `T1110` Brute Force | ≥ 5 failed SSH authentication attempts from identical source IP within 5 minutes. |
| **RULE-002** | **Successful Login After Brute Force** | CRITICAL | `T1078` Valid Accounts | Successful SSH login from an IP address that generated ≥ 3 authentication failures in the prior 30 minutes. |
| **RULE-003** | **Suspicious Privilege Escalation** | HIGH | `T1548` Abuse Elevation Mechanism | `sudo` followed by interactive shell invocation (`bash`, `sh`, `su -`, or scripting language shell spawn). |
| **RULE-004** | **Suspicious Process Relationship** | HIGH | `T1059` Command & Scripting | Web daemon (`nginx`, `apache2`, `php-fpm`) spawning interactive shells or utilities (`bash`, `nc`, `curl`). |
| **RULE-005** | **Suspicious Outbound Connection** | HIGH | `T1071` Application Layer Protocol | Outbound TCP/UDP socket established to high-risk C2/reverse shell ports (`4444`, `1337`, `6667`, etc.) or script piping. |

---

## 4. Multi-Stage Attack Chain Simulation

The project includes an automated end-to-end cyber intrusion scenario:
1. **Reconnaissance & Password Guessing**: 6 failed SSH login attempts from attacker IP `198.51.100.42` targeting host `prod-db-01.corp.internal`.
2. **Account Compromise**: Valid password accepted for user `deploy` from the same attacker IP.
3. **Privilege Escalation**: Adversary executes `sudo /bin/bash -i` to obtain root access.
4. **Execution & Web Shell**: `nginx` web daemon spawns anomalous interactive bash process downloading a secondary payload.
5. **Command & Control / Exfiltration**: Sockets outbound connection to `198.51.100.42:4444` (Netcat reverse shell).

---

## 5. Technology Stack

* **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts.
* **Backend**: Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy 2.0, SQLite.
* **AI Providers**:
  * `GeminiProvider`: Google GenAI SDK (`gemini-2.5-flash`).
  * `LocalLLMProvider`: OpenAI/Ollama compatible interface for local Qwen2.5 models.
* **Testing**: Pytest with in-memory SQLite isolation.

---

## 6. Getting Started & Deployment

### One-Step Complete Installation Script
To install the entire platform, dependencies, systemd services, and the Linux endpoint agent with a single command:
```bash
chmod +x install.sh
sudo ./install.sh
```

### Manual Environment Setup
Alternatively, configure manually:
```bash
cp .env.example .env
```
Add your `GEMINI_API_KEY` (optional; an intelligent deterministic heuristic fallback activates automatically if omitted).

### 2. Running the Unified Application
```bash
npm run dev
```
This single command boots:
* The Python FastAPI backend on `http://127.0.0.1:8000`
* The Vite + Express proxy on `http://0.0.0.0:3000`

### 3. Running Unit Tests
```bash
npm run test:backend
# or
PYTHONPATH=. pytest tests/ -v
```

### 4. Interactive API Documentation
Navigate to `http://localhost:3000/docs` to inspect and test all interactive FastAPI OpenAPI endpoints.
