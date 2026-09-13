# AI-SOC Linux Endpoint Agent (`aisoc-agent`) — Technical Architecture

The `aisoc-agent` is an ultra-lightweight, production-grade Linux telemetry collector and secure transport daemon engineered specifically for edge Linux endpoints. It operates purely as a telemetry emitter, decoupling heavy analytical processing (AI correlation, risk scoring, MITRE mapping) onto the Central AI-SOC Platform.

---

## 1. Architectural Philosophy

```
+--------------------------------------------------------------------------------+
|                             LINUX ENDPOINT HOST                                |
|                                                                                |
|  +--------------------------------------------------------------------------+  |
|  |                           TELEMETRY COLLECTORS                           |  |
|  |  +-----------------+  +-----------------+  +--------------------------+  |  |
|  |  |  AuthLog Tailer |  | Journald Stream |  | Auditd Syscall Collector |  |  |
|  |  +-----------------+  +-----------------+  +--------------------------+  |  |
|  |  +-----------------+  +-----------------+                                |  |
|  |  |  /proc Monitor  |  | Net TCP Scanner |                                |  |
|  |  +-----------------+  +-----------------+                                |  |
|  +--------------------------------------------------------------------------+  |
|                                       |                                        |
|                                       v                                        |
|  +--------------------------------------------------------------------------+  |
|  |                        PARSERS & ECS-NORMALIZER                          |  |
|  |    (SSHParser, SudoParser, AuditParser, NetworkParser -> ISO-8601 UTC)   |  |
|  +--------------------------------------------------------------------------+  |
|                                       |                                        |
|                                       v                                        |
|  +--------------------------------------------------------------------------+  |
|  |             PERSISTENT LOCAL SPOOL BUFFER (SQLite WAL Mode)              |  |
|  |               (/var/lib/aisoc/buffer/events_spool.db)                    |  |
|  +--------------------------------------------------------------------------+  |
|                                       |                                        |
|                                       v                                        |
|  +--------------------------------------------------------------------------+  |
|  |                 BATCH SHIPPER & TRANSPORT (HTTPX / TLS)                  |  |
|  |              + Keep-Alive Heartbeat Daemon (/api/heartbeat)              |  |
|  +--------------------------------------------------------------------------+  |
+---------------------------------------|----------------------------------------+
                                        | HTTPS POST /api/events/batch (Bearer Auth)
                                        v
+--------------------------------------------------------------------------------+
|                        CENTRAL AI-SOC PLATFORM (FASTAPI)                       |
|  - Detection Engine (MITRE ATT&CK Matrix)                                      |
|  - Multi-Stage Correlation Engine                                              |
|  - Dynamic Risk Engine & Attack Graph                                          |
|  - Gemini & Qwen Dual AI Analysis Pipeline                                     |
|  - Real-Time React SOC Dashboard                                               |
+--------------------------------------------------------------------------------+
```

---

## 2. Core Modules & Responsibilities

### 2.1 Configuration Manager (`aisoc_agent/config.py`)
- Reads tiered configuration from `/etc/aisoc/agent.conf`, environment variables, or CLI parameters.
- Secures cryptographic Bearer tokens with strict `0600` Linux file permissions.
- Redacts secrets from memory and CLI status dumps.

### 2.2 Telemetry Parsers (`aisoc_agent/parsers/`)
- **SSH Parser (`parsers/ssh.py`):** Extracts failed passwords, invalid usernames, public key logins, client IP addresses, and source ports.
- **Sudo Parser (`parsers/sudo.py`):** Identifies elevated command executions, unauthorized `sudoers` violations, and PAM password failures.
- **Auditd Parser (`parsers/audit.py`):** Unpacks `EXECVE`, `USER_AUTH`, `USER_CMD`, and `SYSCALL` kernel records, decoding hex arguments.
- **Network Parser (`parsers/network.py`):** Decodes `/proc/net/tcp` little-endian hex IP structures into human-readable socket metadata.

### 2.3 Event Normalizer (`aisoc_agent/normalizer/events.py`)
- Maps heterogeneous raw syslog and kernel streams into the unified Central SOC JSON schema.
- Standardizes UTC timestamps with trailing `Z` ISO-8601 format.
- Strictly sets `simulation: false` to designate verified endpoint telemetry.

### 2.4 Persistent Spool Buffer (`aisoc_agent/buffer/spool.py`)
- SQLite database operating in Write-Ahead Logging (`WAL`) mode.
- Enforces strict FIFO ordering and transactionally acknowledges batches upon HTTP `200/201` server response.
- Guarantees zero event loss during network outages and reboots while capping disk capacity at a safe limit.

### 2.5 Transport & Batch Shipper (`aisoc_agent/transport/`)
- HTTP/HTTPS client utilizing `httpx` with TLS certificate validation.
- Employs exponential backoff (1s -> 30s) during transient connectivity disruptions.
- Ships events in configurable batch payloads (default: 50 events).
