# AI-SOC Central Platform — Security Audit

---

## 1. Authentication & Identity Architecture

### 1.1. SOC Analyst Access (RBAC)
- **Password Security:** Uses native `bcrypt` (`gensalt(rounds=12)`) with automatic password truncation to 72 bytes. This eliminates vulnerability to DoS and deprecated `passlib` compatibility bugs.
- **Session Tokens:** Stateless RFC 7519 JSON Web Tokens (JWT) signed with HMAC-SHA256 (`HS256`).
- **Authorization Levels:**
  - `ADMIN`: Full access to configuration, agent token revocation, user management, and incident resolution.
  - `ANALYST`: Incident investigation, triage, status updates, and report generation.

### 1.2. Linux Endpoint Agent Authentication
- **Token Format:** Cryptographically generated 256-bit high-entropy token (`secrets.token_hex(32)`).
- **One-Way Storage:** Raw tokens are returned to the agent **only once** upon registration (`POST /api/agents/register`). The database stores only the SHA256 cryptographic digest (`auth_token_hash`).
- **Transport Verification:** Agents authenticate via `Authorization: Bearer <token>` or `X-Agent-Token: <token>`. Headers are verified against stored hashes using constant-time comparison.

---

## 2. AI Security & Operational Guardrails

### 2.1. Strictly Read-Only Security Analyst Persona
- **Zero Autonomous Execution:** The AI model is strictly an advisory forensic assistant. The system contains **no tools, no shell executors, and no automated remediation capabilities** that could allow the model to run arbitrary Linux commands or modify network firewalls.
- **Anti-Hallucination Framework:**
  - The system prompt enforces separating factual observations (`observed_evidence` citing exact timestamps, source IPs, commands, and exit codes) from inferential hypotheses (`hypotheses`).
  - Structured JSON schemas ensure outputs are strictly type-validated before display.
- **Zero Exposure of API Keys:** The `GEMINI_API_KEY` and local LLM tokens are held exclusively in the backend server memory and are never transmitted to client browsers.

---

## 3. Data Integrity & SQL Injection Defenses

- **Parameterized Queries:** All database interactions utilize SQLAlchemy 2.0 ORM query builders and parameterized SQL bindings. Raw unsanitized string interpolations are strictly absent.
- **Input Validation:** Every HTTP request payload is parsed and validated by strict Pydantic models with type bounds (e.g., port numbers bounded `0 <= port <= 65535`, pagination limits bounded `1 <= limit <= 500`).
- **SOC Audit Logging:** All administrative actions (agent enrollments, incident status changes, user logins) write tamper-evident records to the `audit_logs` database table.
