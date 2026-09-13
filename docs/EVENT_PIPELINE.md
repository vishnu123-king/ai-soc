# AI-SOC Event & Incident Lifecycle Pipeline

```
                       ┌───────────────────────────────────────────────┐
                       │    Linux Endpoint (aisoc-agent / auditd)      │
                       └──────────────────────┬────────────────────────┘
                                              │ POST /api/events (JSON)
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ CENTRAL SOC PLATFORM PROCESSING PIPELINE                                                    │
│                                                                                             │
│  1. Ingestion & Normalization                                                               │
│     ├── Validate Pydantic Schema (`EventCreate` / `EventBatchCreate`)                       │
│     ├── Map Linux specifics to canonical fields (timestamp, host, user, IPs, ports)        │
│     ├── Persist to DB table `events`                                                        │
│     └── Refresh Agent status (`ONLINE`, update `last_seen`)                                 │
│                                                                                             │
│  2. Deterministic Detection Evaluation                                                      │
│     ├── Stream event to DetectionEngine registry (`backend/app/detection/engine.py`)        │
│     ├── Execute 6 modular rule checks with time-window state lookups                        │
│     ├── If rule matches: Create & persist `Detection` alert record                          │
│     └── Emit WebSocket `DETECTION_TRIGGERED`                                                │
│                                                                                             │
│  3. Graph & Time-Window Incident Correlation                                                │
│     ├── Stream detection to CorrelationEngine (`backend/app/correlation/engine.py`)         │
│     ├── Search for active Incident on same `hostname` or `source_ip` within 30 min window   │
│     ├── If found: Attach Detection & associated Events to existing Incident                 │
│     └── If not found: Instantiate new Incident record in state `NEW`                        │
│                                                                                             │
│  4. Dynamic Multi-Vector Risk Calculation                                                   │
│     ├── RiskEngine (`backend/app/risk/engine.py`) recalculates:                             │
│     │   - Base severity sum (Critical=40, High=25, Medium=15, Low=5)                        │
│     │   - MITRE Tactic diversity multiplier (1.0x to 1.35x across kill chain)               │
│     │   - Privilege & root target penalty (+15 points)                                      │
│     ├── Generate human-readable `risk_explanation` string                                   │
│     ├── Update Incident severity rating (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`)            │
│     └── Emit WebSocket `INCIDENT_UPDATED`                                                   │
│                                                                                             │
│  5. MITRE ATT&CK Matrix Consolidation                                                       │
│     ├── Aggregate unique Technique IDs from all associated detections                       │
│     └── Map to full descriptive catalog (`backend/app/mitre/mapper.py`)                     │
│                                                                                             │
│  6. AI-Assisted Deep Investigation (On-Demand / Automated)                                  │
│     ├── Extract structured incident context (title, detections, timeline, raw logs)        │
│     ├── Execute `analyze_incident_safely()` via configured provider:                        │
│     │   - Google Gemini 2.5 Flash (`google-genai` SDK)                                      │
│     │   - Local LLMs (Ollama / vLLM / Qwen 2.5 via `/v1/chat/completions`)                 │
│     │   - Resilient Fallback (Deterministic SOC Security Analyst)                           │
│     ├── Enforce strict Anti-Hallucination JSON schema                                       │
│     ├── Persist analysis to DB table `ai_analyses`                                          │
│     └── Emit WebSocket `AI_ANALYSIS_COMPLETED`                                              │
│                                                                                             │
│  7. Real-Time Presentation & Export                                                         │
│     ├── Update React SOC Dashboard in real-time (< 100ms via `/ws`)                         │
│     ├── Interactive timeline visualization, evidence drill-down, MITRE matrix inspector     │
│     └── Printable Executive HTML/PDF Security Reports (`/api/reports/incident/{id}`)        │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Performance & Sliding Window Details

1. **Sliding Time Windows:**
   - **SSH Brute Force:** 5-minute sliding window querying past events on the same host/IP.
   - **Port Scan Reconnaissance:** 3-minute sliding window counting unique probed ports.
   - **Incident Correlation:** 30-minute sliding window grouping alerts from identical host or attacker IP.

2. **Concurrency & Thread Safety:**
   - FastAPI uses asynchronous non-blocking event loops for API endpoints.
   - Database sessions use scoped session pools (`get_db` dependency with auto-commit/close semantics).
   - In-memory WebSocket connections handle instant broadcasting without blocking event ingestion.
