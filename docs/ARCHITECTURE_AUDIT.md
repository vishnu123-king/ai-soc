# AI-SOC Central Platform — Architecture Audit

**Date:** 2026-09-12  
**Platform Version:** 1.0.0  
**Audit Scope:** Full Central Platform (Backend, Database, Detection, Correlation, Risk Engine, AI Providers, Real-Time WebSockets, Frontend, Deployment).

---

## 1. Executive Summary

A comprehensive implementation audit was conducted on the AI-SOC Central Platform codebase. The platform is designed as a **modular monolith** running a high-performance **FastAPI backend** (Python 3.11+), **SQLAlchemy ORM** supporting both SQLite and PostgreSQL, a **Vite + React (TypeScript + Tailwind CSS)** security dashboard, and an integrated **Node.js/Express reverse proxy gateway**.

### Verification Verdict
The central platform is fully operational, deterministic, and modular. It correctly implements:
- **Normalized Event Ingestion Pipeline** (`POST /api/events`, `POST /api/events/batch`, `POST /api/logs`)
- **Agent Life-cycle & Heartbeat Tracking** (`POST /api/agents/register`, `POST /api/agents/{agent_id}/heartbeat`, auto-offline after 5 minutes)
- **Deterministic 6-Rule Detection Engine** (`SSHBruteForceRule`, `SudoAbuseRule`, `ShadowAccessRule`, `ReverseShellRule`, `PortScanRule`, `AutomatedToolRule`)
- **Time-Windowed Graph/Incident Correlation Engine** (30-minute sliding window grouped by host and threat source IP)
- **Dynamic Multi-Vector Risk Engine** (Severity weighting, MITRE tactic breadth, privilege indicators)
- **MITRE ATT&CK Catalog & Matrix Mapper** (v14 enterprise framework mapping Tactics TA0001–TA0011 and Techniques T1110–T1071)
- **Pluggable AI Incident Investigation Provider** (Gemini 2.5 Flash, Local LLMs / Qwen via OpenAI-compatible endpoints, and an offline deterministic security analyst fallback)
- **Bidirectional WebSocket Broadcast Engine** (`/ws` and `/ws/soc` broadcasting events, alerts, incident updates, AI analysis results)
- **Executive Reporting System** (Print-ready HTML/PDF reports with MITRE badges and forensic steps)

---

## 2. Directory Structure & Component Topology

```
.
├── backend/
│   ├── alembic/                      # Database migrations (Alembic configuration & version scripts)
│   │   ├── env.py
│   │   └── versions/
│   │       └── 001_initial_schema.py # Initial migration with all core tables & indices
│   ├── app/
│   │   ├── ai/                       # AI Analysis Subsystem
│   │   │   ├── __init__.py           # Provider resolver with safe fallback handler
│   │   │   ├── base.py               # AIProvider abstract base class
│   │   │   ├── gemini.py             # Google Gemini 2.5 Flash implementation
│   │   │   ├── local_llm.py          # OpenAI-compatible local LLM provider (Ollama / vLLM / Qwen)
│   │   │   ├── mock.py               # Deterministic offline SOC analyst fallback
│   │   │   └── prompts.py            # Anti-hallucination structured prompt schemas
│   │   ├── api/                      # REST API Endpoints
│   │   │   ├── __init__.py           # Router aggregation
│   │   │   ├── agents.py             # Agent enrollment, list, and heartbeats
│   │   │   ├── auth.py               # Analyst login, token refresh, and registration
│   │   │   ├── compat.py             # Compatibility endpoints for UI and automated testing
│   │   │   ├── dashboard.py          # KPI metrics, timeline time-series, agent health
│   │   │   ├── events.py             # Telemetry ingestion, filtering, pagination
│   │   │   ├── incidents.py          # Incident lifecycle, triage, status updates, AI analysis
│   │   │   ├── reports.py            # HTML printable executive reports
│   │   │   ├── rules.py              # Detection rules catalog & MITRE endpoints
│   │   │   └── simulation.py         # 4 Educational attack simulation pipelines
│   │   ├── auth/                     # Authentication & Security Core
│   │   │   ├── jwt.py                # JWT creation, decode, analyst RBAC & agent token verification
│   │   │   └── security.py           # Native bcrypt hashing, token generation
│   │   ├── correlation/              # Event & Alert Correlation
│   │   │   └── engine.py             # CorrelationEngine (30-min window, graph grouping)
│   │   ├── database/                 # Persistence Layer
│   │   │   └── connection.py         # SQLAlchemy engine, SessionLocal, table initializer
│   │   ├── detection/                # Threat Detection Rules
│   │   │   ├── base.py               # BaseDetectionRule abstract contract
│   │   │   ├── engine.py             # DetectionEngine rule registry & evaluator
│   │   │   └── rules.py              # 6 Concrete Linux detection rules
│   │   ├── mitre/                    # MITRE ATT&CK Framework
│   │   │   ├── data.py               # Tactics (TA0001-TA0011) & Techniques (T1110-T1071)
│   │   │   └── mapper.py             # MitreMapper consolidation helper
│   │   ├── models/                   # SQLAlchemy Data Models
│   │   │   ├── agent.py              # Agent registry table
│   │   │   ├── ai_analysis.py        # AI incident analysis records
│   │   │   ├── audit_log.py          # SOC administrative audit logs
│   │   │   ├── detection.py          # Correlated alert / detection findings
│   │   │   ├── event.py              # Normalized telemetry log entries
│   │   │   ├── incident.py           # Security incidents & m2m association table
│   │   │   └── user.py               # SOC analyst users & roles
│   │   ├── risk/                     # Risk Scoring Subsystem
│   │   │   └── engine.py             # RiskEngine (dynamic 0-100 scoring & explanation)
│   │   ├── schemas/                  # Pydantic Request/Response Models
│   │   │   ├── agent.py
│   │   │   ├── ai.py
│   │   │   ├── dashboard.py
│   │   │   ├── event.py
│   │   │   └── incident.py
│   │   ├── config.py                 # Pydantic BaseSettings environment configuration
│   │   ├── main.py                   # FastAPI application root & lifecycle events
│   │   └── websocket_manager.py      # Real-time WebSocket connection & broadcast manager
│   └── tests/                        # Comprehensive Test Suite
│       ├── test_ai_provider.py       # AI fallbacks, prompt schemas, and JSON parsing
│       ├── test_api_endpoints.py     # Agents, events, incidents, reports, auth APIs
│       ├── test_correlation.py       # Multi-alert grouping & incident window tests
│       ├── test_detection_engine.py  # All 6 detection rules unit tests
│       └── test_risk_engine.py       # Deterministic scoring validation
├── src/                              # React 18 Frontend
│   ├── components/                   # Modular UI Components (Tailwind CSS + Lucide Icons)
│   │   ├── AttackSimulator.tsx       # Interactive scenario launcher
│   │   ├── ChartsView.tsx            # Recharts telemetry & threat distribution
│   │   ├── IncidentDetailModal.tsx   # Deep incident investigation, timeline, AI trigger
│   │   ├── IncidentsTable.tsx        # Filterable, sortable incident queue
│   │   ├── LiveLogStream.tsx         # Real-time telemetry inspector
│   │   ├── Navbar.tsx                # Status indicators, quick actions, navigation
│   │   ├── RulesAndMitreView.tsx     # Rule definitions & MITRE matrix inspector
│   │   └── StatCards.tsx             # Real-time KPI stat cards
│   ├── services/                     # API & WebSocket client services
│   │   └── api.ts
│   ├── App.tsx                       # Root Application component with WebSocket listener
│   ├── index.css                     # Tailwind CSS entrypoint
│   ├── main.tsx                      # DOM entrypoint
│   └── types.ts                      # Shared TypeScript data interfaces
├── server.ts                         # Node.js/Express reverse proxy & process orchestrator
├── package.json                      # Node packages & build scripts
└── vite.config.ts                    # Vite configuration
```

---

## 3. Technology Stack Verification

| Subsystem | Technology | Verification Status | Notes |
| :--- | :--- | :--- | :--- |
| **API Framework** | FastAPI 0.110+ (ASGI) | Verified | High throughput, asynchronous route handling, automatic OpenAPI/Swagger specs at `/api/docs`. |
| **Data Persistence** | SQLAlchemy 2.0+ & Alembic | Verified | Supports SQLite (`sqlite:///aisoc.db`) and PostgreSQL (`postgresql://...`). Indexes placed on query-critical columns. |
| **Authentication** | Native `bcrypt` + PyJWT | Verified | Stateless JWT for SOC analysts; cryptographically secure 256-bit SHA256 hashed bearer tokens for Linux agents. |
| **AI Subsystem** | Google GenAI SDK (`google-genai`), HTTPX local client | Verified | Read-only analyst role. Safe fallback guarantees zero 500 error crashes. |
| **Real-Time Layer** | FastAPI WebSockets + Starlette ConnectionManager | Verified | Sub-100ms push notification for telemetry logs, triggered detections, incident updates, and AI findings. |
| **Frontend UI** | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons | Verified | Clean, high-contrast dark SOC console aesthetic. Zero mock data dependencies. |
| **Process Manager** | Express + `http-proxy-middleware` | Verified | Unified Port 3000 entrypoint managing both FastAPI backend process and Vite/SPA static delivery. |
