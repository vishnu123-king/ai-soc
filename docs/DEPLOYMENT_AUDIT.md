# AI-SOC Central Platform — Deployment Audit

---

## 1. Process & Network Architecture

The AI-SOC deployment runs a coordinated dual-process architecture managed by a Node.js process orchestrator (`server.ts`):

```
                       ┌────────────────────────────┐
                       │   Ingress Proxy / Client   │
                       └─────────────┬──────────────┘
                                     │ Port 3000 (0.0.0.0)
                                     ▼
                      ┌──────────────────────────────┐
                      │  Node.js / Express Gateway   │
                      │         (server.ts)          │
                      └──┬────────────────────────┬──┘
                         │                        │
       /api, /docs, /ws  │                        │  SPA Frontend
     (Reverse Proxy HTTP)│                        │  (Static/Vite)
                         ▼                        ▼
       ┌───────────────────────────┐    ┌──────────────────┐
       │ FastAPI Python Backend    │    │ React SPA Client │
       │ (Port 8088 / 127.0.0.1)   │    │ (dist/index.html)│
       └───────────────────────────┘    └──────────────────┘
```

### Port Mapping & Security
- **Public Port:** `3000` (Bound to `0.0.0.0`, the only externally accessible port).
- **Internal FastAPI Port:** `8088` (Bound to `127.0.0.1`, protected from direct external exposure).
- **WebSocket Upgrade:** Express intercepts HTTP upgrade headers on `/ws` and proxies TCP sockets to FastAPI's WebSocket endpoint.

---

## 2. Environment Variables Configuration

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Host binding interface for Central Platform |
| `PORT` | `3000` | Public container ingress port |
| `FASTAPI_PORT` | `8088` | Internal loopback port for the Python backend |
| `DATABASE_URL` | `sqlite:///aisoc.db` | Connection string for SQLite or PostgreSQL (`postgresql://user:pass@host/db`) |
| `JWT_SECRET_KEY` | `aisoc-insecure-...` | Secret key for signing analyst JWT tokens |
| `AGENT_ENROLLMENT_KEY` | `aisoc-agent-enrollment-secret-key` | Shared secret for agent provisioning |
| `AI_PROVIDER` | `gemini` | Configured AI engine (`gemini`, `local`, `qwen`, `mock`) |
| `GEMINI_API_KEY` | *(empty)* | Google GenAI API Key for Gemini 2.5 Flash |
| `LOCAL_LLM_BASE_URL` | `http://localhost:11434/v1` | Base URL for local LLMs (Ollama / vLLM / LM Studio) |
| `LOCAL_LLM_MODEL` | `qwen2.5:7b` | Model name for local inference |

---

## 3. Production Build & Start Verification

1. **Build Step (`npm run build`):**
   - Bundles the frontend React application with Vite into `/dist`.
   - Bundles `server.ts` with `esbuild` into a single CommonJS artifact `dist/server.cjs`.
2. **Start Step (`npm start`):**
   - Launches `node dist/server.cjs`.
   - Automatically initializes Python environment, performs Alembic database migration and schema seeding, and starts Uvicorn with auto-recovery.
