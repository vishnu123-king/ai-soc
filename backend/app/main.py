import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database.connection import engine, init_db, SessionLocal
from backend.app.models.user import User
from backend.app.models.agent import Agent
from backend.app.models.event import Event
from backend.app.auth.security import get_password_hash
from backend.app.api import api_router
from backend.app.websocket_manager import ws_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("aisoc.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AI-SOC database and schema...")
    init_db()
    
    db: Session = SessionLocal()
    try:
        # Seed default administrative account
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@aisoc.local",
                hashed_password=get_password_hash("admin123"),
                role="ADMIN",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            logger.info("Default administrator account created: admin / admin123")

        # Seed initial operational baseline if brand new deployment
        agent_count = db.query(Agent).count()
        if agent_count == 0:
            logger.info("Seeding initial registered agents and educational baseline telemetry...")
            from backend.app.api.simulation import run_attack_simulation, SimulationRunRequest
            import asyncio

            # Run baseline simulation
            try:
                await run_attack_simulation(
                    SimulationRunRequest(scenario="ssh_brute_force", hostname="srv-linux-prod-01", agent_id="agent-prod-01"),
                    db
                )
            except Exception as sim_err:
                logger.warning(f"Initial baseline simulation skipped: {sim_err}")
    except Exception as e:
        logger.error(f"Error during startup seeding: {e}", exc_info=True)
    finally:
        db.close()

    logger.info(f"AI-SOC Central Platform v{settings.VERSION} online. AI Provider: {settings.AI_PROVIDER}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Central AI-SOC Platform: A Hybrid Rule-Based and Local LLM Framework for Linux Security Monitoring & Automated Incident Investigation",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api
app.include_router(api_router, prefix=settings.API_V1_STR)

# Mount Live WebSocket endpoints
@app.websocket("/ws")
@app.websocket("/ws/soc")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)
