from fastapi import APIRouter
from backend.app.api.health import router as health_router
from backend.app.api.agents import router as agents_router
from backend.app.api.events import router as events_router
from backend.app.api.detections import router as detections_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.simulation import router as simulation_router
from backend.app.api.reports import router as reports_router
from backend.app.api.auth import router as auth_router
from backend.app.api.rules import router as rules_router
from backend.app.api.compat import router as compat_router

api_router = APIRouter()

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(agents_router, prefix="/agents", tags=["Agents"])
api_router.include_router(events_router, prefix="/events", tags=["Events"])
api_router.include_router(detections_router, prefix="/detections", tags=["Detections"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(simulation_router, prefix="/simulation", tags=["Simulation"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(rules_router, tags=["Rules and MITRE"])
api_router.include_router(compat_router, tags=["Compatibility"])


