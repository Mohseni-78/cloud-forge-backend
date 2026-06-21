from fastapi import FastAPI

from app.core.config import get_settings
from app.modules.auth.routes import router as auth_routes
from app.modules.health.routes import router as health_routes

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
)

app.include_router(health_routes, tags=["health"])
app.include_router(auth_routes, prefix="/auth", tags=["auth"])
