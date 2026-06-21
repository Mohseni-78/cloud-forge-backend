from fastapi import APIRouter, HTTPException, status

from app.core.config import get_settings
from app.db.session import check_database_connection
from app.integrations.redis import check_redis_connection

settings = get_settings()

router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.environment,
    }


@router.get("/version")
def version():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
    }


@router.get("/health/database")
def database_health_check():
    try:
        check_database_connection()
        return {"status": "ok", "database": "connected"}

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "error",
                "database": "not connected",
                "reason": str(error),
            },
        )


@router.get("/health/redis")
def redis_health_check():
    try:
        check_redis_connection()
        return {"status": "ok", "database": "connected"}
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "error",
                "database": "not connected",
                "reason": str(error),
            },
        )
