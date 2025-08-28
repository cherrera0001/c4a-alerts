"""
Health check endpoints.
"""

from datetime import datetime

from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

@router.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check endpoint."""
    # TODO: Add database, Redis, and other service checks
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "services": {
            "api": "healthy",
            "database": "healthy",  # TODO: Implement actual check
            "redis": "healthy",     # TODO: Implement actual check
            "workers": "healthy"    # TODO: Implement actual check
        }
    }
