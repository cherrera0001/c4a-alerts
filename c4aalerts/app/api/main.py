"""
C4A Alerts FastAPI Application

Main FastAPI application with middleware, routes, and configuration.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from c4aalerts.app.api.routes import health, workers, malware, auth, security_stats
from c4aalerts.app.api.middleware import setup_middlewares
from c4aalerts.app.monitoring.observability import observability
from c4aalerts.app.auth.jwt_auth import get_current_user

# Create FastAPI application
app = FastAPI(
    title="C4A Alerts API",
    description="Modular Threat Intelligence & Alerting Platform API with Zero-Trust Security",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configurar middlewares de seguridad y observabilidad
app = setup_middlewares(app)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],  # Configure appropriately for production
)

# Include routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(workers.router, prefix="/api/v1/workers", tags=["workers"])
app.include_router(malware.router, prefix="/api/v1/malware", tags=["malware"])
app.include_router(security_stats.router, prefix="/api/v1", tags=["security"])

# Endpoint de observabilidad
@app.get("/api/v1/observability", tags=["observability"])
async def get_observability_data(current_user = Depends(get_current_user)):
    """Obtener datos de observabilidad del sistema."""
    # Solo admin y analyst pueden acceder a observabilidad
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to access observability data"
        )
    return observability.get_observability_data()

# Endpoint de seguridad
@app.get("/api/v1/security/stats", tags=["security"])
async def get_security_stats(current_user = Depends(get_current_user)):
    """Obtener estadísticas de seguridad."""
    # Solo admin puede acceder a estadísticas de seguridad
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can access security statistics"
        )
    from c4aalerts.app.security.zero_trust import zero_trust_security
    return zero_trust_security.get_security_stats()

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "C4A Alerts API",
        "version": "2.0.0",
        "status": "running",
        "features": [
            "Zero-Trust Security",
            "Distributed Tracing",
            "Real-time Monitoring",
            "Malware Detection",
            "Behavioral Analysis"
        ]
    }
