"""
C4A Alerts FastAPI Application

Main FastAPI application with middleware, routes, and configuration.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from c4aalerts.app.api.routes import health, workers

# Create FastAPI application
app = FastAPI(
    title="C4A Alerts API",
    description="Modular Threat Intelligence & Alerting Platform API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

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
app.include_router(workers.router, prefix="/api/v1/workers", tags=["workers"])

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "C4A Alerts API",
        "version": "2.0.0",
        "status": "running"
    }
