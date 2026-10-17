"""
FastAPI Main Application
Updated with normalized /reports routes
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from app.db.session import engine, Base
from app.api import auth
from app.api.endpoints import reports, discovery, schedules, scans, scan_groups, ws, dashboard, users, admin

# Create FastAPI app
app = FastAPI(
    title="Security Compliance Platform",
    description="Web Security Compliance Scanning Platform",
    version="2.0.0"
)

# Proxy Headers (Crucial for HTTPS behind Nginx)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Create database tables
Base.metadata.create_all(bind=engine)

# ==================== ROUTES ====================

# Authentication routes
app.include_router(
    auth.router,
    prefix="/api/auth",
    tags=["authentication"]
)

# Reports routes
app.include_router(
    reports.router,
    prefix="/api/reports",
    tags=["reports"]
)

# Discovery routes
app.include_router(
    discovery.router,
    prefix="/api",
    tags=["discovery"]
)

# Scans routes
app.include_router(
    scans.router,
    prefix="/api",
    tags=["scans"]
)

# Schedule routes
app.include_router(
    schedules.router,
    prefix="/api",
    tags=["schedules"]
)

# Scan Groups routes
app.include_router(
    scan_groups.router,
    prefix="/api",
    tags=["scan_groups"]
)

# Dashboard routes
app.include_router(
    dashboard.router,
    prefix="/api/dashboard",
    tags=["dashboard"]
)

# User management routes
app.include_router(
    users.router,
    prefix="/api/users",
    tags=["users"]
)

# Admin specific routes
app.include_router(
    admin.router,
    prefix="/api/admin",
    tags=["admin"]
)

# WebSocket and Logs routes
app.include_router(
    ws.router,
    prefix="/api/scans",
    tags=["scans_live"]
)

# Dedicated Discovery Feed
app.include_router(
    ws.discovery_router,
    prefix="/api/discovery-feed",
    tags=["discovery_live"]
)

# ==================== ROOT ENDPOINTS ====================

@app.get("/")
def root():
    """Root endpoint."""
    return {
        "message": "Security Compliance Platform API",
        "version": "2.0.0",
        "status": "operational"
    }

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "compliance-api"
    }

@app.get("/api/info")
def api_info():
    """API information."""
    return {
        "endpoints": {
            "auth": "/auth",
            "reports": "/reports",
            "health": "/health"
        },
        "features": [
            "User authentication",
            "Scan report management",
            "Live progress logs",
            "Report downloads (PDF, Excel, CSV)",
            "Scan control (stop, delete)"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
