"""
Main FastAPI application for the Linux Code Signing Toolkit API.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import time
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .database import create_tables
from .routers import signing, admin
from .models import HealthResponse, ErrorResponse

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Store application startup time
start_time = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Linux Code Signing Toolkit API")

    # Create database tables
    try:
        await create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

    logger.info("API server started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Linux Code Signing Toolkit API")

# Create FastAPI application
app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version=settings.api_version,
    debug=settings.debug,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID middleware
@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """Add unique request ID to each request."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    # Add request ID to response headers
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response

# Logging middleware
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log all requests."""
    start_time_req = time.time()

    # Get client IP
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")

    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} - "
        f"IP: {client_ip} - "
        f"Request ID: {getattr(request.state, 'request_id', 'unknown')}"
    )

    # Process request
    response = await call_next(request)

    # Calculate response time
    process_time = time.time() - start_time_req

    # Log response
    logger.info(
        f"Response: {response.status_code} - "
        f"Time: {process_time:.3f}s - "
        f"Request ID: {getattr(request.state, 'request_id', 'unknown')}"
    )

    return response

# Exception handler
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    request_id = getattr(request.state, 'request_id', 'unknown')

    logger.error(
        f"Unhandled exception in request {request_id}: {str(exc)}",
        exc_info=True
    )

    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_server_error",
            message="An internal server error occurred",
            details={"request_id": request_id}
        ).dict()
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    request_id = getattr(request.state, 'request_id', 'unknown')

    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.__class__.__name__.lower().replace('exception', ''),
            message=exc.detail,
            details={"request_id": request_id}
        ).dict()
    )

# Include routers
from .routers import signing, admin, operations, compliance
app.include_router(signing.router)
app.include_router(admin.router)
app.include_router(operations.router)
app.include_router(compliance.router)

# Health check endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Test database connection
        from .database import engine
        async with engine.begin() as conn:
            await conn.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"

    uptime = time.time() - start_time

    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        version=settings.api_version,
        timestamp=time.time(),
        database_status=db_status,
        uptime_seconds=uptime
    )

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Linux Code Signing Toolkit API",
        "version": settings.api_version,
        "description": settings.api_description,
        "author": "Ryan Coleman <coleman.ryan@gmail.com>",
        "docs_url": "/docs",
        "health_check": "/health"
    }

# API info endpoint
@app.get("/api/v1/info")
async def api_info():
    """API information endpoint."""
    return {
        "api_version": settings.api_version,
        "supported_signing_types": ["windows", "java", "air", "apple"],
        "supported_operations": ["sign", "verify", "unsign", "resign"],
        "max_file_size": settings.max_file_size,
        "allowed_extensions": settings.allowed_extensions,
        "rate_limits": {
            "per_minute": settings.rate_limit_per_minute,
            "per_hour": settings.rate_limit_per_hour
        }
    }

def main():
    """Main entry point for running the API server."""
    uvicorn.run(
        "codesign_api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )

if __name__ == "__main__":
    main()