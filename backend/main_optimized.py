"""
Optimized main FastAPI application with middleware, error handling, and monitoring
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZIPMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging
import time
from typing import Callable

from config import get_settings, logger
from database_optimized import init_db
from advanced_security import get_quantum_engine, get_transaction_encryptor
from cache import get_cache_manager

# Import routers
from routers import transactions, users, security

settings = get_settings()

# Setup logging
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

class RequestLoggingMiddleware:
    """Custom middleware for request/response logging"""
    
    def __init__(self, app: FastAPI):
        self.app = app
    
    async def __call__(self, request: Request, call_next: Callable):
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        # Log request metrics
        process_time = time.time() - start_time
        logger.info(
            f"{request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.3f}s"
        )
        
        response.headers["X-Process-Time"] = str(process_time)
        return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    logger.info("🚀 Quantum-Safe Banking API starting")
    init_db()
    get_quantum_engine()
    get_transaction_encryptor()
    get_cache_manager()
    logger.info("✅ Initialization complete")
    
    yield
    
    # Shutdown
    logger.info("🛑 Quantum-Safe Banking API shutting down")

app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Compression middleware
app.add_middleware(GZIPMiddleware, minimum_size=1000)

# Custom request logging middleware
app.middleware("http")(RequestLoggingMiddleware(app))

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )

# Include routers
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(transactions.router, prefix="/api/transactions", tags=["Transactions"])
app.include_router(security.router, prefix="/api/security", tags=["Security"])

# Health check endpoint
@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "quantum_support": "CRYSTALS-Kyber & Dilithium"
    }

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": settings.API_DESCRIPTION,
        "docs": "/api/docs",
        "endpoints": {
            "health": "/api/health",
            "users": "/api/users",
            "transactions": "/api/transactions",
            "security": "/api/security"
        }
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info("API startup event triggered")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("API shutdown event triggered")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=settings.LOG_LEVEL.lower()
    )
