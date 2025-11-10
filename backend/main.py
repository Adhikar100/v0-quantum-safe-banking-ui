from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import logging
from database import engine, SessionLocal, Base
from models import User, Transaction, QuantumKey
from schemas import (
    TransferRequest,
    TransactionResponse,
    UserResponse,
    QuantumKeyResponse
)
from security import (
    encrypt_transaction,
    decrypt_transaction,
    generate_quantum_key,
    verify_quantum_signature,
)
from routers import transactions, users, security

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Quantum-Safe Banking API started")
    yield
    logger.info("Quantum-Safe Banking API shutdown")

app = FastAPI(
    title="Quantum-Safe Banking API",
    description="Secure banking system with CRYSTALS-Kyber & Dilithium encryption",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Include routers
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(transactions.router, prefix="/api/transactions", tags=["transactions"])
app.include_router(security.router, prefix="/api/security", tags=["security"])

# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "Quantum-Safe Banking API"}

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Quantum-Safe Banking API",
        "version": "1.0.0",
        "security": "CRYSTALS-Kyber & Dilithium"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
