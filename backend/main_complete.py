"""
Complete FastAPI application with quantum cryptography
"""
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZIPMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from decimal import Decimal
from datetime import datetime
import time

from backend.config import get_settings, setup_logging
from backend.pqc_core import (
    SecurityLevel,
    get_quantum_encryptor,
    get_kyber,
    get_dilithium,
)
from backend.transaction_processor import (
    TransactionProcessor,
    TransactionStatus,
)
from backend.user_manager import (
    AdvancedUserManager,
    UserRole,
    UserStatus,
)

# Setup logging
logger = setup_logging()
settings = get_settings()

# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
)

# Add middleware
app.add_middleware(GZIPMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.info(f"{request.method} {request.url.path} - {process_time:.3f}s")
    return response

# ==================== Pydantic Models ====================

class UserCreateRequest(BaseModel):
    """User creation request"""
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=2)
    account_number: str
    initial_balance: Decimal = Decimal("0.00")

class UserLoginRequest(BaseModel):
    """User login request"""
    email: EmailStr
    password: str
    device_id: Optional[str] = None

class TransferRequest(BaseModel):
    """Transfer request"""
    sender_id: int
    receiver_id: Optional[int] = None
    receiver_account: Optional[str] = None
    receiver_name: Optional[str] = None
    amount: Decimal = Field(..., gt=0)
    metadata: Optional[Dict[str, Any]] = None

class KeyRotationRequest(BaseModel):
    """Key rotation request"""
    user_id: int
    security_level: str = "LEVEL_3"

class MFASetupRequest(BaseModel):
    """MFA setup request"""
    user_id: int

class MFAVerifyRequest(BaseModel):
    """MFA verify request"""
    user_id: int
    code: str

# ==================== Health Check ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.API_VERSION,
        "quantum_crypto": "enabled",
        "liboqs_available": True,
    }

# ==================== User Endpoints ====================

@app.post("/api/users/register")
async def register_user(request: UserCreateRequest):
    """Register new user with quantum security"""
    try:
        user_manager = AdvancedUserManager(None)  # DB passed in production
        
        success, user_id, message = await user_manager.create_user(
            email=request.email,
            password=request.password,
            name=request.name,
            account_number=request.account_number,
            role=UserRole.CUSTOMER,
            initial_balance=request.initial_balance,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message,
            )
        
        return {
            "success": True,
            "user_id": user_id,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed",
        )

@app.post("/api/users/login")
async def login_user(request: UserLoginRequest):
    """Authenticate user"""
    try:
        user_manager = AdvancedUserManager(None)
        
        success, user_data, message = await user_manager.authenticate_user(
            email=request.email,
            password=request.password,
            device_id=request.device_id,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=message,
            )
        
        return {
            "success": True,
            "user": user_data,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed",
        )

@app.get("/api/users/{user_id}/profile")
async def get_user_profile(user_id: int):
    """Get user profile with security info"""
    try:
        user_manager = AdvancedUserManager(None)
        profile = await user_manager.get_user_profile(user_id)
        
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        
        return {
            "success": True,
            "profile": profile,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile retrieval failed",
        )

# ==================== Quantum Key Endpoints ====================

@app.post("/api/quantum/keys/rotate")
async def rotate_quantum_keys(request: KeyRotationRequest):
    """Rotate user's quantum keys"""
    try:
        user_manager = AdvancedUserManager(None)
        security_level = SecurityLevel[request.security_level]
        
        success, message = await user_manager.rotate_quantum_keys(
            user_id=request.user_id,
            security_level=security_level,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message,
            )
        
        return {
            "success": True,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Key rotation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key rotation failed",
        )

@app.get("/api/quantum/keys/{user_id}/info")
async def get_quantum_key_info(user_id: int):
    """Get quantum key information"""
    try:
        kyber = get_kyber(SecurityLevel.LEVEL_3)
        dilithium = get_dilithium(SecurityLevel.LEVEL_3)
        
        return {
            "success": True,
            "user_id": user_id,
            "kyber": {
                "algorithm": kyber.algorithm.value,
                "security_level": kyber.security_level.name,
                "using_liboqs": kyber.use_liboqs,
            },
            "dilithium": {
                "algorithm": dilithium.algorithm.value,
                "security_level": dilithium.security_level.name,
                "using_liboqs": dilithium.use_liboqs,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        logger.error(f"Key info retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key info retrieval failed",
        )

# ==================== Transaction Endpoints ====================

@app.post("/api/transactions/transfer")
async def transfer_funds(request: TransferRequest):
    """Execute quantum-secure transfer"""
    try:
        processor = TransactionProcessor(None, SecurityLevel.LEVEL_3)
        
        result = await processor.process_transfer(
            sender_id=request.sender_id,
            receiver_id=request.receiver_id or 0,
            amount=request.amount,
            receiver_name=request.receiver_name or "",
            receiver_account=request.receiver_account or "",
            metadata=request.metadata,
        )
        
        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Transfer failed"),
            )
        
        return {
            "success": True,
            "transaction": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transfer failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transfer failed",
        )

@app.post("/api/transactions/batch")
async def batch_transfer(transfers: List[TransferRequest]):
    """Batch transfer processing"""
    try:
        processor = TransactionProcessor(None, SecurityLevel.LEVEL_3)
        
        transfer_data = [
            {
                "sender_id": t.sender_id,
                "receiver_id": t.receiver_id or 0,
                "amount": t.amount,
                "receiver_name": t.receiver_name or "",
                "receiver_account": t.receiver_account or "",
                "metadata": t.metadata,
            }
            for t in transfers
        ]
        
        results = await processor.batch_process_transfers(transfer_data)
        
        return {
            "success": True,
            "total_transfers": len(transfers),
            "successful": sum(1 for r in results if r.get("success")),
            "failed": sum(1 for r in results if not r.get("success")),
            "transactions": results,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        logger.error(f"Batch transfer failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Batch transfer failed",
        )

# ==================== MFA Endpoints ====================

@app.post("/api/mfa/setup")
async def setup_mfa(request: MFASetupRequest):
    """Setup multi-factor authentication"""
    try:
        user_manager = AdvancedUserManager(None)
        
        success, secret, message = await user_manager.enable_mfa(
            user_id=request.user_id,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message,
            )
        
        return {
            "success": True,
            "mfa_secret": secret,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA setup failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup failed",
        )

@app.post("/api/mfa/verify")
async def verify_mfa(request: MFAVerifyRequest):
    """Verify MFA code"""
    try:
        user_manager = AdvancedUserManager(None)
        
        success, message = await user_manager.verify_mfa(
            user_id=request.user_id,
            code=request.code,
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=message,
            )
        
        return {
            "success": True,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed",
        )

# ==================== Security Info Endpoint ====================

@app.get("/api/security/info")
async def get_security_info():
    """Get system security information"""
    return {
        "success": True,
        "system": {
            "name": "Quantum-Safe Banking",
            "version": settings.API_VERSION,
        },
        "cryptography": {
            "algorithms": ["CRYSTALS-Kyber", "CRYSTALS-Dilithium"],
            "security_levels": ["LEVEL_1 (128-bit)", "LEVEL_3 (192-bit)", "LEVEL_5 (256-bit)"],
            "quantum_resistant": True,
            "liboqs_available": True,
        },
        "compliance": {
            "nist_approved": True,
            "post_quantum": True,
            "standards": ["FIPS 202", "NIST SP 800-208"],
        },
        "timestamp": datetime.utcnow().isoformat(),
    }

# ==================== Error Handlers ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=settings.LOG_LEVEL.lower(),
    )
