from fastapi import APIRouter, HTTPException
from schemas import UserResponse, UserCreate
from datetime import datetime

router = APIRouter()

@router.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate):
    """Register a new banking user"""
    return {
        "id": 1,
        "email": user.email,
        "name": user.name,
        "account_number": user.account_number,
        "balance": 0.0,
        "is_verified": False,
        "created_at": datetime.utcnow()
    }

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    """Get user details"""
    return {
        "id": user_id,
        "email": "user@example.com",
        "name": "John Doe",
        "account_number": "1234567890",
        "balance": 5000.0,
        "is_verified": True,
        "created_at": datetime.utcnow()
    }

@router.put("/{user_id}/verify")
async def verify_user(user_id: int):
    """Verify user identity"""
    return {
        "user_id": user_id,
        "is_verified": True,
        "message": "User verified successfully"
    }
