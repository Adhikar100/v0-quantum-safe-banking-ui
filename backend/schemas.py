from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    email: EmailStr
    name: str
    account_number: str

class UserCreate(UserBase):
    pass

class UserResponse(UserBase):
    id: int
    balance: float
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

class TransferRequest(BaseModel):
    receiver_name: str
    receiver_account: str
    amount: float
    description: Optional[str] = None

class TransactionResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    amount: float
    status: str
    nist_approved: bool
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class QuantumKeyResponse(BaseModel):
    id: int
    key_type: str
    is_active: bool
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True
