"""
Optimized transaction router with caching, validation, and proper error handling
"""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from datetime import datetime, timedelta
from typing import List, Optional
import logging
import uuid

from database_optimized import get_db_session
from models_optimized import Transaction, User, AuditLog
from schemas import TransferRequest, TransactionResponse, TransactionHistoryResponse
from advanced_security import get_transaction_encryptor, get_quantum_engine
from cache import get_cache_manager

logger = logging.getLogger(__name__)
router = APIRouter()

cache_manager = get_cache_manager()
encryptor = get_transaction_encryptor()
quantum_engine = get_quantum_engine()

@router.get("/demo/sender")
async def get_demo_sender(db: Session = Depends(get_db_session)):
    """Get or create demo sender user for testing"""
    try:
        # Check if demo user exists
        demo_user = db.query(User).filter(User.email == "demo@quantumbank.io").first()
        
        if not demo_user:
            # Create demo user
            demo_user = User(
                email="demo@quantumbank.io",
                username="demouser",
                account_number="1000000000",
                balance=10000.0,
                kyber_public_key="demo_kyber_key",
                kyber_private_key="demo_kyber_private",
                dilithium_public_key="demo_dilithium_key",
                dilithium_private_key="demo_dilithium_private"
            )
            db.add(demo_user)
            db.commit()
            db.refresh(demo_user)
            logger.info(f"Created demo user with ID {demo_user.id}")
        
        return {
            "id": demo_user.id,
            "email": demo_user.email,
            "username": demo_user.username,
            "account_number": demo_user.account_number,
            "balance": demo_user.balance
        }
    except Exception as e:
        logger.error(f"Demo sender creation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create demo sender")

async def get_or_create_receiver(account_number: str, receiver_name: str, db: Session):
    """Get existing receiver or create new one"""
    receiver = db.query(User).filter(User.account_number == account_number).first()
    
    if not receiver:
        # Create new receiver
        receiver = User(
            email=f"{account_number}@quantumbank.io",
            username=receiver_name.lower().replace(" ", "_"),
            account_number=account_number,
            balance=0.0,
            kyber_public_key="receiver_kyber_key",
            kyber_private_key="receiver_kyber_private",
            dilithium_public_key="receiver_dilithium_key",
            dilithium_private_key="receiver_dilithium_private"
        )
        db.add(receiver)
        db.commit()
        db.refresh(receiver)
        logger.info(f"Created receiver user {account_number}")
    
    return receiver

@router.post("/transfer", response_model=TransactionResponse)
async def create_transfer(
    transfer: TransferRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db_session)
):
    """
    Create a quantum-safe encrypted transaction
    Implements Kyber for encryption and Dilithium for signing
    Simplified to accept transfer data and auto-create sender/receiver
    """
    try:
        sender = db.query(User).filter(User.email == "demo@quantumbank.io").first()
        if not sender:
            sender = User(
                email="demo@quantumbank.io",
                username="demouser",
                account_number="1000000000",
                balance=10000.0,
                kyber_public_key="demo_kyber_key",
                kyber_private_key="demo_kyber_private",
                dilithium_public_key="demo_dilithium_key",
                dilithium_private_key="demo_dilithium_private"
            )
            db.add(sender)
            db.commit()
            db.refresh(sender)
        
        if sender.balance < transfer.amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        receiver = await get_or_create_receiver(
            transfer.receiver_account,
            transfer.receiver_name,
            db
        )
        
        # Encrypt transaction data
        transaction_data = {
            "sender_id": sender.id,
            "receiver_id": receiver.id,
            "amount": transfer.amount,
            "description": transfer.description or "",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        encrypted_tx = encryptor.encrypt_transaction(
            transaction_data,
            receiver.kyber_public_key.encode() if receiver.kyber_public_key else b""
        )
        
        # Create transaction record
        tx = Transaction(
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=transfer.amount,
            status="pending",
            encrypted_data=encrypted_tx.ciphertext.hex(),
            quantum_signature=encrypted_tx.signature.hex(),
            nonce=encrypted_tx.nonce.hex()
        )
        
        db.add(tx)
        db.commit()
        db.refresh(tx)
        
        # Log audit
        audit = AuditLog(
            user_id=sender.id,
            action="TRANSFER_INITIATED",
            details=f"Transfer to {receiver.account_number} for ${transfer.amount}"
        )
        db.add(audit)
        db.commit()
        
        # Invalidate cache
        background_tasks.add_task(cache_manager.invalidate_user_cache, sender.id)
        
        logger.info(f"Transaction {tx.id} created successfully")
        
        return TransactionResponse(
            id=tx.id,
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=transfer.amount,
            status="pending",
            created_at=tx.created_at
        )
    
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Transaction creation failed: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Transaction failed: {str(e)}")

@router.get("/history/{user_id}")
async def get_transaction_history(
    user_id: int,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db_session)
):
    """
    Get user's transaction history with pagination
    Includes caching for performance
    """
    try:
        cache_key = f"user_{user_id}_history_{limit}_{offset}"
        cached = await cache_manager.backend.get(cache_key)
        if cached:
            return cached
        
        # Query transactions
        transactions = db.query(Transaction).filter(
            (Transaction.sender_id == user_id) | (Transaction.receiver_id == user_id)
        ).order_by(desc(Transaction.created_at)).offset(offset).limit(limit).all()
        
        # Calculate totals
        sent = db.query(Transaction).filter(
            (Transaction.sender_id == user_id) & (Transaction.status == "completed")
        ).with_entities(db.func.sum(Transaction.amount)).scalar() or 0.0
        
        received = db.query(Transaction).filter(
            (Transaction.receiver_id == user_id) & (Transaction.status == "completed")
        ).with_entities(db.func.sum(Transaction.amount)).scalar() or 0.0
        
        result = {
            "user_id": user_id,
            "transactions": [
                {
                    "id": tx.id,
                    "sender_id": tx.sender_id,
                    "receiver_id": tx.receiver_id,
                    "amount": tx.amount,
                    "status": tx.status,
                    "created_at": tx.created_at
                }
                for tx in transactions
            ],
            "total_sent": sent,
            "total_received": received,
            "pagination": {"limit": limit, "offset": offset}
        }
        
        # Cache result
        await cache_manager.backend.set(cache_key, result, ttl=300)
        
        return result
    
    except Exception as e:
        logger.error(f"History retrieval failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve history")

@router.get("/{transaction_id}", response_model=TransactionResponse)
async def get_transaction(
    transaction_id: int,
    db: Session = Depends(get_db_session)
):
    """Get transaction details"""
    cache_key = f"transaction_{transaction_id}"
    cached = await cache_manager.backend.get(cache_key)
    if cached:
        return cached
    
    tx = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    result = TransactionResponse(
        id=tx.id,
        sender_id=tx.sender_id,
        receiver_id=tx.receiver_id,
        amount=tx.amount,
        status=tx.status,
        created_at=tx.created_at
    )
    
    await cache_manager.backend.set(cache_key, result, ttl=600)
    return result

@router.patch("/{transaction_id}/confirm")
async def confirm_transaction(
    transaction_id: int,
    db: Session = Depends(get_db_session)
):
    """Confirm and complete transaction"""
    tx = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    try:
        sender = db.query(User).filter(User.id == tx.sender_id).first()
        receiver = db.query(User).filter(User.id == tx.receiver_id).first()
        
        # Update balances
        sender.balance -= tx.amount
        receiver.balance += tx.amount
        
        tx.status = "completed"
        tx.completed_at = datetime.utcnow()
        
        db.commit()
        
        # Invalidate caches
        await cache_manager.invalidate_transaction_cache(transaction_id)
        await cache_manager.invalidate_user_cache(tx.sender_id)
        await cache_manager.invalidate_user_cache(tx.receiver_id)
        
        logger.info(f"Transaction {transaction_id} confirmed")
        
        return {"status": "completed", "transaction_id": transaction_id}
    
    except Exception as e:
        logger.error(f"Transaction confirmation failed: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Confirmation failed: {str(e)}")
