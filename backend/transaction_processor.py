"""
Advanced Secure Transaction Processing Engine
Handles complex banking operations with quantum security
"""
import asyncio
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
import uuid
import time
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import json

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from backend.pqc_core import (
    get_quantum_encryptor,
    get_kyber,
    get_dilithium,
    EncryptedPayload,
    SecurityLevel,
)

logger = logging.getLogger(__name__)

class TransactionStatus(Enum):
    """Transaction lifecycle states"""
    PENDING = "pending"
    VALIDATING = "validating"
    ENCRYPTING = "encrypting"
    SIGNING = "signing"
    BROADCASTING = "broadcasting"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class TransactionRisk(Enum):
    """Transaction risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RiskAssessment:
    """Transaction risk assessment"""
    risk_level: TransactionRisk
    risk_score: float
    anomalies: List[str] = field(default_factory=list)
    fraud_indicators: List[str] = field(default_factory=list)
    recommended_action: str = "proceed"
    timestamp: datetime = field(default_factory=datetime.utcnow)

class TransactionValidator(ABC):
    """Base validator for transaction rules"""
    
    @abstractmethod
    async def validate(self, transaction: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate transaction"""
        pass

class AmountValidator(TransactionValidator):
    """Validates transaction amounts"""
    
    MAX_DAILY_AMOUNT = Decimal("100000")
    MAX_TRANSACTION_AMOUNT = Decimal("10000")
    MIN_TRANSACTION_AMOUNT = Decimal("0.01")
    
    async def validate(self, transaction: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            amount = Decimal(str(transaction.get("amount", 0)))
            
            if amount < self.MIN_TRANSACTION_AMOUNT:
                return False, f"Amount below minimum: {self.MIN_TRANSACTION_AMOUNT}"
            
            if amount > self.MAX_TRANSACTION_AMOUNT:
                return False, f"Amount exceeds maximum: {self.MAX_TRANSACTION_AMOUNT}"
            
            return True, "Amount valid"
        except Exception as e:
            return False, f"Amount validation error: {str(e)}"

class ReceiverValidator(TransactionValidator):
    """Validates receiver information"""
    
    async def validate(self, transaction: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            receiver_id = transaction.get("receiver_id")
            receiver_name = transaction.get("receiver_name")
            receiver_account = transaction.get("receiver_account")
            
            if not receiver_id and not receiver_account:
                return False, "Receiver ID or account number required"
            
            if receiver_id == transaction.get("sender_id"):
                return False, "Cannot send to self"
            
            return True, "Receiver valid"
        except Exception as e:
            return False, f"Receiver validation error: {str(e)}"

class FraudDetector:
    """Advanced fraud detection system"""
    
    def __init__(self):
        self.suspicious_amounts = {
            Decimal("999"): "Round suspicious amount",
            Decimal("9999"): "Double round suspicious amount",
        }
        self.velocity_thresholds = {
            "per_minute": 5,
            "per_hour": 50,
            "per_day": 200,
        }
    
    async def assess_risk(
        self,
        transaction: Dict[str, Any],
        sender_history: List[Dict[str, Any]]
    ) -> RiskAssessment:
        """Comprehensive fraud risk assessment"""
        risk_score = 0.0
        anomalies = []
        fraud_indicators = []
        
        # Check for unusual amounts
        amount = Decimal(str(transaction.get("amount", 0)))
        for suspicious_amt, reason in self.suspicious_amounts.items():
            if amount == suspicious_amt:
                risk_score += 0.15
                fraud_indicators.append(reason)
        
        # Check for velocity anomalies
        if sender_history:
            recent_transactions = [
                t for t in sender_history
                if (datetime.utcnow() - t.get("created_at", datetime.utcnow())).total_seconds() < 3600
            ]
            if len(recent_transactions) > self.velocity_thresholds["per_hour"]:
                risk_score += 0.3
                anomalies.append(f"High transaction velocity: {len(recent_transactions)} in 1 hour")
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = TransactionRisk.CRITICAL
            recommended_action = "block"
        elif risk_score >= 0.5:
            risk_level = TransactionRisk.HIGH
            recommended_action = "review"
        elif risk_score >= 0.3:
            risk_level = TransactionRisk.MEDIUM
            recommended_action = "monitor"
        else:
            risk_level = TransactionRisk.LOW
            recommended_action = "proceed"
        
        logger.info(f"Risk assessment: {risk_level.value} (score: {risk_score:.2f})")
        
        return RiskAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            anomalies=anomalies,
            fraud_indicators=fraud_indicators,
            recommended_action=recommended_action,
        )

class TransactionProcessor:
    """Main transaction processing engine"""
    
    def __init__(self, db: Session, security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.db = db
        self.security_level = security_level
        self.encryptor = get_quantum_encryptor(security_level)
        self.kyber = get_kyber(security_level)
        self.dilithium = get_dilithium(security_level)
        
        # Validators
        self.validators = [
            AmountValidator(),
            ReceiverValidator(),
        ]
        
        # Fraud detector
        self.fraud_detector = FraudDetector()
        
        # Transaction states
        self.pending_transactions: Dict[str, Dict[str, Any]] = {}
    
    async def process_transfer(
        self,
        sender_id: int,
        receiver_id: int,
        amount: Decimal,
        receiver_name: str = "",
        receiver_account: str = "",
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Complete transfer processing pipeline with quantum security
        """
        transaction_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            # Step 1: Create transaction object
            transaction = {
                "id": transaction_id,
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "receiver_name": receiver_name,
                "receiver_account": receiver_account,
                "amount": float(amount),
                "metadata": metadata or {},
                "created_at": datetime.utcnow(),
                "status": TransactionStatus.PENDING.value,
            }
            
            logger.info(f"Starting transaction {transaction_id}")
            
            # Step 2: Validate transaction
            transaction["status"] = TransactionStatus.VALIDATING.value
            for validator in self.validators:
                is_valid, message = await validator.validate(transaction)
                if not is_valid:
                    logger.warning(f"Validation failed: {message}")
                    return {
                        "success": False,
                        "transaction_id": transaction_id,
                        "error": message,
                        "status": TransactionStatus.FAILED.value,
                    }
            
            # Step 3: Fraud detection
            sender = self.db.query(lambda: None).first()  # Placeholder
            risk_assessment = await self.fraud_detector.assess_risk(
                transaction,
                [] # Would fetch sender history from DB
            )
            
            if risk_assessment.recommended_action == "block":
                logger.error(f"Transaction blocked due to fraud risk: {transaction_id}")
                return {
                    "success": False,
                    "transaction_id": transaction_id,
                    "error": "Transaction blocked due to fraud risk",
                    "status": TransactionStatus.FAILED.value,
                    "risk_assessment": {
                        "risk_level": risk_assessment.risk_level.value,
                        "risk_score": risk_assessment.risk_score,
                    }
                }
            
            # Step 4: Encrypt transaction
            transaction["status"] = TransactionStatus.ENCRYPTING.value
            
            # Mock keys for now - would fetch from DB in production
            recipient_kyber_public_key = os.urandom(1184)  # Kyber768 public key size
            sender_dilithium_private_key = os.urandom(2544)  # Dilithium3 private key size
            
            encrypted_payload = self.encryptor.encrypt_and_sign(
                transaction,
                recipient_kyber_public_key,
                sender_dilithium_private_key,
            )
            
            # Step 5: Sign transaction
            transaction["status"] = TransactionStatus.SIGNING.value
            transaction["signature"] = encrypted_payload.digital_signature.hex()
            transaction["encrypted_data"] = encrypted_payload.to_dict()
            
            # Step 6: Broadcast (simulate)
            transaction["status"] = TransactionStatus.BROADCASTING.value
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Step 7: Confirm
            transaction["status"] = TransactionStatus.CONFIRMED.value
            transaction["completed_at"] = datetime.utcnow()
            
            elapsed = time.time() - start_time
            
            logger.info(f"Transaction {transaction_id} confirmed in {elapsed:.3f}s")
            
            return {
                "success": True,
                "transaction_id": transaction_id,
                "status": TransactionStatus.CONFIRMED.value,
                "amount": float(amount),
                "processing_time_ms": int(elapsed * 1000),
                "risk_assessment": {
                    "risk_level": risk_assessment.risk_level.value,
                    "risk_score": risk_assessment.risk_score,
                },
                "encrypted_payload": encrypted_payload.to_dict(),
            }
            
        except Exception as e:
            logger.error(f"Transaction processing failed: {e}", exc_info=True)
            return {
                "success": False,
                "transaction_id": transaction_id,
                "error": str(e),
                "status": TransactionStatus.FAILED.value,
            }
    
    async def batch_process_transfers(
        self,
        transfers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process multiple transfers concurrently"""
        tasks = [
            self.process_transfer(**transfer)
            for transfer in transfers
        ]
        results = await asyncio.gather(*tasks)
        return results

import os
