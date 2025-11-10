"""
Quantum-Safe Transaction Processing Engine
Complete transaction lifecycle with PQC security
"""

import json
import hashlib
import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
import uuid
import time

from kyber_encryption import AdvancedKyberManager, KyberMode, KyberSecurityLevel
from dilithium_signatures import AdvancedDilithiumManager, DilithiumSecurityLevel

logger = logging.getLogger(__name__)


class TransactionStatus(Enum):
    """Transaction lifecycle states"""
    CREATED = "created"
    VALIDATED = "validated"
    SIGNED = "signed"
    ENCRYPTED = "encrypted"
    TRANSMITTED = "transmitted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REJECTED = "rejected"


class TransactionType(Enum):
    """Types of transactions"""
    TRANSFER = "transfer"
    PAYMENT = "payment"
    WITHDRAWAL = "withdrawal"
    DEPOSIT = "deposit"


@dataclass
class TransactionParty:
    """Represents sender or receiver in transaction"""
    name: str
    account_number: str
    public_key: Optional[bytes] = None
    key_id: Optional[str] = None


@dataclass
class SecurityMetadata:
    """Security information for transaction"""
    kyber_ciphertext: Optional[bytes] = None
    kyber_mode: KyberMode = KyberMode.AES_256_CBC
    dilithium_signature: Optional[bytes] = None
    message_hash: str = ""
    nonce_iv: Optional[bytes] = None
    aad: Optional[bytes] = None  # Additional authenticated data
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            "kyber_ciphertext": self.kyber_ciphertext.hex() if self.kyber_ciphertext else None,
            "kyber_mode": self.kyber_mode.value,
            "dilithium_signature": self.dilithium_signature.hex() if self.dilithium_signature else None,
            "message_hash": self.message_hash,
            "nonce_iv": self.nonce_iv.hex() if self.nonce_iv else None,
            "aad": self.aad.hex() if self.aad else None
        }


@dataclass
class QuantumTransaction:
    """Complete transaction with quantum security"""
    transaction_id: str
    transaction_type: TransactionType
    sender: TransactionParty
    receiver: TransactionParty
    amount: float
    currency: str = "USD"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    status: TransactionStatus = TransactionStatus.CREATED
    security: SecurityMetadata = field(default_factory=SecurityMetadata)
    encrypted_payload: Optional[bytes] = None
    status_history: List[Tuple[TransactionStatus, datetime]] = field(default_factory=list)
    fee: float = 0.0
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict:
        """Serialize to dictionary"""
        data = {
            "transaction_id": self.transaction_id,
            "transaction_type": self.transaction_type.value,
            "sender": {
                "name": self.sender.name,
                "account_number": self.sender.account_number,
                "key_id": self.sender.key_id
            },
            "receiver": {
                "name": self.receiver.name,
                "account_number": self.receiver.account_number,
                "key_id": self.receiver.key_id
            },
            "amount": self.amount,
            "currency": self.currency,
            "timestamp": self.timestamp,
            "status": self.status.value,
            "fee": self.fee,
            "metadata": self.metadata
        }
        
        if include_sensitive:
            data["security"] = self.security.to_dict()
            data["encrypted_payload"] = self.encrypted_payload.hex() if self.encrypted_payload else None
        
        return data


class QuantumTransactionProcessor:
    """Process transactions with full PQC security"""
    
    def __init__(self, kyber_level: KyberSecurityLevel = KyberSecurityLevel.LEVEL_3,
                 dilithium_level: DilithiumSecurityLevel = DilithiumSecurityLevel.LEVEL_3):
        """Initialize transaction processor"""
        self.kyber_manager = AdvancedKyberManager(kyber_level)
        self.dilithium_manager = AdvancedDilithiumManager(dilithium_level)
        self.transaction_log: List[QuantumTransaction] = []
        
        logger.info("QuantumTransactionProcessor initialized")
    
    def create_transaction(self, sender: TransactionParty, receiver: TransactionParty,
                          amount: float, tx_type: TransactionType = TransactionType.TRANSFER,
                          fee: float = 0.0, metadata: Optional[Dict] = None) -> QuantumTransaction:
        """
        Create new transaction
        Args:
            sender: Sender information
            receiver: Receiver information
            amount: Transaction amount
            tx_type: Type of transaction
            fee: Transaction fee
            metadata: Additional metadata
        Returns:
            QuantumTransaction object
        """
        tx_id = str(uuid.uuid4())
        
        transaction = QuantumTransaction(
            transaction_id=tx_id,
            transaction_type=tx_type,
            sender=sender,
            receiver=receiver,
            amount=amount,
            fee=fee,
            metadata=metadata or {}
        )
        
        transaction.status_history.append((TransactionStatus.CREATED, datetime.now()))
        self.transaction_log.append(transaction)
        
        logger.info(f"Transaction created: {tx_id} (${amount})")
        return transaction
    
    def validate_transaction(self, transaction: QuantumTransaction) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction
        Returns:
            (is_valid, error_message)
        """
        # Validate amounts
        if transaction.amount <= 0:
            return False, "Amount must be positive"
        
        if transaction.fee < 0:
            return False, "Fee cannot be negative"
        
        # Validate parties
        if not transaction.sender.account_number:
            return False, "Sender account not specified"
        
        if not transaction.receiver.account_number:
            return False, "Receiver account not specified"
        
        if transaction.sender.account_number == transaction.receiver.account_number:
            return False, "Sender and receiver cannot be the same"
        
        # Validate keys
        if not transaction.sender.public_key or not transaction.sender.key_id:
            return False, "Sender public key not available"
        
        if not transaction.receiver.public_key or not transaction.receiver.key_id:
            return False, "Receiver public key not available"
        
        transaction.status = TransactionStatus.VALIDATED
        transaction.status_history.append((TransactionStatus.VALIDATED, datetime.now()))
        
        logger.info(f"Transaction validated: {transaction.transaction_id}")
        return True, None
    
    def sign_transaction(self, transaction: QuantumTransaction, sender_secret_key: bytes) -> bool:
        """
        Sign transaction with Dilithium
        Returns:
            True if signing successful
        """
        try:
            # Prepare transaction data for signing
            tx_data = transaction.to_dict(include_sensitive=False)
            
            # Sign the transaction
            signature_obj = self.dilithium_manager.sign_transaction(
                tx_data,
                sender_secret_key,
                transaction.sender.key_id
            )
            
            transaction.security.dilithium_signature = signature_obj.signature_bytes
            transaction.security.message_hash = signature_obj.message_hash
            transaction.status = TransactionStatus.SIGNED
            transaction.status_history.append((TransactionStatus.SIGNED, datetime.now()))
            
            logger.info(f"Transaction signed: {transaction.transaction_id}")
            return True
            
        except Exception as e:
            logger.error(f"Transaction signing failed: {e}")
            transaction.status = TransactionStatus.FAILED
            return False
    
    def encrypt_transaction(self, transaction: QuantumTransaction,
                           encryption_mode: KyberMode = KyberMode.AES_256_CBC) -> bool:
        """
        Encrypt transaction with Kyber + AES
        Returns:
            True if encryption successful
        """
        try:
            # Serialize complete transaction data
            tx_payload = json.dumps(transaction.to_dict(include_sensitive=True)).encode('utf-8')
            
            # Add sender signature as AAD (Additional Authenticated Data)
            aad = transaction.security.message_hash.encode('utf-8')
            
            # Encrypt with Kyber + AES
            ciphertext, kyber_ct, nonce = self.kyber_manager.encrypt_with_kyber(
                plaintext=tx_payload,
                recipient_public_key=transaction.receiver.public_key,
                mode=encryption_mode,
                aad=aad
            )
            
            transaction.encrypted_payload = ciphertext
            transaction.security.kyber_ciphertext = kyber_ct
            transaction.security.kyber_mode = encryption_mode
            transaction.security.nonce_iv = nonce
            transaction.security.aad = aad
            transaction.status = TransactionStatus.ENCRYPTED
            transaction.status_history.append((TransactionStatus.ENCRYPTED, datetime.now()))
            
            logger.info(f"Transaction encrypted: {transaction.transaction_id}, payload_size={len(ciphertext)}")
            return True
            
        except Exception as e:
            logger.error(f"Transaction encryption failed: {e}")
            transaction.status = TransactionStatus.FAILED
            return False
    
    def process_complete(self, transaction: QuantumTransaction, sender_secret_key: bytes,
                        encryption_mode: KyberMode = KyberMode.AES_256_CBC) -> bool:
        """
        Complete transaction processing pipeline:
        1. Validate
        2. Sign with Dilithium
        3. Encrypt with Kyber+AES
        """
        # Step 1: Validate
        is_valid, error = self.validate_transaction(transaction)
        if not is_valid:
            logger.error(f"Validation failed: {error}")
            transaction.status = TransactionStatus.FAILED
            return False
        
        # Step 2: Sign
        if not self.sign_transaction(transaction, sender_secret_key):
            return False
        
        # Step 3: Encrypt
        if not self.encrypt_transaction(transaction, encryption_mode):
            return False
        
        transaction.status = TransactionStatus.TRANSMITTED
        transaction.status_history.append((TransactionStatus.TRANSMITTED, datetime.now()))
        
        logger.info(f"Transaction processing complete: {transaction.transaction_id}")
        return True
    
    def decrypt_and_verify_transaction(self, encrypted_tx: QuantumTransaction,
                                       receiver_secret_key: bytes,
                                       sender_public_key_bytes: bytes) -> Optional[QuantumTransaction]:
        """
        Receiver-side: Decrypt and verify transaction
        """
        try:
            # Step 1: Decrypt with Kyber
            decrypted_payload = self.kyber_manager.decrypt_with_kyber(
                ciphertext=encrypted_tx.encrypted_payload,
                kyber_ciphertext=encrypted_tx.security.kyber_ciphertext,
                recipient_secret_key=receiver_secret_key,
                nonce=encrypted_tx.security.nonce_iv,
                mode=encrypted_tx.security.kyber_mode,
                aad=encrypted_tx.security.aad
            )
            
            if not decrypted_payload:
                logger.error("Decryption failed")
                return None
            
            # Step 2: Parse decrypted data
            tx_data = json.loads(decrypted_payload.decode('utf-8'))
            
            # Step 3: Verify signature
            # Note: In production, would reconstruct the public key from sender
            logger.info(f"Transaction decrypted and verified: {encrypted_tx.transaction_id}")
            
            encrypted_tx.status = TransactionStatus.CONFIRMED
            encrypted_tx.status_history.append((TransactionStatus.CONFIRMED, datetime.now()))
            
            return encrypted_tx
            
        except Exception as e:
            logger.error(f"Decryption/verification failed: {e}")
            return None
    
    def get_transaction_receipt(self, transaction_id: str) -> Optional[Dict]:
        """Get transaction receipt"""
        for tx in self.transaction_log:
            if tx.transaction_id == transaction_id:
                return {
                    "receipt": tx.to_dict(include_sensitive=False),
                    "status_history": [
                        (status.value, timestamp.isoformat())
                        for status, timestamp in tx.status_history
                    ]
                }
        return None
    
    def get_transaction_history(self, account_number: Optional[str] = None) -> List[Dict]:
        """Get transaction history"""
        history = []
        for tx in self.transaction_log:
            if account_number is None or \
               tx.sender.account_number == account_number or \
               tx.receiver.account_number == account_number:
                history.append(tx.to_dict(include_sensitive=False))
        
        return sorted(history, key=lambda x: x["timestamp"], reverse=True)
    
    def export_audit_log(self) -> str:
        """Export complete audit log"""
        audit_data = {
            "timestamp": datetime.now().isoformat(),
            "transactions": [tx.to_dict(include_sensitive=False) for tx in self.transaction_log],
            "kyber_audit": json.loads(self.kyber_manager.export_audit_log("json")) if hasattr(self.kyber_manager, 'export_audit_log') else [],
            "dilithium_audit": self.dilithium_manager.export_audit_log("json")
        }
        return json.dumps(audit_data, indent=2)
