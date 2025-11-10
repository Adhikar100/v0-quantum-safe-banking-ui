"""
Advanced CRYSTALS-Dilithium Digital Signature Module
ML-DSA-44, ML-DSA-65, ML-DSA-87 implementations
NIST Post-Quantum Cryptography Standard (FIPS 204)
"""

import hashlib
import json
import logging
from typing import Tuple, Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import time

try:
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    DILITHIUM_AVAILABLE = True
except ImportError:
    DILITHIUM_AVAILABLE = False

logger = logging.getLogger(__name__)


class DilithiumSecurityLevel(Enum):
    """Dilithium security levels per NIST standardization"""
    LEVEL_2 = 2  # ML-DSA-44: 128-bit post-quantum security
    LEVEL_3 = 3  # ML-DSA-65: 192-bit post-quantum security
    LEVEL_5 = 5  # ML-DSA-87: 256-bit post-quantum security


class SignatureFormat(Enum):
    """Signature encoding formats"""
    RAW = "raw"  # Raw bytes
    HEX = "hex"  # Hexadecimal string
    BASE64 = "base64"  # Base64 encoded


@dataclass
class DilithiumPublicKey:
    """Represents a Dilithium public key"""
    key_bytes: bytes
    security_level: DilithiumSecurityLevel
    created_at: str
    key_id: str
    owner: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            "key_bytes": self.key_bytes.hex(),
            "security_level": self.security_level.name,
            "created_at": self.created_at,
            "key_id": self.key_id,
            "owner": self.owner
        }


@dataclass
class DilithiumSignature:
    """Represents a Dilithium signature with metadata"""
    signature_bytes: bytes
    message_hash: str
    created_at: str
    signer_key_id: str
    verified: bool = False
    verification_time: Optional[float] = None
    signature_format: SignatureFormat = SignatureFormat.RAW
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            "signature_bytes": self.signature_bytes.hex(),
            "message_hash": self.message_hash,
            "created_at": self.created_at,
            "signer_key_id": self.signer_key_id,
            "verified": self.verified,
            "verification_time": self.verification_time,
            "signature_format": self.signature_format.value
        }


@dataclass
class SignatureAuditLog:
    """Audit log for signature operations"""
    operation: str
    timestamp: str
    key_id: str
    message_hash: str
    success: bool
    duration_ms: float
    details: Dict = field(default_factory=dict)


class AdvancedDilithiumManager:
    """Advanced Dilithium digital signature manager"""
    
    def __init__(self, security_level: DilithiumSecurityLevel = DilithiumSecurityLevel.LEVEL_3):
        """Initialize Dilithium manager with specified security level"""
        if not DILITHIUM_AVAILABLE:
            raise RuntimeError("dilithium-py library not installed. Install via: pip install dilithium-py")
        
        self.security_level = security_level
        self.dilithium_variant = self._get_dilithium_variant()
        self.public_key_registry: Dict[str, DilithiumPublicKey] = {}
        self.signature_audit_log: List[SignatureAuditLog] = []
        
        logger.info(f"AdvancedDilithiumManager initialized with {security_level.name}")
    
    def _get_dilithium_variant(self):
        """Get Dilithium variant based on security level"""
        variants = {
            DilithiumSecurityLevel.LEVEL_2: ML_DSA_44,
            DilithiumSecurityLevel.LEVEL_3: ML_DSA_65,
            DilithiumSecurityLevel.LEVEL_5: ML_DSA_87
        }
        return variants[self.security_level]
    
    def generate_keypair(self, owner: Optional[str] = None) -> Tuple[bytes, DilithiumPublicKey]:
        """
        Generate a new Dilithium keypair
        Args:
            owner: Optional owner identifier
        Returns:
            (secret_key, public_key_object): Generated keypair
        """
        start_time = time.time()
        
        sk, pk = self.dilithium_variant.keygen()
        
        key_id = hashlib.sha256(pk).hexdigest()[:16]
        public_key_obj = DilithiumPublicKey(
            key_bytes=pk,
            security_level=self.security_level,
            created_at=datetime.now().isoformat(),
            key_id=key_id,
            owner=owner
        )
        
        self.public_key_registry[key_id] = public_key_obj
        
        duration = (time.time() - start_time) * 1000
        log_entry = SignatureAuditLog(
            operation="keypair_generation",
            timestamp=datetime.now().isoformat(),
            key_id=key_id,
            message_hash="",
            success=True,
            duration_ms=duration,
            details={"owner": owner, "security_level": self.security_level.name}
        )
        self.signature_audit_log.append(log_entry)
        
        logger.info(f"Dilithium keypair generated: {key_id} (duration: {duration:.2f}ms)")
        return sk, public_key_obj
    
    def sign_message(self, message: bytes, secret_key: bytes, key_id: str) -> DilithiumSignature:
        """
        Sign a message with Dilithium
        Args:
            message: Message to sign
            secret_key: Dilithium secret key
            key_id: Identifier of the signing key
        Returns:
            DilithiumSignature object with metadata
        """
        start_time = time.time()
        message_hash = hashlib.sha256(message).hexdigest()
        
        try:
            signature = self.dilithium_variant.sign(secret_key, message)
            
            sig_obj = DilithiumSignature(
                signature_bytes=signature,
                message_hash=message_hash,
                created_at=datetime.now().isoformat(),
                signer_key_id=key_id
            )
            
            duration = (time.time() - start_time) * 1000
            log_entry = SignatureAuditLog(
                operation="sign_message",
                timestamp=datetime.now().isoformat(),
                key_id=key_id,
                message_hash=message_hash,
                success=True,
                duration_ms=duration,
                details={"message_len": len(message), "signature_len": len(signature)}
            )
            self.signature_audit_log.append(log_entry)
            
            logger.info(f"Message signed: hash={message_hash}, sig_len={len(signature)}, duration={duration:.2f}ms")
            return sig_obj
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            log_entry = SignatureAuditLog(
                operation="sign_message",
                timestamp=datetime.now().isoformat(),
                key_id=key_id,
                message_hash=message_hash,
                success=False,
                duration_ms=duration,
                details={"error": str(e)}
            )
            self.signature_audit_log.append(log_entry)
            
            logger.error(f"Message signing failed: {e}")
            raise
    
    def verify_signature(self, message: bytes, signature: DilithiumSignature,
                        public_key: DilithiumPublicKey) -> bool:
        """
        Verify a Dilithium signature
        Args:
            message: Original message
            signature: Signature object to verify
            public_key: Public key for verification
        Returns:
            True if signature is valid, False otherwise
        """
        start_time = time.time()
        message_hash = hashlib.sha256(message).hexdigest()
        
        try:
            self.dilithium_variant.verify(public_key.key_bytes, message, signature.signature_bytes)
            
            signature.verified = True
            signature.verification_time = (time.time() - start_time) * 1000
            
            log_entry = SignatureAuditLog(
                operation="verify_signature",
                timestamp=datetime.now().isoformat(),
                key_id=public_key.key_id,
                message_hash=message_hash,
                success=True,
                duration_ms=signature.verification_time,
                details={"signer": public_key.owner}
            )
            self.signature_audit_log.append(log_entry)
            
            logger.info(f"Signature verified: key_id={public_key.key_id}, duration={signature.verification_time:.2f}ms")
            return True
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            
            log_entry = SignatureAuditLog(
                operation="verify_signature",
                timestamp=datetime.now().isoformat(),
                key_id=public_key.key_id,
                message_hash=message_hash,
                success=False,
                duration_ms=duration,
                details={"error": str(e)}
            )
            self.signature_audit_log.append(log_entry)
            
            logger.warning(f"Signature verification failed: {e}")
            return False
    
    def batch_verify_signatures(self, messages: List[bytes], signatures: List[DilithiumSignature],
                               public_key: DilithiumPublicKey) -> List[bool]:
        """
        Verify multiple signatures efficiently
        Args:
            messages: List of messages
            signatures: List of signatures
            public_key: Public key for verification
        Returns:
            List of verification results
        """
        if len(messages) != len(signatures):
            raise ValueError("Messages and signatures length mismatch")
        
        results = []
        for msg, sig in zip(messages, signatures):
            results.append(self.verify_signature(msg, sig, public_key))
        
        logger.info(f"Batch verification completed: {sum(results)}/{len(results)} valid")
        return results
    
    def sign_transaction(self, transaction_data: Dict, secret_key: bytes, key_id: str) -> DilithiumSignature:
        """
        Sign a transaction (specialized signing)
        Args:
            transaction_data: Transaction dictionary
            secret_key: Signer's secret key
            key_id: Signer's key ID
        Returns:
            DilithiumSignature for the transaction
        """
        # Serialize transaction with deterministic ordering
        message = json.dumps(transaction_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return self.sign_message(message, secret_key, key_id)
    
    def verify_transaction_signature(self, transaction_data: Dict, signature: DilithiumSignature,
                                    public_key: DilithiumPublicKey) -> bool:
        """
        Verify a transaction signature
        Args:
            transaction_data: Transaction dictionary
            signature: Transaction signature
            public_key: Signer's public key
        Returns:
            True if transaction signature is valid
        """
        message = json.dumps(transaction_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return self.verify_signature(message, signature, public_key)
    
    def get_audit_log(self, operation: Optional[str] = None, key_id: Optional[str] = None) -> List[SignatureAuditLog]:
        """
        Retrieve audit log with optional filtering
        Args:
            operation: Filter by operation type
            key_id: Filter by key ID
        Returns:
            Filtered audit log entries
        """
        logs = self.signature_audit_log
        
        if operation:
            logs = [log for log in logs if log.operation == operation]
        
        if key_id:
            logs = [log for log in logs if log.key_id == key_id]
        
        return logs
    
    def export_public_key(self, key_id: str) -> Optional[Dict]:
        """Export public key details"""
        if key_id not in self.public_key_registry:
            return None
        
        key_obj = self.public_key_registry[key_id]
        return key_obj.to_dict()
    
    def export_audit_log(self, format: str = "json") -> str:
        """
        Export audit log
        Args:
            format: Export format ("json", "csv")
        Returns:
            Formatted audit log
        """
        if format == "json":
            logs_data = [
                {
                    "operation": log.operation,
                    "timestamp": log.timestamp,
                    "key_id": log.key_id,
                    "message_hash": log.message_hash,
                    "success": log.success,
                    "duration_ms": log.duration_ms,
                    "details": log.details
                }
                for log in self.signature_audit_log
            ]
            return json.dumps(logs_data, indent=2)
        
        elif format == "csv":
            lines = ["operation,timestamp,key_id,message_hash,success,duration_ms"]
            for log in self.signature_audit_log:
                lines.append(f"{log.operation},{log.timestamp},{log.key_id},{log.message_hash},{log.success},{log.duration_ms}")
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
