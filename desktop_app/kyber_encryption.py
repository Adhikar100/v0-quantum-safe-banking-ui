"""
Advanced CRYSTALS-Kyber Encryption Module
ML-KEM-512, ML-KEM-768, ML-KEM-1024 implementations
NIST Post-Quantum Cryptography Standard (FIPS 203)
"""

import hashlib
import json
import logging
from typing import Tuple, Optional, Dict
from dataclasses import dataclass
from enum import Enum
import os
from datetime import datetime

try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)


class KyberSecurityLevel(Enum):
    """Kyber security levels per NIST standardization"""
    LEVEL_1 = 1  # ML-KEM-512: 128-bit post-quantum security
    LEVEL_3 = 3  # ML-KEM-768: 192-bit post-quantum security
    LEVEL_5 = 5  # ML-KEM-1024: 256-bit post-quantum security


class KyberMode(Enum):
    """Encryption modes after key establishment"""
    AES_256_CBC = "aes_256_cbc"
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"


@dataclass
class KyberKeyPair:
    """Represents a Kyber keypair"""
    public_key: bytes
    secret_key: bytes
    security_level: KyberSecurityLevel
    created_at: str
    key_id: str
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            "public_key": self.public_key.hex(),
            "secret_key": self.secret_key.hex(),
            "security_level": self.security_level.name,
            "created_at": self.created_at,
            "key_id": self.key_id
        }


@dataclass
class KyberCiphertext:
    """Represents encapsulated ciphertext and shared secret"""
    ciphertext: bytes
    shared_secret: bytes
    ephemeral_public_key: Optional[bytes] = None
    created_at: str = None
    encryption_mode: KyberMode = KyberMode.AES_256_CBC
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            "ciphertext": self.ciphertext.hex(),
            "shared_secret": self.shared_secret.hex(),
            "ephemeral_public_key": self.ephemeral_public_key.hex() if self.ephemeral_public_key else None,
            "created_at": self.created_at,
            "encryption_mode": self.encryption_mode.value
        }


class AdvancedKyberManager:
    """Advanced Kyber key establishment and encapsulation manager"""
    
    def __init__(self, security_level: KyberSecurityLevel = KyberSecurityLevel.LEVEL_3):
        """Initialize Kyber manager with specified security level"""
        if not KYBER_AVAILABLE:
            raise RuntimeError("kyber-py library not installed. Install via: pip install kyber-py")
        
        self.security_level = security_level
        self.kyber_variant = self._get_kyber_variant()
        self.key_registry: Dict[str, KyberKeyPair] = {}
        
        logger.info(f"AdvancedKyberManager initialized with {security_level.name}")
    
    def _get_kyber_variant(self):
        """Get Kyber variant based on security level"""
        variants = {
            KyberSecurityLevel.LEVEL_1: ML_KEM_512,
            KyberSecurityLevel.LEVEL_3: ML_KEM_768,
            KyberSecurityLevel.LEVEL_5: ML_KEM_1024
        }
        return variants[self.security_level]
    
    def generate_keypair(self) -> KyberKeyPair:
        """
        Generate a new Kyber keypair
        Returns: KyberKeyPair with public and secret keys
        """
        ek, dk = self.kyber_variant.keygen()
        
        key_id = hashlib.sha256(ek).hexdigest()[:16]
        keypair = KyberKeyPair(
            public_key=ek,
            secret_key=dk,
            security_level=self.security_level,
            created_at=datetime.now().isoformat(),
            key_id=key_id
        )
        
        self.key_registry[key_id] = keypair
        logger.info(f"Kyber keypair generated: {key_id}")
        
        return keypair
    
    def encapsulate(self, recipient_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using recipient's public key
        Args:
            recipient_public_key: Recipient's Kyber public key
        Returns:
            (ciphertext, shared_secret): Encapsulated key material
        """
        try:
            ss, ct = self.kyber_variant.encaps(recipient_public_key)
            logger.info(f"Encapsulation successful: shared_secret_len={len(ss)}, ciphertext_len={len(ct)}")
            return ss, ct
        except Exception as e:
            logger.error(f"Encapsulation failed: {e}")
            raise
    
    def decapsulate(self, ciphertext: bytes, recipient_secret_key: bytes) -> bytes:
        """
        Decapsulate to recover shared secret
        Args:
            ciphertext: Encapsulated ciphertext from sender
            recipient_secret_key: Recipient's Kyber secret key
        Returns:
            shared_secret: Recovered shared secret for symmetric encryption
        """
        try:
            ss = self.kyber_variant.decaps(ciphertext, recipient_secret_key)
            logger.info(f"Decapsulation successful: shared_secret_len={len(ss)}")
            return ss
        except Exception as e:
            logger.error(f"Decapsulation failed: {e}")
            raise
    
    def derive_encryption_key(self, shared_secret: bytes, salt: Optional[bytes] = None,
                             info: Optional[bytes] = None, key_length: int = 32) -> bytes:
        """
        Derive encryption key from Kyber shared secret using HKDF-SHA256
        Args:
            shared_secret: Kyber shared secret
            salt: Optional salt for KDF
            info: Optional context info for KDF
            key_length: Desired key length in bytes (default 32 for AES-256)
        Returns:
            Derived key material
        """
        if salt is None:
            salt = b""
        if info is None:
            info = b"kyber-encryption-key"
        
        # HKDF-SHA256 extract and expand
        prk = hmac_sha256(salt, shared_secret)
        okm = hkdf_expand(prk, info, key_length)
        
        logger.info(f"Derived encryption key: length={len(okm)}")
        return okm
    
    def encrypt_with_kyber(self, plaintext: bytes, recipient_public_key: bytes,
                          mode: KyberMode = KyberMode.AES_256_CBC,
                          aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Complete encryption pipeline: Kyber encapsulation + symmetric encryption
        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's Kyber public key
            mode: Encryption mode (AES-256-CBC, AES-256-GCM, ChaCha20-Poly1305)
            aad: Additional authenticated data (for GCM/ChaCha)
        Returns:
            (ciphertext, kyber_ciphertext, nonce): Encrypted data and key material
        """
        try:
            # Step 1: Kyber encapsulation
            shared_secret, kyber_ct = self.encapsulate(recipient_public_key)
            
            # Step 2: Derive encryption key
            encryption_key = self.derive_encryption_key(shared_secret)
            
            # Step 3: Encrypt based on mode
            if mode == KyberMode.AES_256_CBC:
                nonce = get_random_bytes(16)  # IV for CBC
                cipher = AES.new(encryption_key, AES.MODE_CBC, nonce)
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                
            elif mode == KyberMode.AES_256_GCM:
                nonce = get_random_bytes(12)  # Nonce for GCM
                cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
                if aad:
                    cipher.update(aad)
                ciphertext = cipher.encrypt(plaintext)
                ciphertext += cipher.digest()  # Add authentication tag
                
            elif mode == KyberMode.CHACHA20_POLY1305:
                nonce = get_random_bytes(12)
                cipher = ChaCha20_Poly1305.new(key=encryption_key, nonce=nonce)
                if aad:
                    cipher.update(aad)
                ciphertext = cipher.encrypt(plaintext)
                ciphertext += cipher.digest()
            else:
                raise ValueError(f"Unsupported encryption mode: {mode}")
            
            logger.info(f"Encryption successful: mode={mode.value}, plaintext_len={len(plaintext)}, ciphertext_len={len(ciphertext)}")
            return ciphertext, kyber_ct, nonce
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_with_kyber(self, ciphertext: bytes, kyber_ciphertext: bytes,
                          recipient_secret_key: bytes, nonce: bytes,
                          mode: KyberMode = KyberMode.AES_256_CBC,
                          aad: Optional[bytes] = None) -> Optional[bytes]:
        """
        Complete decryption pipeline: Kyber decapsulation + symmetric decryption
        Args:
            ciphertext: Encrypted data
            kyber_ciphertext: Kyber encapsulated key
            recipient_secret_key: Recipient's Kyber secret key
            nonce: IV/Nonce used for encryption
            mode: Encryption mode
            aad: Additional authenticated data (for authenticated modes)
        Returns:
            Decrypted plaintext or None on failure
        """
        try:
            # Step 1: Kyber decapsulation
            shared_secret = self.decapsulate(kyber_ciphertext, recipient_secret_key)
            
            # Step 2: Derive encryption key
            encryption_key = self.derive_encryption_key(shared_secret)
            
            # Step 3: Decrypt based on mode
            if mode == KyberMode.AES_256_CBC:
                cipher = AES.new(encryption_key, AES.MODE_CBC, nonce)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
            elif mode == KyberMode.AES_256_GCM:
                tag = ciphertext[-16:]  # Last 16 bytes are authentication tag
                ciphertext_only = ciphertext[:-16]
                cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
                if aad:
                    cipher.update(aad)
                plaintext = cipher.decrypt_and_verify(ciphertext_only, tag)
                
            elif mode == KyberMode.CHACHA20_POLY1305:
                tag = ciphertext[-16:]
                ciphertext_only = ciphertext[:-16]
                cipher = ChaCha20_Poly1305.new(key=encryption_key, nonce=nonce)
                if aad:
                    cipher.update(aad)
                plaintext = cipher.decrypt_and_verify(ciphertext_only, tag)
            else:
                raise ValueError(f"Unsupported decryption mode: {mode}")
            
            logger.info(f"Decryption successful: mode={mode.value}, ciphertext_len={len(ciphertext)}, plaintext_len={len(plaintext)}")
            return plaintext
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256"""
    import hmac
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 expand step"""
    import hmac
    
    n = (length + 31) // 32
    okm = b""
    t = b""
    
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    
    return okm[:length]
