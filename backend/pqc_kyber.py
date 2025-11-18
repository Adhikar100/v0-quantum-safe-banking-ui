"""
CRYSTALS-Kyber-768 Implementation
Key Encapsulation Mechanism (KEM) for secure session key establishment
NIST Post-Quantum Cryptography Standard (FIPS 203)
"""

import os
import hashlib
import secrets
from typing import Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Try to import liboqs for production PQC
try:
    import oqs
    LIBOQS_AVAILABLE = True
    logger.info("liboqs library available - using production Kyber-768")
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning("liboqs not available - using simulation mode")


@dataclass
class KyberKeyPair:
    """Kyber-768 key pair"""
    public_key: bytes
    secret_key: bytes
    algorithm: str = "Kyber768"


@dataclass
class KyberEncapsulation:
    """Encapsulated shared secret"""
    ciphertext: bytes
    shared_secret: bytes


class CRYSTALSKyber768:
    """
    CRYSTALS-Kyber-768 Key Encapsulation Mechanism
    
    Security Level: NIST Level 3 (192-bit security)
    Public Key Size: 1184 bytes
    Secret Key Size: 2400 bytes
    Ciphertext Size: 1088 bytes
    Shared Secret Size: 32 bytes
    """
    
    ALGORITHM_NAME = "Kyber768"
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    def __init__(self):
        """Initialize Kyber-768 instance"""
        self.kem = None
        if LIBOQS_AVAILABLE:
            try:
                self.kem = oqs.KeyEncapsulation(self.ALGORITHM_NAME)
                logger.info(f"Initialized {self.ALGORITHM_NAME} with liboqs")
            except Exception as e:
                logger.error(f"Failed to initialize liboqs KEM: {e}")
                self.kem = None
    
    def generate_keypair(self) -> KyberKeyPair:
        """
        Generate a new Kyber-768 keypair
        
        Returns:
            KyberKeyPair with public and secret keys
        """
        if self.kem:
            # Production: Use liboqs
            try:
                public_key = self.kem.generate_keypair()
                secret_key = self.kem.export_secret_key()
                
                logger.info(f"Generated Kyber-768 keypair (liboqs)")
                return KyberKeyPair(
                    public_key=public_key,
                    secret_key=secret_key,
                    algorithm=self.ALGORITHM_NAME
                )
            except Exception as e:
                logger.error(f"Keypair generation failed: {e}")
                raise
        else:
            # Simulation: Generate random bytes of correct size
            public_key = secrets.token_bytes(self.PUBLIC_KEY_SIZE)
            secret_key = secrets.token_bytes(self.SECRET_KEY_SIZE)
            
            logger.warning("Generated simulated Kyber-768 keypair")
            return KyberKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=f"{self.ALGORITHM_NAME}-Simulated"
            )
    
    def encapsulate(self, public_key: bytes) -> KyberEncapsulation:
        """
        Encapsulate a shared secret using recipient's public key
        
        Args:
            public_key: Recipient's Kyber-768 public key
            
        Returns:
            KyberEncapsulation containing ciphertext and shared secret
        """
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid public key size: {len(public_key)}")
        
        if self.kem:
            # Production: Use liboqs
            try:
                ciphertext, shared_secret = self.kem.encap_secret(public_key)
                
                logger.info(f"Encapsulated shared secret (liboqs)")
                return KyberEncapsulation(
                    ciphertext=ciphertext,
                    shared_secret=shared_secret
                )
            except Exception as e:
                logger.error(f"Encapsulation failed: {e}")
                raise
        else:
            # Simulation: Generate deterministic values
            ciphertext = secrets.token_bytes(self.CIPHERTEXT_SIZE)
            # Derive shared secret from public key for consistency
            shared_secret = hashlib.sha256(public_key + ciphertext).digest()
            
            logger.warning("Simulated Kyber-768 encapsulation")
            return KyberEncapsulation(
                ciphertext=ciphertext,
                shared_secret=shared_secret
            )
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret using own secret key
        
        Args:
            secret_key: Own Kyber-768 secret key
            ciphertext: Ciphertext received from sender
            
        Returns:
            Shared secret (32 bytes)
        """
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(f"Invalid secret key size: {len(secret_key)}")
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}")
        
        if self.kem:
            # Production: Use liboqs
            try:
                # Import secret key
                temp_kem = oqs.KeyEncapsulation(self.ALGORITHM_NAME, secret_key)
                shared_secret = temp_kem.decap_secret(ciphertext)
                
                logger.info(f"Decapsulated shared secret (liboqs)")
                return shared_secret
            except Exception as e:
                logger.error(f"Decapsulation failed: {e}")
                raise
        else:
            # Simulation: Derive from secret key and ciphertext
            shared_secret = hashlib.sha256(secret_key[:self.PUBLIC_KEY_SIZE] + ciphertext).digest()
            
            logger.warning("Simulated Kyber-768 decapsulation")
            return shared_secret
    
    def benchmark(self, iterations: int = 100) -> dict:
        """
        Benchmark Kyber-768 operations
        
        Args:
            iterations: Number of iterations to run
            
        Returns:
            Dictionary with timing results
        """
        import time
        
        results = {
            "algorithm": self.ALGORITHM_NAME,
            "iterations": iterations,
            "liboqs_available": LIBOQS_AVAILABLE
        }
        
        # Keypair generation
        start = time.time()
        for _ in range(iterations):
            self.generate_keypair()
        results["keypair_generation_ms"] = (time.time() - start) * 1000 / iterations
        
        # Encapsulation
        keypair = self.generate_keypair()
        start = time.time()
        for _ in range(iterations):
            self.encapsulate(keypair.public_key)
        results["encapsulation_ms"] = (time.time() - start) * 1000 / iterations
        
        # Decapsulation
        encap = self.encapsulate(keypair.public_key)
        start = time.time()
        for _ in range(iterations):
            self.decapsulate(keypair.secret_key, encap.ciphertext)
        results["decapsulation_ms"] = (time.time() - start) * 1000 / iterations
        
        return results


def encrypt_with_kyber(plaintext: bytes, recipient_public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data using Kyber-768 + AES-256-GCM
    
    Args:
        plaintext: Data to encrypt
        recipient_public_key: Recipient's Kyber-768 public key
        
    Returns:
        (ciphertext, kyber_ciphertext) tuple
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    kyber = CRYSTALSKyber768()
    
    # Encapsulate shared secret
    encap = kyber.encapsulate(recipient_public_key)
    
    # Use shared secret as AES key
    aesgcm = AESGCM(encap.shared_secret)
    nonce = os.urandom(12)
    
    # Encrypt plaintext
    ciphertext = nonce + aesgcm.encrypt(nonce, plaintext, None)
    
    return ciphertext, encap.ciphertext


def decrypt_with_kyber(ciphertext: bytes, kyber_ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decrypt data using Kyber-768 + AES-256-GCM
    
    Args:
        ciphertext: Encrypted data
        kyber_ciphertext: Kyber ciphertext
        secret_key: Own Kyber-768 secret key
        
    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    kyber = CRYSTALSKyber768()
    
    # Decapsulate shared secret
    shared_secret = kyber.decapsulate(secret_key, kyber_ciphertext)
    
    # Extract nonce and ciphertext
    nonce = ciphertext[:12]
    encrypted_data = ciphertext[12:]
    
    # Decrypt with AES
    aesgcm = AESGCM(shared_secret)
    plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
    
    return plaintext


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("=== CRYSTALS-Kyber-768 Demo ===\n")
    
    kyber = CRYSTALSKyber768()
    
    # Generate keypair
    print("1. Generating keypair...")
    keypair = kyber.generate_keypair()
    print(f"   Public key size: {len(keypair.public_key)} bytes")
    print(f"   Secret key size: {len(keypair.secret_key)} bytes")
    
    # Encapsulate
    print("\n2. Encapsulating shared secret...")
    encap = kyber.encapsulate(keypair.public_key)
    print(f"   Ciphertext size: {len(encap.ciphertext)} bytes")
    print(f"   Shared secret: {encap.shared_secret.hex()[:64]}...")
    
    # Decapsulate
    print("\n3. Decapsulating shared secret...")
    recovered_secret = kyber.decapsulate(keypair.secret_key, encap.ciphertext)
    print(f"   Recovered secret: {recovered_secret.hex()[:64]}...")
    print(f"   Match: {encap.shared_secret == recovered_secret}")
    
    # Benchmark
    print("\n4. Running benchmark...")
    results = kyber.benchmark(iterations=10)
    print(f"   Keypair generation: {results['keypair_generation_ms']:.2f} ms")
    print(f"   Encapsulation: {results['encapsulation_ms']:.2f} ms")
    print(f"   Decapsulation: {results['decapsulation_ms']:.2f} ms")
