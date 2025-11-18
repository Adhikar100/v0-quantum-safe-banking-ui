"""
CRYSTALS-Dilithium3 Implementation
Digital Signature Algorithm for authentication
NIST Post-Quantum Cryptography Standard (FIPS 204)
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
    logger.info("liboqs library available - using production Dilithium3")
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning("liboqs not available - using simulation mode")


@dataclass
class DilithiumKeyPair:
    """Dilithium3 key pair"""
    public_key: bytes
    secret_key: bytes
    algorithm: str = "Dilithium3"


@dataclass
class DilithiumSignature:
    """Digital signature"""
    signature: bytes
    message: bytes
    timestamp: float


class CRYSTALSDilithium3:
    """
    CRYSTALS-Dilithium3 Digital Signature Algorithm
    
    Security Level: NIST Level 3 (192-bit security)
    Public Key Size: 1952 bytes
    Secret Key Size: 4000 bytes
    Signature Size: 3293 bytes
    """
    
    ALGORITHM_NAME = "Dilithium3"
    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4000
    SIGNATURE_SIZE = 3293
    
    def __init__(self):
        """Initialize Dilithium3 instance"""
        self.sig = None
        if LIBOQS_AVAILABLE:
            try:
                self.sig = oqs.Signature(self.ALGORITHM_NAME)
                logger.info(f"Initialized {self.ALGORITHM_NAME} with liboqs")
            except Exception as e:
                logger.error(f"Failed to initialize liboqs Signature: {e}")
                self.sig = None
    
    def generate_keypair(self) -> DilithiumKeyPair:
        """
        Generate a new Dilithium3 keypair
        
        Returns:
            DilithiumKeyPair with public and secret keys
        """
        if self.sig:
            # Production: Use liboqs
            try:
                public_key = self.sig.generate_keypair()
                secret_key = self.sig.export_secret_key()
                
                logger.info(f"Generated Dilithium3 keypair (liboqs)")
                return DilithiumKeyPair(
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
            
            logger.warning("Generated simulated Dilithium3 keypair")
            return DilithiumKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=f"{self.ALGORITHM_NAME}-Simulated"
            )
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message using Dilithium3
        
        Args:
            message: Message to sign
            secret_key: Signer's secret key
            
        Returns:
            Digital signature (bytes)
        """
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(f"Invalid secret key size: {len(secret_key)}")
        
        if self.sig:
            # Production: Use liboqs
            try:
                # Import secret key
                temp_sig = oqs.Signature(self.ALGORITHM_NAME, secret_key)
                signature = temp_sig.sign(message)
                
                logger.info(f"Signed message with Dilithium3 (liboqs)")
                return signature
            except Exception as e:
                logger.error(f"Signing failed: {e}")
                raise
        else:
            # Simulation: HMAC-SHA512 signature
            signature = hashlib.sha512(secret_key + message).digest()
            # Pad to correct size
            signature = signature + secrets.token_bytes(self.SIGNATURE_SIZE - len(signature))
            
            logger.warning("Simulated Dilithium3 signature")
            return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a Dilithium3 signature
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid public key size: {len(public_key)}")
        if len(signature) != self.SIGNATURE_SIZE:
            raise ValueError(f"Invalid signature size: {len(signature)}")
        
        if self.sig:
            # Production: Use liboqs
            try:
                # Create signature verifier
                verifier = oqs.Signature(self.ALGORITHM_NAME)
                verifier.generate_keypair()  # Dummy keypair
                
                # Verify signature
                is_valid = verifier.verify(message, signature, public_key)
                
                logger.info(f"Verified Dilithium3 signature: {is_valid}")
                return is_valid
            except Exception as e:
                logger.error(f"Verification failed: {e}")
                return False
        else:
            # Simulation: Check HMAC
            # Extract secret key from public key (simulation only!)
            expected_sig = hashlib.sha512(public_key + message).digest()
            is_valid = signature[:64] == expected_sig
            
            logger.warning(f"Simulated Dilithium3 verification: {is_valid}")
            return is_valid
    
    def sign_transaction(self, transaction_data: dict, secret_key: bytes) -> DilithiumSignature:
        """
        Sign a transaction with metadata
        
        Args:
            transaction_data: Transaction dictionary
            secret_key: Signer's secret key
            
        Returns:
            DilithiumSignature with signature and timestamp
        """
        import json
        import time
        
        # Serialize transaction
        message = json.dumps(transaction_data, sort_keys=True).encode()
        
        # Add timestamp
        timestamp = time.time()
        timestamped_message = f"{timestamp}:".encode() + message
        
        # Sign
        signature = self.sign(timestamped_message, secret_key)
        
        return DilithiumSignature(
            signature=signature,
            message=timestamped_message,
            timestamp=timestamp
        )
    
    def verify_transaction(self, signature_obj: DilithiumSignature, public_key: bytes) -> bool:
        """
        Verify a transaction signature
        
        Args:
            signature_obj: DilithiumSignature object
            public_key: Signer's public key
            
        Returns:
            True if valid, False otherwise
        """
        import time
        
        # Check timestamp (reject if older than 5 minutes)
        current_time = time.time()
        if current_time - signature_obj.timestamp > 300:
            logger.warning("Transaction signature expired")
            return False
        
        # Verify signature
        return self.verify(signature_obj.message, signature_obj.signature, public_key)
    
    def benchmark(self, iterations: int = 100) -> dict:
        """
        Benchmark Dilithium3 operations
        
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
        
        # Signing
        keypair = self.generate_keypair()
        message = b"Test message for benchmarking"
        start = time.time()
        for _ in range(iterations):
            self.sign(message, keypair.secret_key)
        results["signing_ms"] = (time.time() - start) * 1000 / iterations
        
        # Verification
        signature = self.sign(message, keypair.secret_key)
        start = time.time()
        for _ in range(iterations):
            self.verify(message, signature, keypair.public_key)
        results["verification_ms"] = (time.time() - start) * 1000 / iterations
        
        return results


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("=== CRYSTALS-Dilithium3 Demo ===\n")
    
    dilithium = CRYSTALSDilithium3()
    
    # Generate keypair
    print("1. Generating keypair...")
    keypair = dilithium.generate_keypair()
    print(f"   Public key size: {len(keypair.public_key)} bytes")
    print(f"   Secret key size: {len(keypair.secret_key)} bytes")
    
    # Sign message
    message = b"Transfer $500 to Alice"
    print(f"\n2. Signing message: {message.decode()}")
    signature = dilithium.sign(message, keypair.secret_key)
    print(f"   Signature size: {len(signature)} bytes")
    print(f"   Signature: {signature.hex()[:64]}...")
    
    # Verify signature
    print("\n3. Verifying signature...")
    is_valid = dilithium.verify(message, signature, keypair.public_key)
    print(f"   Valid: {is_valid}")
    
    # Sign transaction
    print("\n4. Signing transaction...")
    transaction = {
        "sender": "Bob",
        "receiver": "Alice",
        "amount": 500,
        "currency": "USD"
    }
    tx_sig = dilithium.sign_transaction(transaction, keypair.secret_key)
    print(f"   Transaction signed at: {tx_sig.timestamp}")
    
    # Verify transaction
    print("\n5. Verifying transaction...")
    tx_valid = dilithium.verify_transaction(tx_sig, keypair.public_key)
    print(f"   Transaction valid: {tx_valid}")
    
    # Benchmark
    print("\n6. Running benchmark...")
    results = dilithium.benchmark(iterations=10)
    print(f"   Keypair generation: {results['keypair_generation_ms']:.2f} ms")
    print(f"   Signing: {results['signing_ms']:.2f} ms")
    print(f"   Verification: {results['verification_ms']:.2f} ms")
