"""
Utility functions for quantum cryptography operations in banking
"""
from typing import Dict, Any
from security import (
    CRYSTALSKyber,
    CRYSTALSDilithium,
    QuantumCrypto
)
import json


class QuantumBankingUtils:
    """Utilities for quantum-safe banking operations"""
    
    @staticmethod
    def create_secure_transfer(
        sender_id: str,
        receiver_name: str,
        amount: float,
        account_number: str,
        sender_dilithium_key: str
    ) -> Dict[str, Any]:
        """Create a cryptographically signed transfer request"""
        
        transfer_data = {
            "sender_id": sender_id,
            "receiver_name": receiver_name,
            "amount": amount,
            "account_number": account_number,
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
        }
        
        # Sign with Dilithium
        signature = CRYSTALSDilithium.sign(
            json.dumps(transfer_data, sort_keys=True),
            sender_dilithium_key
        )
        
        return {
            "transfer": transfer_data,
            "signature": signature,
            "algorithm": "CRYSTALS-Dilithium"
        }
    
    @staticmethod
    def verify_transfer(signed_transfer: Dict[str, Any], 
                       sender_verification_key: str) -> bool:
        """Verify a transfer was signed correctly"""
        
        transfer_json = json.dumps(signed_transfer["transfer"], sort_keys=True)
        return CRYSTALSDilithium.verify(
            transfer_json,
            signed_transfer["signature"],
            sender_verification_key
        )
    
    @staticmethod
    def secure_key_exchange(
        sender_kyber_public_key: str,
        receiver_kyber_public_key: str
    ) -> Dict[str, Any]:
        """Establish shared secret between two parties"""
        
        # Sender encapsulates for receiver
        sender_ct, sender_secret = CRYSTALSKyber.encapsulate(receiver_kyber_public_key)
        
        # Receiver would decapsulate using their secret key
        return {
            "ciphertext": sender_ct,
            "shared_secret_hex": sender_secret,
            "key_exchange_algorithm": "CRYSTALS-Kyber",
            "security_level": "Post-Quantum"
        }
    
    @staticmethod
    def generate_bank_certificates() -> Dict[str, Any]:
        """Generate bank's quantum-safe certificates"""
        
        kyber = CRYSTALSKyber.generate_keypair()
        dilithium = CRYSTALSDilithium.generate_keypair()
        
        return {
            "bank_kyber_public": kyber["public_key"],
            "bank_kyber_secret": kyber["secret_key"],
            "bank_dilithium_verification": dilithium["verification_key"],
            "bank_dilithium_signing": dilithium["signing_key"],
            "certificate_valid_from": __import__('datetime').datetime.utcnow().isoformat(),
            "certificate_expires": (__import__('datetime').datetime.utcnow() + 
                                   __import__('datetime').timedelta(days=730)).isoformat()
        }
