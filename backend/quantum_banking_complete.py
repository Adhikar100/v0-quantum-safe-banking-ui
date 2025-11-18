"""
Complete Quantum-Safe Banking System
Integrates Kyber-768 and Dilithium3 for secure transactions
"""

import json
import logging
from typing import Dict, Tuple
from dataclasses import dataclass, asdict
import time

from pqc_kyber import CRYSTALSKyber768, encrypt_with_kyber, decrypt_with_kyber
from pqc_dilithium import CRYSTALSDilithium3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BankAccount:
    """Bank account with quantum keys"""
    account_number: str
    account_name: str
    balance: float
    kyber_public_key: bytes
    kyber_secret_key: bytes
    dilithium_public_key: bytes
    dilithium_secret_key: bytes


@dataclass
class SecureTransaction:
    """Quantum-safe transaction"""
    transaction_id: str
    sender_account: str
    receiver_account: str
    amount: float
    encrypted_data: bytes
    kyber_ciphertext: bytes
    dilithium_signature: bytes
    timestamp: float
    status: str


class QuantumSafeBankingSystem:
    """
    Complete quantum-safe banking system using:
    - CRYSTALS-Kyber-768 for encryption
    - CRYSTALS-Dilithium3 for signatures
    """
    
    def __init__(self):
        self.kyber = CRYSTALSKyber768()
        self.dilithium = CRYSTALSDilithium3()
        self.accounts: Dict[str, BankAccount] = {}
        self.transactions: Dict[str, SecureTransaction] = {}
    
    def create_account(self, account_number: str, account_name: str, initial_balance: float) -> BankAccount:
        """
        Create a new bank account with quantum keys
        
        Args:
            account_number: Account number
            account_name: Account holder name
            initial_balance: Starting balance
            
        Returns:
            BankAccount with generated quantum keys
        """
        logger.info(f"Creating account: {account_number} for {account_name}")
        
        # Generate Kyber keypair for encryption
        kyber_keys = self.kyber.generate_keypair()
        
        # Generate Dilithium keypair for signatures
        dilithium_keys = self.dilithium.generate_keypair()
        
        account = BankAccount(
            account_number=account_number,
            account_name=account_name,
            balance=initial_balance,
            kyber_public_key=kyber_keys.public_key,
            kyber_secret_key=kyber_keys.secret_key,
            dilithium_public_key=dilithium_keys.public_key,
            dilithium_secret_key=dilithium_keys.secret_key
        )
        
        self.accounts[account_number] = account
        logger.info(f"Account created successfully with quantum keys")
        
        return account
    
    def transfer_money(
        self,
        sender_account_num: str,
        receiver_account_num: str,
        amount: float
    ) -> SecureTransaction:
        """
        Execute quantum-safe money transfer
        
        Args:
            sender_account_num: Sender's account number
            receiver_account_num: Receiver's account number
            amount: Transfer amount
            
        Returns:
            SecureTransaction object
        """
        logger.info(f"Processing transfer: {sender_account_num} -> {receiver_account_num}, Amount: ${amount}")
        
        # Validate accounts
        if sender_account_num not in self.accounts:
            raise ValueError(f"Sender account {sender_account_num} not found")
        if receiver_account_num not in self.accounts:
            raise ValueError(f"Receiver account {receiver_account_num} not found")
        
        sender = self.accounts[sender_account_num]
        receiver = self.accounts[receiver_account_num]
        
        # Check balance
        if sender.balance < amount:
            raise ValueError(f"Insufficient balance: ${sender.balance} < ${amount}")
        
        # Create transaction data
        transaction_data = {
            "sender": sender_account_num,
            "receiver": receiver_account_num,
            "amount": amount,
            "timestamp": time.time()
        }
        
        # Step 1: Sign transaction with sender's Dilithium key
        logger.info("Step 1: Signing transaction with Dilithium3...")
        message = json.dumps(transaction_data, sort_keys=True).encode()
        signature = self.dilithium.sign(message, sender.dilithium_secret_key)
        
        # Step 2: Encrypt transaction with receiver's Kyber key
        logger.info("Step 2: Encrypting transaction with Kyber-768...")
        encrypted_data, kyber_ciphertext = encrypt_with_kyber(
            message,
            receiver.kyber_public_key
        )
        
        # Step 3: Update balances
        sender.balance -= amount
        receiver.balance += amount
        
        # Step 4: Create transaction record
        import hashlib
        tx_id = hashlib.sha256(message + signature).hexdigest()[:16]
        
        transaction = SecureTransaction(
            transaction_id=tx_id,
            sender_account=sender_account_num,
            receiver_account=receiver_account_num,
            amount=amount,
            encrypted_data=encrypted_data,
            kyber_ciphertext=kyber_ciphertext,
            dilithium_signature=signature,
            timestamp=transaction_data["timestamp"],
            status="completed"
        )
        
        self.transactions[tx_id] = transaction
        
        logger.info(f"Transaction completed successfully. ID: {tx_id}")
        logger.info(f"Sender new balance: ${sender.balance}")
        logger.info(f"Receiver new balance: ${receiver.balance}")
        
        return transaction
    
    def verify_transaction(self, transaction_id: str) -> bool:
        """
        Verify transaction signature
        
        Args:
            transaction_id: Transaction ID to verify
            
        Returns:
            True if valid, False otherwise
        """
        if transaction_id not in self.transactions:
            raise ValueError(f"Transaction {transaction_id} not found")
        
        tx = self.transactions[transaction_id]
        sender = self.accounts[tx.sender_account]
        receiver = self.accounts[tx.receiver_account]
        
        logger.info(f"Verifying transaction {transaction_id}...")
        
        # Decrypt transaction data
        decrypted_data = decrypt_with_kyber(
            tx.encrypted_data,
            tx.kyber_ciphertext,
            receiver.kyber_secret_key
        )
        
        # Verify signature
        is_valid = self.dilithium.verify(
            decrypted_data,
            tx.dilithium_signature,
            sender.dilithium_public_key
        )
        
        logger.info(f"Transaction verification: {'VALID' if is_valid else 'INVALID'}")
        return is_valid
    
    def get_account_balance(self, account_number: str) -> float:
        """Get account balance"""
        if account_number not in self.accounts:
            raise ValueError(f"Account {account_number} not found")
        return self.accounts[account_number].balance
    
    def get_transaction_history(self, account_number: str) -> list:
        """Get transaction history for an account"""
        if account_number not in self.accounts:
            raise ValueError(f"Account {account_number} not found")
        
        history = []
        for tx_id, tx in self.transactions.items():
            if tx.sender_account == account_number or tx.receiver_account == account_number:
                history.append({
                    "transaction_id": tx_id,
                    "sender": tx.sender_account,
                    "receiver": tx.receiver_account,
                    "amount": tx.amount,
                    "timestamp": tx.timestamp,
                    "status": tx.status
                })
        
        return sorted(history, key=lambda x: x["timestamp"], reverse=True)


def main():
    """Demo of complete quantum-safe banking system"""
    print("=" * 60)
    print("QUANTUM-SAFE BANKING SYSTEM")
    print("CRYSTALS-Kyber-768 + CRYSTALS-Dilithium3")
    print("=" * 60)
    
    # Initialize system
    bank = QuantumSafeBankingSystem()
    
    # Create accounts
    print("\n1. Creating accounts with quantum keys...")
    alice = bank.create_account("ACC001", "Alice Smith", 10000.0)
    bob = bank.create_account("ACC002", "Bob Johnson", 5000.0)
    print(f"   Alice's account: {alice.account_number}, Balance: ${alice.balance}")
    print(f"   Bob's account: {bob.account_number}, Balance: ${bob.balance}")
    
    # Transfer money
    print("\n2. Executing quantum-safe transfer...")
    print(f"   Transferring $500 from Alice to Bob")
    transaction = bank.transfer_money("ACC001", "ACC002", 500.0)
    print(f"   Transaction ID: {transaction.transaction_id}")
    print(f"   Status: {transaction.status}")
    
    # Verify transaction
    print("\n3. Verifying transaction signature...")
    is_valid = bank.verify_transaction(transaction.transaction_id)
    print(f"   Signature valid: {is_valid}")
    
    # Check balances
    print("\n4. Updated balances:")
    print(f"   Alice: ${bank.get_account_balance('ACC001')}")
    print(f"   Bob: ${bank.get_account_balance('ACC002')}")
    
    # Transaction history
    print("\n5. Alice's transaction history:")
    history = bank.get_transaction_history("ACC001")
    for tx in history:
        print(f"   TX {tx['transaction_id']}: ${tx['amount']} to {tx['receiver']}")
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
