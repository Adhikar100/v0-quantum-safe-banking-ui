"""
Quantum-Safe Banking Desktop Application
Implements CRYSTALS-Kyber & CRYSTALS-Dilithium with Tkinter GUI
NIST Post-Quantum Cryptography Standards
"""

import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import os
import sys

# PQC Libraries
try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("[WARNING] kyber-py and dilithium-py not installed. Install via: pip install kyber-py dilithium-py")

# Encryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('quantum_bank.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TransactionStatus(Enum):
    """Transaction status enumeration"""
    PENDING = "pending"
    SIGNED = "signed"
    ENCRYPTED = "encrypted"
    TRANSMITTED = "transmitted"
    FAILED = "failed"


@dataclass
class Transaction:
    """Transaction data structure"""
    sender_name: str
    sender_account: str
    receiver_name: str
    receiver_account: str
    amount: float
    timestamp: str
    status: TransactionStatus = TransactionStatus.PENDING
    signature: Optional[bytes] = None
    ciphertext: Optional[bytes] = None
    transaction_id: Optional[str] = None


class QuantumCryptoManager:
    """Manages CRYSTALS-Kyber & CRYSTALS-Dilithium operations"""
    
    def __init__(self, security_level: int = 2):
        """
        Initialize quantum crypto manager
        security_level: 1=Kyber512/Dilithium2, 2=Kyber768/Dilithium3, 3=Kyber1024/Dilithium5
        """
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        self.security_level = security_level
        self.kyber_variant = self._get_kyber_variant()
        self.dilithium_variant = self._get_dilithium_variant()
        
        # Initialize keypairs
        self.dilithium_sk, self.dilithium_pk = self.dilithium_variant.keygen()
        logger.info(f"Dilithium keypair generated (Level {security_level})")
    
    def _get_kyber_variant(self):
        """Get Kyber variant based on security level"""
        variants = {1: ML_KEM_512, 2: ML_KEM_768, 3: ML_KEM_1024}
        return variants.get(self.security_level, ML_KEM_768)
    
    def _get_dilithium_variant(self):
        """Get Dilithium variant based on security level"""
        variants = {1: ML_DSA_44, 2: ML_DSA_65, 3: ML_DSA_87}
        return variants.get(self.security_level, ML_DSA_65)
    
    def generate_receiver_kyber_keypair(self) -> bytes:
        """Generate Kyber public key for receiver"""
        ek, _ = self.kyber_variant.keygen()
        logger.info("Receiver Kyber keypair generated")
        return ek
    
    def sign_transaction(self, message: bytes) -> bytes:
        """Sign transaction with Dilithium"""
        signature = self.dilithium_variant.sign(self.dilithium_sk, message)
        logger.info(f"Transaction signed with Dilithium (sig length: {len(signature)} bytes)")
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Verify Dilithium signature"""
        try:
            self.dilithium_variant.verify(self.dilithium_pk, message, signature)
            logger.info("Signature verified successfully")
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def encrypt_transaction(self, message: bytes, receiver_kyber_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt transaction with Kyber KEM + AES-256-CBC
        Returns: (ciphertext, encapsulated_key)
        """
        # Kyber encapsulation
        ss, ct = self.kyber_variant.encaps(receiver_kyber_pk)
        
        # Derive AES key from shared secret
        aes_key = hashlib.sha256(ss).digest()[:32]
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Encrypt with AES-256-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        
        # Combine IV + ciphertext
        encrypted_data = iv + ciphertext
        
        logger.info(f"Transaction encrypted with Kyber+AES (data: {len(encrypted_data)} bytes)")
        return encrypted_data, ct
    
    def decrypt_transaction(self, encrypted_data: bytes, ciphertext_kyber: bytes, 
                           receiver_kyber_sk: bytes) -> Optional[bytes]:
        """Decrypt transaction (for receiver)"""
        try:
            # Kyber decapsulation
            ss = self.kyber_variant.decaps(ciphertext_kyber, receiver_kyber_sk)
            
            # Derive AES key
            aes_key = hashlib.sha256(ss).digest()[:32]
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            logger.info("Transaction decrypted successfully")
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None


class QuantumBankingGUI:
    """Main GUI Application for Quantum-Safe Banking"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum-Safe Banking System")
        self.root.geometry("500x650")
        self.root.resizable(False, False)
        
        # Color scheme
        self.bg_color = "#1a1a2e"
        self.fg_color = "#0f3460"
        self.accent_color = "#16c784"
        self.error_color = "#e74c3c"
        self.text_color = "#ecf0f1"
        
        self.root.config(bg=self.bg_color)
        
        # Initialize crypto
        try:
            self.crypto = QuantumCryptoManager(security_level=2)
            self.quantum_ready = True
        except Exception as e:
            logger.error(f"Failed to initialize quantum crypto: {e}")
            self.quantum_ready = False
            messagebox.showerror("Error", f"Quantum crypto initialization failed: {e}")
            self.root.quit()
        
        # Demo receiver data with Kyber public keys
        self.receivers: Dict[str, Dict] = {
            "123456789": {
                "name": "John Doe",
                "kyber_pk": self.crypto.generate_receiver_kyber_keypair(),
                "kyber_sk": None  # In production, stored securely
            },
            "987654321": {
                "name": "Jane Smith",
                "kyber_pk": self.crypto.generate_receiver_kyber_keypair(),
                "kyber_sk": None
            },
            "555555555": {
                "name": "Bob Johnson",
                "kyber_pk": self.crypto.generate_receiver_kyber_keypair(),
                "kyber_sk": None
            }
        }
        
        # Sender account
        self.sender_account = "999999999"
        self.sender_name = "Alice Cooper"
        
        # Transaction history
        self.transactions = []
        
        self.setup_ui()
        logger.info("Quantum Banking GUI initialized successfully")
    
    def setup_ui(self):
        """Setup UI components following flowchart"""
        
        # Title
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(pady=15)
        
        title_label = tk.Label(
            title_frame,
            text="🔐 Quantum-Safe Banking",
            font=("Arial", 18, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()
        
        subtitle = tk.Label(
            title_frame,
            text="CRYSTALS-Kyber & CRYSTALS-Dilithium PQC",
            font=("Arial", 9),
            bg=self.bg_color,
            fg=self.text_color
        )
        subtitle.pack()
        
        # Error label
        self.error_label = tk.Label(
            self.root,
            text="",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.error_color,
            wraplength=450
        )
        self.error_label.pack(pady=10)
        
        # Main form frame
        form_frame = tk.Frame(self.root, bg=self.fg_color, relief=tk.RAISED, bd=2)
        form_frame.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)
        
        # Receiver Name
        tk.Label(
            form_frame,
            text="Receiver Name:",
            font=("Arial", 10, "bold"),
            bg=self.fg_color,
            fg=self.text_color
        ).pack(anchor=tk.W, padx=15, pady=(15, 5))
        
        self.name_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            bg="#0a0a14",
            fg=self.text_color,
            insertbackground=self.accent_color
        )
        self.name_entry.pack(padx=15, pady=(0, 10), fill=tk.X, ipady=8)
        self.name_entry.bind("<Return>", lambda e: self.validate_and_proceed())
        
        # Receiver Account
        tk.Label(
            form_frame,
            text="Receiver Account:",
            font=("Arial", 10, "bold"),
            bg=self.fg_color,
            fg=self.text_color
        ).pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        self.account_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            bg="#0a0a14",
            fg=self.text_color,
            insertbackground=self.accent_color
        )
        self.account_entry.pack(padx=15, pady=(0, 10), fill=tk.X, ipady=8)
        self.account_entry.bind("<Return>", lambda e: self.validate_and_proceed())
        
        # Amount
        tk.Label(
            form_frame,
            text="Amount ($):",
            font=("Arial", 10, "bold"),
            bg=self.fg_color,
            fg=self.text_color
        ).pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        self.amount_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            bg="#0a0a14",
            fg=self.text_color,
            insertbackground=self.accent_color
        )
        self.amount_entry.pack(padx=15, pady=(0, 15), fill=tk.X, ipady=8)
        self.amount_entry.bind("<Return>", lambda e: self.validate_and_proceed())
        
        # Security info
        security_frame = tk.Frame(form_frame, bg="#0a0a14", relief=tk.SUNKEN, bd=1)
        security_frame.pack(padx=15, pady=10, fill=tk.X)
        
        security_label = tk.Label(
            security_frame,
            text="🛡️ Quantum Security Status: Active",
            font=("Arial", 9),
            bg="#0a0a14",
            fg=self.accent_color
        )
        security_label.pack(pady=8)
        
        security_detail = tk.Label(
            security_frame,
            text="CRYSTALS-Kyber (Encryption) | CRYSTALS-Dilithium (Signatures)\nNIST Post-Quantum Cryptography Standard",
            font=("Arial", 8),
            bg="#0a0a14",
            fg=self.text_color
        )
        security_detail.pack(pady=(0, 8))
        
        # Buttons
        button_frame = tk.Frame(self.root, bg=self.bg_color)
        button_frame.pack(pady=15)
        
        self.cancel_btn = tk.Button(
            button_frame,
            text="CANCEL",
            font=("Arial", 11, "bold"),
            bg="#e74c3c",
            fg="white",
            padx=20,
            pady=10,
            command=self.cancel_transaction,
            cursor="hand2"
        )
        self.cancel_btn.pack(side=tk.LEFT, padx=10)
        
        self.send_btn = tk.Button(
            button_frame,
            text="SEND",
            font=("Arial", 11, "bold"),
            bg=self.accent_color,
            fg="black",
            padx=20,
            pady=10,
            command=self.validate_and_proceed,
            cursor="hand2"
        )
        self.send_btn.pack(side=tk.LEFT, padx=10)
        
        # Transaction history section
        history_label = tk.Label(
            self.root,
            text="Recent Transactions",
            font=("Arial", 10, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        history_label.pack(pady=(10, 5))
        
        # Listbox for transactions
        self.history_listbox = tk.Listbox(
            self.root,
            font=("Arial", 8),
            bg="#0a0a14",
            fg=self.text_color,
            height=4,
            relief=tk.SUNKEN
        )
        self.history_listbox.pack(padx=15, fill=tk.BOTH, expand=True)
    
    def show_error(self, message: str):
        """Display error message"""
        self.error_label.config(text=f"❌ {message}", fg=self.error_color)
        logger.warning(f"User error: {message}")
    
    def clear_error(self):
        """Clear error message"""
        self.error_label.config(text="")
    
    def validate_name(self) -> bool:
        """Step 1: Validate receiver name"""
        name = self.name_entry.get().strip()
        if not name:
            self.show_error("Please enter receiver name.")
            self.name_entry.focus()
            return False
        
        # Check if name exists in receivers
        name_found = any(
            info["name"].lower() == name.lower()
            for info in self.receivers.values()
        )
        
        if not name_found:
            self.show_error(f"Receiver '{name}' not found in system.")
            self.name_entry.focus()
            return False
        
        self.clear_error()
        logger.info(f"Name validation passed: {name}")
        return True
    
    def validate_account(self) -> bool:
        """Step 2: Validate receiver account"""
        account = self.account_entry.get().strip()
        
        if not account:
            self.show_error("Please enter receiver account number.")
            self.account_entry.focus()
            return False
        
        if not account.isdigit():
            self.show_error("Account must be numeric.")
            self.account_entry.focus()
            return False
        
        if account not in self.receivers:
            self.show_error("Account not found in system.")
            self.account_entry.focus()
            return False
        
        # Verify name matches account
        receiver_name = self.name_entry.get().strip()
        account_name = self.receivers[account]["name"]
        
        if receiver_name.lower() != account_name.lower():
            self.show_error(f"Name mismatch. Account belongs to {account_name}.")
            self.name_entry.focus()
            return False
        
        self.clear_error()
        logger.info(f"Account validation passed: {account}")
        return True
    
    def validate_amount(self) -> bool:
        """Step 3: Validate amount"""
        amount_str = self.amount_entry.get().strip()
        
        if not amount_str:
            self.show_error("Please enter transaction amount.")
            self.amount_entry.focus()
            return False
        
        try:
            amount = float(amount_str)
            if amount <= 0:
                self.show_error("Amount must be greater than zero.")
                self.amount_entry.focus()
                return False
            
            if amount > 1000000:
                self.show_error("Amount exceeds maximum limit ($1,000,000).")
                self.amount_entry.focus()
                return False
        
        except ValueError:
            self.show_error("Invalid amount format. Please enter a number.")
            self.amount_entry.focus()
            return False
        
        self.clear_error()
        logger.info(f"Amount validation passed: ${amount}")
        return True
    
    def validate_and_proceed(self):
        """Validate all fields and proceed with transaction"""
        if not self.validate_name():
            return
        
        if not self.validate_account():
            return
        
        if not self.validate_amount():
            return
        
        # All validations passed - proceed with transaction
        self.process_transaction()
    
    def process_transaction(self):
        """Step 5: Process transaction with PQC"""
        receiver_account = self.account_entry.get().strip()
        receiver_name = self.receivers[receiver_account]["name"]
        amount = float(self.amount_entry.get().strip())
        
        try:
            # Build transaction message
            timestamp = datetime.now().isoformat()
            transaction_data = {
                "sender": self.sender_name,
                "sender_account": self.sender_account,
                "receiver": receiver_name,
                "receiver_account": receiver_account,
                "amount": amount,
                "timestamp": timestamp
            }
            
            message = json.dumps(transaction_data).encode('utf-8')
            
            # Step 5a: Sign with Dilithium
            self.show_error("⏳ Signing transaction with CRYSTALS-Dilithium...")
            self.root.update()
            
            signature = self.crypto.sign_transaction(message)
            
            if not self.crypto.verify_signature(message, signature):
                self.show_error("❌ Signature verification failed!")
                logger.error("Signature verification failed")
                return
            
            # Step 5b: Encrypt with Kyber
            self.show_error("⏳ Encrypting with CRYSTALS-Kyber...")
            self.root.update()
            
            receiver_kyber_pk = self.receivers[receiver_account]["kyber_pk"]
            encrypted_data, ciphertext_kyber = self.crypto.encrypt_transaction(
                message + b"|" + signature,
                receiver_kyber_pk
            )
            
            # Create transaction object
            transaction = Transaction(
                sender_name=self.sender_name,
                sender_account=self.sender_account,
                receiver_name=receiver_name,
                receiver_account=receiver_account,
                amount=amount,
                timestamp=timestamp,
                status=TransactionStatus.ENCRYPTED,
                signature=signature.hex(),
                ciphertext=encrypted_data.hex()
            )
            
            # Generate transaction ID
            transaction_id = hashlib.sha256(
                (message + signature + str(timestamp).encode()).encode()
            ).hexdigest()[:16]
            transaction.transaction_id = transaction_id
            
            self.transactions.append(transaction)
            
            # Display success
            self.show_success_transaction(transaction, encrypted_data, ciphertext_kyber)
            
        except Exception as e:
            logger.error(f"Transaction processing failed: {e}")
            self.show_error(f"❌ Transaction failed: {str(e)}")
    
    def show_success_transaction(self, transaction: Transaction, encrypted_data: bytes, ct_kyber: bytes):
        """Display transaction success details"""
        self.clear_error()
        
        success_msg = f"""✅ Transaction Successful!

Transaction ID: {transaction.transaction_id}
Sender: {transaction.sender_name} ({transaction.sender_account})
Receiver: {transaction.receiver_name} ({transaction.receiver_account})
Amount: ${transaction.amount:.2f}
Timestamp: {transaction.timestamp}

Quantum Security Applied:
• Signature: CRYSTALS-Dilithium (ML-DSA-65)
• Encryption: CRYSTALS-Kyber (ML-KEM-768) + AES-256-CBC
• Message Hash: {hashlib.sha256(json.dumps(asdict(transaction)).encode()).hexdigest()[:16]}

Encrypted Data (hex preview): {encrypted_data.hex()[:32]}...
Kyber Ciphertext (hex): {ct_kyber.hex()[:32]}...
"""
        
        messagebox.showinfo("Transaction Complete", success_msg)
        
        # Update history
        self.update_transaction_history()
        
        # Clear form
        self.name_entry.delete(0, tk.END)
        self.account_entry.delete(0, tk.END)
        self.amount_entry.delete(0, tk.END)
        self.name_entry.focus()
        
        logger.info(f"Transaction completed: {transaction.transaction_id}")
    
    def update_transaction_history(self):
        """Update transaction history listbox"""
        self.history_listbox.delete(0, tk.END)
        
        for tx in reversed(self.transactions[-5:]):  # Show last 5
            history_text = f"{tx.timestamp[:10]} | {tx.sender_name} → {tx.receiver_name} | ${tx.amount:.2f} | ID: {tx.transaction_id}"
            self.history_listbox.insert(tk.END, history_text)
    
    def cancel_transaction(self):
        """Step 4: Cancel transaction"""
        result = messagebox.askyesno("Confirm", "Cancel this transaction?")
        if result:
            self.name_entry.delete(0, tk.END)
            self.account_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)
            self.clear_error()
            self.name_entry.focus()
            logger.info("Transaction cancelled by user")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = QuantumBankingGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
