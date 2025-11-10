"""
Quantum-Safe Banking Database Service
Neon PostgreSQL integration with PQC key storage
"""

import logging
from typing import Optional, List, Dict, Tuple
from datetime import datetime
import json
from dataclasses import asdict

try:
    from neon_serverless import neon
    NEON_AVAILABLE = True
except ImportError:
    NEON_AVAILABLE = False

logger = logging.getLogger(__name__)


class QuantumBankingDatabase:
    """Database service for quantum-safe banking"""
    
    def __init__(self, database_url: str):
        """Initialize database connection"""
        if not NEON_AVAILABLE:
            logger.warning("Neon not available. Using in-memory storage.")
            self.sql = None
            self.use_memory = True
            self.memory_db = {
                "users": {},
                "accounts": {},
                "transactions": {},
                "keys": {},
                "audit_log": []
            }
        else:
            self.sql = neon(database_url)
            self.use_memory = False
        
        logger.info("QuantumBankingDatabase initialized")
    
    def init_schema(self) -> bool:
        """Initialize database schema"""
        if self.use_memory:
            logger.info("Using in-memory database")
            return True
        
        try:
            schema_sql = """
            -- Users table
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255),
                dilithium_pk BYTEA NOT NULL,
                kyber_pk BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            
            -- Accounts table
            CREATE TABLE IF NOT EXISTS accounts (
                account_id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(user_id),
                account_number VARCHAR(20) UNIQUE NOT NULL,
                account_type VARCHAR(50),
                balance DECIMAL(15, 2) DEFAULT 0,
                currency VARCHAR(3) DEFAULT 'USD',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            
            -- Transactions table
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id SERIAL PRIMARY KEY,
                transaction_id VARCHAR(36) UNIQUE NOT NULL,
                sender_account VARCHAR(20) NOT NULL,
                receiver_account VARCHAR(20) NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                fee DECIMAL(15, 2),
                currency VARCHAR(3) DEFAULT 'USD',
                status VARCHAR(50),
                encrypted_payload BYTEA,
                kyber_ciphertext BYTEA,
                dilithium_signature BYTEA,
                message_hash VARCHAR(256),
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            -- Quantum keys table
            CREATE TABLE IF NOT EXISTS quantum_keys (
                key_id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(user_id),
                key_type VARCHAR(50),  -- 'kyber' or 'dilithium'
                security_level INTEGER,
                public_key BYTEA,
                key_hash VARCHAR(256),
                created_at TIMESTAMP DEFAULT NOW(),
                rotated_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
            
            -- Audit log table
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id SERIAL PRIMARY KEY,
                operation VARCHAR(100),
                user_id INTEGER,
                transaction_id VARCHAR(36),
                status VARCHAR(50),
                details JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_account);
            CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_account);
            CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
            CREATE INDEX IF NOT EXISTS idx_quantum_keys_user_id ON quantum_keys(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
            """
            
            self.sql(schema_sql)
            logger.info("Database schema initialized")
            return True
            
        except Exception as e:
            logger.error(f"Schema initialization failed: {e}")
            return False
    
    def create_user(self, username: str, email: str, full_name: str,
                   dilithium_pk: bytes, kyber_pk: bytes) -> Optional[int]:
        """Create new user with quantum keys"""
        if self.use_memory:
            user_id = len(self.memory_db["users"]) + 1
            self.memory_db["users"][user_id] = {
                "user_id": user_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "dilithium_pk": dilithium_pk,
                "kyber_pk": kyber_pk,
                "created_at": datetime.now().isoformat()
            }
            return user_id
        
        try:
            result = self.sql(
                """INSERT INTO users (username, email, full_name, dilithium_pk, kyber_pk)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING user_id""",
                username, email, full_name, dilithium_pk, kyber_pk
            )
            user_id = result[0][0]
            logger.info(f"User created: {user_id}")
            return user_id
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            return None
    
    def create_account(self, user_id: int, account_number: str, account_type: str = "checking") -> bool:
        """Create bank account for user"""
        if self.use_memory:
            account_id = len(self.memory_db["accounts"]) + 1
            self.memory_db["accounts"][account_id] = {
                "account_id": account_id,
                "user_id": user_id,
                "account_number": account_number,
                "account_type": account_type,
                "balance": 10000.0,
                "created_at": datetime.now().isoformat()
            }
            return True
        
        try:
            self.sql(
                """INSERT INTO accounts (user_id, account_number, account_type, balance)
                   VALUES ($1, $2, $3, $4)""",
                user_id, account_number, account_type, 10000.0
            )
            logger.info(f"Account created: {account_number}")
            return True
        except Exception as e:
            logger.error(f"Account creation failed: {e}")
            return False
    
    def store_transaction(self, transaction_id: str, sender_account: str, receiver_account: str,
                         amount: float, status: str, encrypted_payload: bytes,
                         kyber_ct: bytes, signature: bytes, message_hash: str) -> bool:
        """Store encrypted transaction"""
        if self.use_memory:
            tx_id = len(self.memory_db["transactions"]) + 1
            self.memory_db["transactions"][tx_id] = {
                "transaction_id": transaction_id,
                "sender_account": sender_account,
                "receiver_account": receiver_account,
                "amount": amount,
                "status": status,
                "encrypted_payload": encrypted_payload,
                "kyber_ciphertext": kyber_ct,
                "dilithium_signature": signature,
                "message_hash": message_hash,
                "created_at": datetime.now().isoformat()
            }
            return True
        
        try:
            self.sql(
                """INSERT INTO transactions 
                   (transaction_id, sender_account, receiver_account, amount, status, 
                    encrypted_payload, kyber_ciphertext, dilithium_signature, message_hash)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                transaction_id, sender_account, receiver_account, amount, status,
                encrypted_payload, kyber_ct, signature, message_hash
            )
            logger.info(f"Transaction stored: {transaction_id}")
            return True
        except Exception as e:
            logger.error(f"Transaction storage failed: {e}")
            return False
    
    def get_user_transactions(self, account_number: str, limit: int = 50) -> List[Dict]:
        """Get user transaction history"""
        if self.use_memory:
            txs = [tx for tx in self.memory_db["transactions"].values()
                   if tx["sender_account"] == account_number or tx["receiver_account"] == account_number]
            return sorted(txs, key=lambda x: x["created_at"], reverse=True)[:limit]
        
        try:
            results = self.sql(
                """SELECT transaction_id, sender_account, receiver_account, amount, status, created_at
                   FROM transactions
                   WHERE sender_account = $1 OR receiver_account = $1
                   ORDER BY created_at DESC
                   LIMIT $2""",
                account_number, limit
            )
            return [
                {
                    "transaction_id": row[0],
                    "sender_account": row[1],
                    "receiver_account": row[2],
                    "amount": float(row[3]),
                    "status": row[4],
                    "created_at": row[5].isoformat()
                }
                for row in results
            ]
        except Exception as e:
            logger.error(f"Transaction retrieval failed: {e}")
            return []
    
    def log_audit_event(self, operation: str, user_id: Optional[int], transaction_id: Optional[str],
                       status: str, details: Dict) -> bool:
        """Log audit event"""
        if self.use_memory:
            self.memory_db["audit_log"].append({
                "operation": operation,
                "user_id": user_id,
                "transaction_id": transaction_id,
                "status": status,
                "details": details,
                "created_at": datetime.now().isoformat()
            })
            return True
        
        try:
            self.sql(
                """INSERT INTO audit_log (operation, user_id, transaction_id, status, details)
                   VALUES ($1, $2, $3, $4, $5)""",
                operation, user_id, transaction_id, status, json.dumps(details)
            )
            logger.info(f"Audit event logged: {operation}")
            return True
        except Exception as e:
            logger.error(f"Audit logging failed: {e}")
            return False
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Retrieve audit log"""
        if self.use_memory:
            return self.memory_db["audit_log"][-limit:]
        
        try:
            results = self.sql(
                """SELECT log_id, operation, user_id, transaction_id, status, created_at
                   FROM audit_log
                   ORDER BY created_at DESC
                   LIMIT $1""",
                limit
            )
            return [
                {
                    "log_id": row[0],
                    "operation": row[1],
                    "user_id": row[2],
                    "transaction_id": row[3],
                    "status": row[4],
                    "created_at": row[5].isoformat()
                }
                for row in results
            ]
        except Exception as e:
            logger.error(f"Audit log retrieval failed: {e}")
            return []
