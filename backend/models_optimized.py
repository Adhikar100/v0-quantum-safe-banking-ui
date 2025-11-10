"""
Optimized SQLAlchemy models with better relationships and indexing
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.orm import relationship, validates
from datetime import datetime
from database_optimized import Base
import logging

logger = logging.getLogger(__name__)

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_account', 'account_number'),
    )

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    account_number = Column(String(20), unique=True, index=True, nullable=False)
    balance = Column(Float, default=0.0, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    kyber_public_key = Column(Text, nullable=True)
    dilithium_public_key = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    transactions_sent = relationship(
        "Transaction",
        foreign_keys="Transaction.sender_id",
        back_populates="sender",
        cascade="all, delete-orphan"
    )
    transactions_received = relationship(
        "Transaction",
        foreign_keys="Transaction.receiver_id",
        back_populates="receiver",
        cascade="all, delete-orphan"
    )
    quantum_keys = relationship(
        "QuantumKey",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    @validates('email')
    def validate_email(self, key, value):
        if '@' not in value:
            raise ValueError("Invalid email")
        return value.lower()
    
    @validates('balance')
    def validate_balance(self, key, value):
        if value < 0:
            raise ValueError("Balance cannot be negative")
        return value

class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        Index('idx_transaction_sender', 'sender_id'),
        Index('idx_transaction_receiver', 'receiver_id'),
        Index('idx_transaction_status', 'status'),
        Index('idx_transaction_created', 'created_at'),
    )

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String(20), default="pending", index=True, nullable=False)
    encrypted_data = Column(Text, nullable=False)
    quantum_signature = Column(Text, nullable=False)
    nonce = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    failed_reason = Column(String(500), nullable=True)

    sender = relationship(
        "User",
        foreign_keys=[sender_id],
        back_populates="transactions_sent"
    )
    receiver = relationship(
        "User",
        foreign_keys=[receiver_id],
        back_populates="transactions_received"
    )

    @validates('amount')
    def validate_amount(self, key, value):
        if value <= 0:
            raise ValueError("Amount must be positive")
        return value

class QuantumKey(Base):
    __tablename__ = "quantum_keys"
    __table_args__ = (
        Index('idx_quantum_key_user', 'user_id'),
        Index('idx_quantum_key_active', 'is_active'),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_type = Column(String(20), nullable=False)  # kyber, dilithium
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="quantum_keys")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_action', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")
