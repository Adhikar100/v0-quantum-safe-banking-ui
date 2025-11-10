from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    account_number = Column(String, unique=True, index=True)
    balance = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    transactions_sent = relationship("Transaction", foreign_keys="Transaction.sender_id", back_populates="sender")
    transactions_received = relationship("Transaction", foreign_keys="Transaction.receiver_id", back_populates="receiver")
    quantum_keys = relationship("QuantumKey", back_populates="user")

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    status = Column(String, default="pending")  # pending, completed, failed
    encrypted_data = Column(Text)
    quantum_signature = Column(String)
    nist_approved = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="transactions_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="transactions_received")

class QuantumKey(Base):
    __tablename__ = "quantum_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    key_type = Column(String)  # kyber, dilithium
    public_key = Column(Text)
    private_key = Column(Text)  # Encrypted in production
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

    user = relationship("User", back_populates="quantum_keys")
