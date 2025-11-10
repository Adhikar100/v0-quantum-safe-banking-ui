"""
Optimized database layer with connection pooling, query optimization,
and automatic index management
"""
from sqlalchemy import create_engine, event, pool, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
import logging
from config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Create optimized engine with connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_recycle=3600,  # Recycle connections every hour
    echo=settings.DATABASE_ECHO,
    connect_args={
        "timeout": 20,
        "check_same_thread": False if "sqlite" in settings.DATABASE_URL else None
    }
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)

Base = declarative_base()

class DatabaseManager:
    """Manages database operations with optimization"""
    
    @staticmethod
    def get_db() -> Session:
        """Get database session"""
        return SessionLocal()
    
    @staticmethod
    def create_indexes():
        """Create database indexes for performance"""
        from models import User, Transaction, QuantumKey
        
        indexes = [
            Index('idx_user_email', User.email),
            Index('idx_user_account', User.account_number),
            Index('idx_transaction_sender', Transaction.sender_id),
            Index('idx_transaction_receiver', Transaction.receiver_id),
            Index('idx_transaction_status', Transaction.status),
            Index('idx_transaction_created', Transaction.created_at),
            Index('idx_quantum_key_user', QuantumKey.user_id),
            Index('idx_quantum_key_active', QuantumKey.is_active),
        ]
        
        logger.info("Creating database indexes")
        for idx in indexes:
            try:
                idx.create(engine, checkfirst=True)
            except Exception as e:
                logger.warning(f"Index creation warning: {e}")

# Event listeners for connection optimization
@event.listens_for(engine, "connect")
def receive_connect(dbapi_connection, connection_record):
    """Optimize connection settings"""
    if "sqlite" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=10000")
        cursor.close()

def init_db():
    """Initialize database with tables and indexes"""
    logger.info("Initializing database")
    Base.metadata.create_all(bind=engine)
    DatabaseManager.create_indexes()
    logger.info("Database initialization complete")

def get_db_session() -> Session:
    """Dependency for getting DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
