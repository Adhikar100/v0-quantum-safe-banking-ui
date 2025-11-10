"""
Advanced configuration management with environment validation and logging setup
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
import logging
from typing import Optional
import os

class Settings(BaseSettings):
    """
    Central configuration for Quantum-Safe Banking API
    Supports environment-specific configurations
    """
    # Database
    DATABASE_URL: str = "postgresql://localhost/quantum_banking"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Quantum Cryptography
    QUANTUM_KEY_ROTATION_DAYS: int = 90
    KYBER_SECURITY_LEVEL: int = 3  # 1, 2, or 3
    DILITHIUM_SECURITY_LEVEL: int = 3  # 2, 3, or 5
    USE_ACTUAL_QUANTUM_CRYPTO: bool = False  # Set to True with liboqs installed
    
    # API Configuration
    API_TITLE: str = "Quantum-Safe Banking API"
    API_DESCRIPTION: str = "Enterprise-grade banking with CRYSTALS-Kyber & Dilithium"
    API_VERSION: str = "2.0.0"
    DEBUG: bool = False
    
    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8000"
    ]
    
    # Redis Cache (optional)
    REDIS_URL: Optional[str] = None
    CACHE_TTL_SECONDS: int = 3600
    
    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD_SECONDS: int = 60
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

def setup_logging(log_level: str = "INFO"):
    """Configure application logging"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('quantum_banking.log')
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging(get_settings().LOG_LEVEL)
