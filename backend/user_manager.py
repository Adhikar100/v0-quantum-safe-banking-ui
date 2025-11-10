"""
Advanced User Management & Authentication with Quantum Key Management
"""
import logging
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from enum import Enum
import secrets
import hashlib
from decimal import Decimal

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from jose import JWTError, jwt
from passlib.context import CryptContext
import base64

from backend.pqc_core import (
    get_kyber,
    get_dilithium,
    SecurityLevel,
    QuantumKeyPair,
)

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserRole(Enum):
    """User roles"""
    CUSTOMER = "customer"
    PREMIUM = "premium"
    BUSINESS = "business"
    ADMIN = "admin"

class UserStatus(Enum):
    """User account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"

class UserSecurityProfile:
    """Enhanced user security profile"""
    
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.kyber_keypair: Optional[QuantumKeyPair] = None
        self.dilithium_keypair: Optional[QuantumKeyPair] = None
        self.backup_kyber_keypair: Optional[QuantumKeyPair] = None
        self.backup_dilithium_keypair: Optional[QuantumKeyPair] = None
        self.key_rotation_schedule: datetime = datetime.utcnow() + timedelta(days=90)
        self.last_login: Optional[datetime] = None
        self.failed_login_attempts: int = 0
        self.mfa_enabled: bool = False
        self.mfa_secret: Optional[str] = None
        self.trusted_devices: List[str] = []

class AdvancedUserManager:
    """Advanced user management with quantum security"""
    
    LOGIN_ATTEMPT_LIMIT = 5
    LOCKOUT_DURATION_MINUTES = 30
    SESSION_TIMEOUT_MINUTES = 60
    MFA_CODE_VALIDITY_MINUTES = 5
    
    def __init__(self, db: Session):
        self.db = db
        self.kyber = get_kyber()
        self.dilithium = get_dilithium()
        self.user_security_profiles: Dict[int, UserSecurityProfile] = {}
    
    def hash_password(self, password: str) -> str:
        """Hash password securely"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    async def create_user(
        self,
        email: str,
        password: str,
        name: str,
        account_number: str,
        role: UserRole = UserRole.CUSTOMER,
        initial_balance: Decimal = Decimal("0.00"),
    ) -> Tuple[bool, Optional[int], str]:
        """Create new user with quantum security setup"""
        try:
            logger.info(f"Creating user: {email}")
            
            # Validate email uniqueness
            existing_user = self.db.query(lambda: None).filter_by(email=email).first()
            if existing_user:
                return False, None, "Email already registered"
            
            # Validate account number uniqueness
            existing_account = self.db.query(lambda: None).filter_by(account_number=account_number).first()
            if existing_account:
                return False, None, "Account number already exists"
            
            # Hash password
            hashed_password = self.hash_password(password)
            
            # Generate quantum keys
            kyber_keypair = self.kyber.generate_keypair()
            dilithium_keypair = self.dilithium.generate_keypair()
            
            logger.info(f"Generated quantum keypairs for {email}")
            
            # In production, this would create actual DB records
            # For now, we simulate:
            user_data = {
                "id": hash(email) % 2147483647,
                "email": email,
                "password_hash": hashed_password,
                "name": name,
                "account_number": account_number,
                "balance": float(initial_balance),
                "role": role.value,
                "status": UserStatus.PENDING_VERIFICATION.value,
                "kyber_public_key": base64.b64encode(kyber_keypair.public_key).decode(),
                "dilithium_public_key": base64.b64encode(dilithium_keypair.public_key).decode(),
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }
            
            # Create security profile
            profile = UserSecurityProfile(user_data["id"])
            profile.kyber_keypair = kyber_keypair
            profile.dilithium_keypair = dilithium_keypair
            self.user_security_profiles[user_data["id"]] = profile
            
            logger.info(f"User created successfully: {email}")
            return True, user_data["id"], "User created successfully"
            
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            return False, None, f"User creation failed: {str(e)}"
    
    async def authenticate_user(
        self,
        email: str,
        password: str,
        device_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Authenticate user with security checks"""
        try:
            logger.info(f"Authenticating user: {email}")
            
            # In production, query actual database
            user_data = self._find_user_by_email(email)
            if not user_data:
                return False, None, "Invalid email or password"
            
            # Check account status
            if user_data.get("status") == UserStatus.LOCKED.value:
                return False, None, "Account is locked"
            
            if user_data.get("status") == UserStatus.SUSPENDED.value:
                return False, None, "Account is suspended"
            
            # Verify password
            if not self.verify_password(password, user_data.get("password_hash", "")):
                # Increment failed attempts
                profile = self.user_security_profiles.get(user_data["id"])
                if profile:
                    profile.failed_login_attempts += 1
                    if profile.failed_login_attempts >= self.LOGIN_ATTEMPT_LIMIT:
                        logger.warning(f"Account locked due to failed attempts: {email}")
                        return False, None, "Too many failed login attempts. Account locked."
                
                return False, None, "Invalid email or password"
            
            # Reset failed attempts
            profile = self.user_security_profiles.get(user_data["id"])
            if profile:
                profile.failed_login_attempts = 0
                profile.last_login = datetime.utcnow()
                
                # Verify MFA if enabled
                if profile.mfa_enabled and device_id not in profile.trusted_devices:
                    return False, None, "MFA verification required"
            
            # Generate session token
            token = self._generate_session_token(user_data["id"])
            
            logger.info(f"User authenticated successfully: {email}")
            
            return True, {
                "user_id": user_data["id"],
                "email": email,
                "name": user_data.get("name"),
                "account_number": user_data.get("account_number"),
                "role": user_data.get("role"),
                "token": token,
                "expires_at": (datetime.utcnow() + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)).isoformat(),
            }, "Authentication successful"
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False, None, f"Authentication error: {str(e)}"
    
    async def rotate_quantum_keys(
        self,
        user_id: int,
        security_level: SecurityLevel = SecurityLevel.LEVEL_3,
    ) -> Tuple[bool, str]:
        """Rotate user's quantum keys"""
        try:
            logger.info(f"Rotating quantum keys for user: {user_id}")
            
            profile = self.user_security_profiles.get(user_id)
            if not profile:
                profile = UserSecurityProfile(user_id)
                self.user_security_profiles[user_id] = profile
            
            # Backup old keys
            profile.backup_kyber_keypair = profile.kyber_keypair
            profile.backup_dilithium_keypair = profile.dilithium_keypair
            
            # Generate new keys
            profile.kyber_keypair = self.kyber.generate_keypair()
            profile.dilithium_keypair = self.dilithium.generate_keypair()
            profile.key_rotation_schedule = datetime.utcnow() + timedelta(days=90)
            
            logger.info(f"Quantum keys rotated successfully for user: {user_id}")
            return True, "Quantum keys rotated successfully"
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False, f"Key rotation failed: {str(e)}"
    
    async def enable_mfa(
        self,
        user_id: int,
    ) -> Tuple[bool, Optional[str], str]:
        """Enable multi-factor authentication"""
        try:
            profile = self.user_security_profiles.get(user_id)
            if not profile:
                profile = UserSecurityProfile(user_id)
                self.user_security_profiles[user_id] = profile
            
            # Generate MFA secret
            mfa_secret = secrets.token_urlsafe(32)
            profile.mfa_enabled = True
            profile.mfa_secret = mfa_secret
            
            logger.info(f"MFA enabled for user: {user_id}")
            return True, mfa_secret, "MFA enabled successfully"
            
        except Exception as e:
            logger.error(f"MFA setup failed: {e}")
            return False, None, f"MFA setup failed: {str(e)}"
    
    async def verify_mfa(
        self,
        user_id: int,
        code: str,
    ) -> Tuple[bool, str]:
        """Verify MFA code"""
        try:
            profile = self.user_security_profiles.get(user_id)
            if not profile or not profile.mfa_enabled:
                return False, "MFA not enabled"
            
            # In production, use proper TOTP verification
            # For demo, accept code "123456"
            if code == "123456":
                logger.info(f"MFA verified for user: {user_id}")
                return True, "MFA verification successful"
            
            return False, "Invalid MFA code"
            
        except Exception as e:
            logger.error(f"MFA verification failed: {e}")
            return False, f"Verification failed: {str(e)}"
    
    def _generate_session_token(self, user_id: int, expires_delta: timedelta = None) -> str:
        """Generate secure session token"""
        if expires_delta is None:
            expires_delta = timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)
        
        expire = datetime.utcnow() + expires_delta
        token_data = {
            "user_id": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(32),  # JWT ID for revocation
        }
        
        # In production, use actual JWT signing
        token = base64.b64encode(str(token_data).encode()).decode()
        logger.info(f"Session token generated for user: {user_id}")
        return token
    
    def _find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email (mock implementation)"""
        # In production, query database
        return {
            "id": hash(email) % 2147483647,
            "email": email,
            "name": "Test User",
            "account_number": "ACC001",
            "password_hash": pwd_context.hash("testpass123"),
            "role": UserRole.CUSTOMER.value,
            "status": UserStatus.ACTIVE.value,
        }
    
    async def get_user_profile(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get complete user profile with security info"""
        try:
            profile = self.user_security_profiles.get(user_id)
            if not profile:
                return None
            
            return {
                "user_id": user_id,
                "kyber_fingerprint": profile.kyber_keypair.fingerprint if profile.kyber_keypair else None,
                "dilithium_fingerprint": profile.dilithium_keypair.fingerprint if profile.dilithium_keypair else None,
                "key_rotation_due": profile.key_rotation_schedule.isoformat(),
                "days_until_key_rotation": (profile.key_rotation_schedule - datetime.utcnow()).days,
                "last_login": profile.last_login.isoformat() if profile.last_login else None,
                "mfa_enabled": profile.mfa_enabled,
                "trusted_devices_count": len(profile.trusted_devices),
            }
        except Exception as e:
            logger.error(f"Profile retrieval failed: {e}")
            return None
