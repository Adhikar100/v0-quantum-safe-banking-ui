"""Configuration management for quantum banking"""

import os
from enum import Enum

class KyberLevel(Enum):
    LEVEL_1 = 1
    LEVEL_3 = 3
    LEVEL_5 = 5

class DilithiumLevel(Enum):
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_5 = 5

# Load from environment
KYBER_SECURITY_LEVEL = int(os.getenv("KYBER_SECURITY_LEVEL", "2"))
DILITHIUM_SECURITY_LEVEL = int(os.getenv("DILITHIUM_SECURITY_LEVEL", "2"))
DATABASE_URL = os.getenv("DATABASE_URL", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "quantum_bank.log")

# Application settings
APP_NAME = "Quantum-Safe Banking System"
APP_VERSION = "1.0.0"
MAX_TRANSACTION_AMOUNT = 1000000.0
MIN_TRANSACTION_AMOUNT = 0.01
DEMO_MODE = True
