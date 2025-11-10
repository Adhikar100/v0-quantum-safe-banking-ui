# Quantum-Safe Banking Desktop Application

## Installation

### 1. Install Python Dependencies

\`\`\`bash
pip install -r desktop_app/requirements.txt
\`\`\`

### 2. System Requirements
- Python 3.9+
- Tkinter (usually included with Python)
- 50MB free disk space

## Running the Application

\`\`\`bash
python desktop_app/quantum_banking_desktop.py
\`\`\`

## Features

### Quantum-Safe Cryptography
- **CRYSTALS-Kyber (ML-KEM-768)**: Post-quantum key encapsulation for secure encryption
- **CRYSTALS-Dilithium (ML-DSA-65)**: NIST-approved digital signatures
- **AES-256-CBC**: Symmetric encryption after key establishment
- **SHA-256**: Hashing for transaction IDs

### Transaction Flow
1. **Enter Receiver Name**: Validates name exists in system
2. **Enter Account Number**: Verifies account matches name
3. **Enter Amount**: Checks validity (0 < amount ≤ $1,000,000)
4. **Confirm or Cancel**: User decides to proceed or abort
5. **Sign & Encrypt**: Transaction signed with Dilithium, encrypted with Kyber+AES
6. **Success Display**: Shows transaction ID and crypto details

### Demo Receivers
- **John Doe** (123456789)
- **Jane Smith** (987654321)
- **Bob Johnson** (555555555)

### Security Features
- Real-time quantum crypto operations
- Transaction signature verification
- Encryption/decryption with random IVs
- Complete audit logging
- Transaction history tracking

## Error Handling

The application validates at each step:
- Non-empty name input
- Account exists in system
- Name-account matching
- Positive amount within limits
- Cryptographic operation success

All errors are displayed in red on the GUI and logged to `quantum_bank.log`.

## Production Enhancements

1. **Database Integration**: Replace hardcoded receivers with PostgreSQL (Neon)
2. **Key Storage**: Use Hardware Security Modules (HSM) for key management
3. **Network Transmission**: Send encrypted transactions over HTTPS
4. **Receiver Decryption**: Implement full receiver-side decryption flow
5. **Multi-Factor Auth**: Add 2FA/biometric authentication
6. **Rate Limiting**: Implement velocity checks and fraud detection

## Testing

### Test Valid Transaction
- Name: "John Doe"
- Account: "123456789"
- Amount: "100"
- Expected: Success with signed & encrypted transaction

### Test Invalid Name
- Name: "Unknown Person"
- Expected: Error message, stays on name field

### Test Invalid Account
- Name: "John Doe"
- Account: "111111111"
- Expected: Account not found error

### Test Invalid Amount
- Amount: "-50" or "0" or "abc"
- Expected: Validation error with appropriate message

## Logging

Logs are written to `quantum_bank.log` with timestamp, module, level, and message. Check this file for debugging failed transactions or cryptographic operations.

## Performance

- Key generation: ~100ms (Kyber + Dilithium)
- Transaction signing: ~50ms
- Transaction encryption: ~30ms
- Total per-transaction: ~200ms
