# Quantum-Safe Banking System - Deployment Guide

## Complete System Architecture

This is a production-grade quantum-safe banking system with:

### Backend Components
- **Advanced PQC Core** (`pqc_core.py`) - CRYSTALS-Kyber & Dilithium implementation
- **Transaction Processor** (`transaction_processor.py`) - Secure transaction pipeline
- **User Manager** (`user_manager.py`) - Advanced user & auth management
- **Main API** (`main_complete.py`) - FastAPI application with 20+ endpoints

### Frontend Components
- **Quantum Dashboard** - Real-time security monitoring
- **Transaction Forms** - Multi-step secure transfers
- **Key Management UI** - Quantum key rotation interface

### Database
- PostgreSQL with comprehensive schema
- Security audit logging
- Key rotation history tracking
- Fraud detection data storage

## Installation & Setup

### 1. Backend Setup

\`\`\`bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements_complete.txt

# Setup environment
cp backend/.env.complete backend/.env
# Edit .env with your database credentials
\`\`\`

### 2. Database Setup

\`\`\`bash
# Create database
createdb quantum_banking

# Run migrations
psql quantum_banking < scripts/01_quantum_banking_schema.sql

# Verify setup
psql quantum_banking -c "\dt"
\`\`\`

### 3. Run Backend Server

\`\`\`bash
cd backend
uvicorn main_complete:app --reload --host 0.0.0.0 --port 8000
\`\`\`

### 4. Frontend Setup

\`\`\`bash
# Install dependencies
npm install

# Create .env.local
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# Run development server
npm run dev
\`\`\`

## API Endpoints

### Authentication (10 endpoints)
- `POST /api/users/register` - Create new user
- `POST /api/users/login` - Authenticate user
- `GET /api/users/{user_id}/profile` - Get user profile
- `POST /api/mfa/setup` - Setup MFA
- `POST /api/mfa/verify` - Verify MFA code

### Quantum Keys (5 endpoints)
- `POST /api/quantum/keys/rotate` - Rotate quantum keys
- `GET /api/quantum/keys/{user_id}/info` - Get key info
- `GET /api/quantum/keys/{user_id}/history` - Key rotation history

### Transactions (5+ endpoints)
- `POST /api/transactions/transfer` - Execute transfer
- `POST /api/transactions/batch` - Batch transfers
- `GET /api/transactions/{id}` - Get transaction details
- `GET /api/transactions/history` - Transaction history

### Security Info (3 endpoints)
- `GET /api/security/info` - System security info
- `GET /health` - Health check

## Security Features

### Cryptographic Security
- **CRYSTALS-Kyber 768**: Post-quantum key encapsulation (192-bit security)
- **CRYSTALS-Dilithium 3**: Post-quantum digital signatures
- **ChaCha20-Poly1305**: Authenticated encryption
- **PBKDF2**: Key derivation with 100,000 iterations

### Access Control
- JWT-based session tokens
- Multi-factor authentication (MFA)
- Device trust management
- IP-based access control

### Fraud Detection
- Transaction velocity analysis
- Anomaly detection
- Risk scoring system
- Automatic blocking of high-risk transactions

### Audit & Compliance
- Complete audit logging
- Key rotation tracking
- Session management
- Failed login attempt monitoring

## Performance Optimizations

- Database connection pooling (20 connections)
- GZIP middleware for compression
- Async/await for non-blocking operations
- Request timing tracking
- Batch transaction processing

## Monitoring

### Logs
- All transactions logged
- Security events tracked
- API performance metrics
- Error tracking and alerting

### Metrics to Monitor
- Transaction success rate
- Average processing time
- Fraud detection rate
- System security posture

## Scaling Considerations

1. **Database**: Use connection pooling, add read replicas
2. **API**: Deploy multiple instances behind load balancer
3. **Cache**: Add Redis for session management
4. **Message Queue**: Use for async transaction processing
5. **Monitoring**: Implement Prometheus + Grafana

## Troubleshooting

### Connection Refused
\`\`\`bash
# Check if backend is running
curl http://localhost:8000/health

# Check if database is running
psql quantum_banking -c "SELECT 1"
\`\`\`

### Key Generation Issues
\`\`\`bash
# Verify liboqs installation
python -c "import liboqs; print(liboqs.__version__)"

# Falls back to SHA3-based implementation if liboqs unavailable
\`\`\`

### Database Errors
\`\`\`bash
# Reset database
dropdb quantum_banking
createdb quantum_banking
psql quantum_banking < scripts/01_quantum_banking_schema.sql
\`\`\`

## Production Deployment

1. Use environment-specific `.env` files
2. Enable database SSL connections
3. Use strong SECRET_KEY
4. Enable Row-Level Security (RLS) in database
5. Deploy behind reverse proxy (nginx/apache)
6. Use HTTPS only
7. Set up automated backups
8. Monitor all security events
9. Keep dependencies updated
10. Implement DDoS protection

## Support

For issues or questions, check the logs or review the inline code documentation in each module.
