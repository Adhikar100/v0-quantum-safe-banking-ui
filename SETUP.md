# Quantum Safe Banking UI - Setup & Run Guide

## Project Overview
This is a full-stack application featuring a modern React/Next.js frontend and a Python FastAPI backend with quantum-safe cryptography (CRYSTALS-Kyber & Dilithium).

## Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn
- PostgreSQL (via Neon integration - already configured)
- Git

## Project Structure
\`\`\`
.
├── backend/                    # Python FastAPI backend
│   ├── main_optimized.py      # Main application entry
│   ├── config.py              # Configuration management
│   ├── advanced_security.py   # Quantum crypto implementation
│   ├── cache.py               # Caching layer
│   ├── routers/               # API endpoints
│   └── requirements.txt        # Python dependencies
├── app/                        # Next.js app directory
├── components/                 # React components
├── public/                     # Static assets
└── package.json               # Node.js dependencies
\`\`\`

---

## Backend Setup (Python FastAPI)

### Step 1: Install Python Dependencies
\`\`\`bash
cd backend
pip install -r requirements.txt
\`\`\`

**Key Dependencies:**
- **FastAPI** - Modern web framework
- **Uvicorn** - ASGI server
- **SQLAlchemy** - ORM for database
- **liboqs-python** - Quantum cryptography (CRYSTALS-Kyber & Dilithium)
- **Pydantic** - Data validation
- **python-jose** - JWT authentication

### Step 2: Set Up Environment Variables
Create a `.env` file in the `backend/` directory:

\`\`\`bash
# Database (Neon PostgreSQL)
DATABASE_URL=postgresql://user:password@host/database
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# JWT Authentication
SECRET_KEY=your-super-secret-key-min-32-chars-long
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
DEBUG=false
ENV=production
LOG_LEVEL=INFO

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Quantum Crypto Mode (production or development)
QUANTUM_MODE=production
\`\`\`

**Note:** The `DATABASE_URL` from Neon is already configured in your Vercel environment variables.

### Step 3: Set Up Database
\`\`\`bash
# Initialize database tables
python -c "from backend.database_optimized import engine; from backend.models_optimized import Base; Base.metadata.create_all(bind=engine)"
\`\`\`

Or use the provided database migration script:
\`\`\`bash
python backend/scripts/init_db.py
\`\`\`

### Step 4: Run Backend Server
\`\`\`bash
# Using uvicorn directly
uvicorn backend.main_optimized:app --reload --host 0.0.0.0 --port 8000

# Or using the startup script
python backend/run.py
\`\`\`

The backend will be available at:
- **API**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs` (interactive Swagger UI)
- **ReDoc**: `http://localhost:8000/redoc` (alternative API documentation)

### Step 5: Test Backend
\`\`\`bash
# Test quantum key generation
curl http://localhost:8000/api/quantum/status

# Test user registration
curl -X POST http://localhost:8000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"secure-password"}'

# Test transaction creation
curl -X POST http://localhost:8000/api/transactions/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "receiver_name":"John Doe",
    "receiver_account":"1234567890",
    "amount":1000.00,
    "currency":"USD"
  }'
\`\`\`

---

## Frontend Setup (Next.js)

### Step 1: Install Node.js Dependencies
\`\`\`bash
npm install
# or
yarn install
\`\`\`

### Step 2: Set Up Environment Variables
Create a `.env.local` file in the root directory:

\`\`\`bash
# Backend API
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_API_TIMEOUT=30000

# Neon Database (from Vercel)
NEON_DATABASE_URL=

# Environment
NEXT_PUBLIC_ENV=development
\`\`\`

### Step 3: Run Development Server
\`\`\`bash
npm run dev
# or
yarn dev
\`\`\`

The frontend will be available at: `http://localhost:3000`

### Step 4: Build for Production
\`\`\`bash
npm run build
npm start
\`\`\`

---

## Complete Setup Flow

### Option A: Quick Start (Development)
\`\`\`bash
# Terminal 1: Backend
cd backend
pip install -r requirements.txt
uvicorn main_optimized:app --reload

# Terminal 2: Frontend
npm install
npm run dev
\`\`\`

Then access the application at `http://localhost:3000`

### Option B: Docker Setup (Recommended for Production)

Create `backend/Dockerfile`:
\`\`\`dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main_optimized:app", "--host", "0.0.0.0", "--port", "8000"]
\`\`\`

Build and run:
\`\`\`bash
docker build -t quantum-banking-backend ./backend
docker run -p 8000:8000 --env-file backend/.env quantum-banking-backend
\`\`\`

---

## API Endpoints

### Authentication
- `POST /api/users/register` - Register new user
- `POST /api/users/login` - Login user
- `POST /api/users/refresh` - Refresh authentication token
- `GET /api/users/profile` - Get user profile

### Quantum Cryptography
- `GET /api/quantum/status` - Check quantum crypto status
- `POST /api/quantum/generate-keys` - Generate quantum-safe keypair
- `POST /api/quantum/encrypt` - Encrypt data with quantum keys
- `POST /api/quantum/decrypt` - Decrypt quantum-encrypted data
- `POST /api/quantum/sign` - Sign transaction with Dilithium
- `POST /api/quantum/verify` - Verify quantum signature

### Transactions
- `POST /api/transactions/create` - Create new transaction
- `GET /api/transactions/{id}` - Get transaction details
- `GET /api/transactions/history` - Get transaction history
- `GET /api/transactions/status` - Get transaction status
- `POST /api/transactions/confirm` - Confirm transaction

### Security
- `POST /api/security/audit-log` - Get audit logs
- `GET /api/security/keys` - Manage security keys
- `POST /api/security/rotate-keys` - Rotate quantum keys

---

## Troubleshooting

### Backend Issues

**Issue**: `ModuleNotFoundError: No module named 'liboqs'`
\`\`\`bash
# Solution: Install liboqs system package
# macOS
brew install liboqs

# Ubuntu
sudo apt-get install liboqs

# Then reinstall Python packages
pip install --upgrade liboqs-python
\`\`\`

**Issue**: Database connection error
\`\`\`bash
# Check DATABASE_URL in .env
# Verify Neon connection string format: 
# postgresql://user:password@host/database
\`\`\`

**Issue**: Port 8000 already in use
\`\`\`bash
# Use different port
uvicorn backend.main_optimized:app --port 8001
\`\`\`

### Frontend Issues

**Issue**: `NEXT_PUBLIC_API_URL` not working
- Ensure backend is running on `http://localhost:8000`
- Check `.env.local` file exists
- Restart dev server after environment changes

**Issue**: CORS errors
- Add frontend URL to `ALLOWED_ORIGINS` in backend `.env`
- Restart backend server

---

## Environment Variables Reference

### Backend Variables
| Variable | Type | Description |
|----------|------|-------------|
| DATABASE_URL | string | PostgreSQL connection string |
| SECRET_KEY | string | JWT secret key (min 32 chars) |
| DEBUG | boolean | Debug mode |
| QUANTUM_MODE | string | production or development |
| LOG_LEVEL | string | INFO, DEBUG, WARNING, ERROR |

### Frontend Variables
| Variable | Type | Description |
|----------|------|-------------|
| NEXT_PUBLIC_API_URL | string | Backend API URL |
| NEXT_PUBLIC_ENV | string | development or production |

---

## Performance Optimization Tips

1. **Caching**: Backend implements Redis-like caching for frequent queries
2. **Connection Pooling**: Database connections are pooled (default: 20)
3. **Async Operations**: All I/O operations are async for better performance
4. **GZIP Compression**: API responses are compressed automatically
5. **Pagination**: Transaction history supports pagination (default: 20 items)

---

## Security Best Practices

✅ CRYSTALS-Kyber for key encapsulation  
✅ CRYSTALS-Dilithium for digital signatures  
✅ JWT tokens with expiration  
✅ Password hashing with bcrypt  
✅ CORS protection  
✅ Input validation with Pydantic  
✅ Audit logging for all transactions  
✅ Rate limiting on sensitive endpoints  

---

## Next Steps

1. Start the backend: `uvicorn backend.main_optimized:app --reload`
2. Start the frontend: `npm run dev`
3. Access the app at `http://localhost:3000`
4. Test with demo transactions
5. Deploy to Vercel (frontend) and cloud platform (backend)

---

## Support & Resources

- **Vercel Deployment**: https://vercel.com
- **FastAPI Docs**: https://fastapi.tiangolo.com
- **Next.js Docs**: https://nextjs.org
- **Quantum Cryptography**: https://liboqs.org
- **API Documentation**: Visit `http://localhost:8000/docs` when server is running
