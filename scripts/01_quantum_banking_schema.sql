-- Quantum-Safe Banking Database Schema
-- PostgreSQL 12+
-- Includes comprehensive security and audit logging

-- ==================== Extensions ====================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==================== Users Table ====================
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    account_number VARCHAR(20) NOT NULL UNIQUE,
    balance NUMERIC(19, 2) NOT NULL DEFAULT 0.00,
    role VARCHAR(50) NOT NULL DEFAULT 'customer',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    kyber_public_key TEXT,
    dilithium_public_key TEXT,
    kyber_fingerprint VARCHAR(64),
    dilithium_fingerprint VARCHAR(64),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_account_number ON users(account_number);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);

-- ==================== Quantum Keys Table ====================
CREATE TABLE quantum_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    security_level VARCHAR(20) NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    rotation_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_quantum_keys_user_id ON quantum_keys(user_id);
CREATE INDEX idx_quantum_keys_is_active ON quantum_keys(is_active);
CREATE INDEX idx_quantum_keys_expires_at ON quantum_keys(expires_at);
CREATE INDEX idx_quantum_keys_algorithm ON quantum_keys(algorithm);

-- ==================== Transactions Table ====================
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount NUMERIC(19, 2) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    encrypted_data TEXT NOT NULL,
    quantum_signature TEXT NOT NULL,
    nonce TEXT,
    algorithm_used VARCHAR(255),
    risk_level VARCHAR(50),
    risk_score NUMERIC(5, 2),
    fraud_indicators TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    failed_reason VARCHAR(500),
    CONSTRAINT positive_amount CHECK (amount > 0)
);

CREATE INDEX idx_transactions_sender_id ON transactions(sender_id);
CREATE INDEX idx_transactions_receiver_id ON transactions(receiver_id);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_risk_level ON transactions(risk_level);

-- ==================== Audit Logs Table ====================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    ip_address VARCHAR(50),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- ==================== Session Table ====================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    ip_address VARCHAR(50),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- ==================== Failed Login Attempts Table ====================
CREATE TABLE failed_login_attempts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(50),
    attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_failed_login_user_id ON failed_login_attempts(user_id);
CREATE INDEX idx_failed_login_attempt_at ON failed_login_attempts(attempt_at);

-- ==================== Trusted Devices Table ====================
CREATE TABLE trusted_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    is_trusted BOOLEAN DEFAULT FALSE,
    trusted_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_device_id ON trusted_devices(device_id);

-- ==================== Key Rotation History ====================
CREATE TABLE key_rotation_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_kyber_fingerprint VARCHAR(64),
    new_kyber_fingerprint VARCHAR(64),
    old_dilithium_fingerprint VARCHAR(64),
    new_dilithium_fingerprint VARCHAR(64),
    reason VARCHAR(255),
    rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_key_rotation_history_user_id ON key_rotation_history(user_id);
CREATE INDEX idx_key_rotation_history_rotated_at ON key_rotation_history(rotated_at);

-- ==================== Transaction Templates ====================
CREATE TABLE transaction_templates (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    template_name VARCHAR(255) NOT NULL,
    receiver_id BIGINT NOT NULL REFERENCES users(id),
    default_amount NUMERIC(19, 2),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_transaction_templates_user_id ON transaction_templates(user_id);

-- ==================== Views ====================

-- View for active users with quantum key info
CREATE VIEW active_users_with_keys AS
SELECT 
    u.id,
    u.email,
    u.name,
    u.account_number,
    u.balance,
    u.status,
    u.kyber_fingerprint,
    u.dilithium_fingerprint,
    COUNT(CASE WHEN qk.is_active = TRUE AND qk.expires_at > NOW() THEN 1 END) as active_keys_count,
    MAX(qk.created_at) as latest_key_date
FROM users u
LEFT JOIN quantum_keys qk ON u.id = qk.user_id
WHERE u.status = 'active'
GROUP BY u.id, u.email, u.name, u.account_number, u.balance, u.status, u.kyber_fingerprint, u.dilithium_fingerprint;

-- View for recent transactions with fraud indicators
CREATE VIEW recent_transactions_summary AS
SELECT 
    t.id,
    t.sender_id,
    t.receiver_id,
    t.amount,
    t.status,
    t.risk_level,
    t.risk_score,
    u1.email as sender_email,
    u2.email as receiver_email,
    t.created_at
FROM transactions t
JOIN users u1 ON t.sender_id = u1.id
JOIN users u2 ON t.receiver_id = u2.id
WHERE t.created_at > NOW() - INTERVAL '30 days'
ORDER BY t.created_at DESC;

-- ==================== Functions ====================

-- Function to update user updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for users table
CREATE TRIGGER users_updated_at_trigger
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_user_updated_at();

-- Function to log user actions
CREATE OR REPLACE FUNCTION log_audit_event(
    p_user_id BIGINT,
    p_action VARCHAR,
    p_details TEXT DEFAULT NULL,
    p_ip_address VARCHAR DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
) RETURNS void AS $$
BEGIN
    INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent)
    VALUES (p_user_id, p_action, p_details, p_ip_address, p_user_agent);
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ==================== Security Settings ====================

-- Row Level Security (optional - uncomment if using Supabase)
-- ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE quantum_keys ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- ==================== Sample Data ====================

-- Insert sample users
INSERT INTO users (email, password_hash, name, account_number, balance, role, status)
VALUES 
    ('alice@quantum-bank.com', 'hashed_password_1', 'Alice Johnson', 'ACC001', 50000.00, 'customer', 'active'),
    ('bob@quantum-bank.com', 'hashed_password_2', 'Bob Smith', 'ACC002', 75000.00, 'customer', 'active'),
    ('admin@quantum-bank.com', 'hashed_password_admin', 'Admin User', 'ACC_ADMIN', 0.00, 'admin', 'active')
ON CONFLICT (email) DO NOTHING;
