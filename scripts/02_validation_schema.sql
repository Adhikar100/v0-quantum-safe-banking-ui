-- Create tables for receiver and account validation
CREATE TABLE IF NOT EXISTS receivers (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  account_number VARCHAR(50) UNIQUE NOT NULL,
  mobile_number VARCHAR(20) UNIQUE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
  id SERIAL PRIMARY KEY,
  account_name VARCHAR(255) NOT NULL,
  account_number VARCHAR(50) NOT NULL,
  bank_name VARCHAR(100) NOT NULL,
  available_balance DECIMAL(15, 2) NOT NULL DEFAULT 50000,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(account_number, bank_name)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT NOW(),
  action VARCHAR(100) NOT NULL,
  sender_id INTEGER,
  receiver_id INTEGER,
  account_id INTEGER,
  amount DECIMAL(15, 2),
  status VARCHAR(50) NOT NULL,
  FOREIGN KEY (receiver_id) REFERENCES receivers(id),
  FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- Add indexes for performance
CREATE INDEX idx_receivers_account ON receivers(account_number);
CREATE INDEX idx_receivers_mobile ON receivers(mobile_number);
CREATE INDEX idx_accounts_account_number ON accounts(account_number);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);

-- Insert demo data for testing
INSERT INTO receivers (name, account_number, mobile_number) VALUES
  ('Adhikar Chaudhary', '1234567890', '+977-9800000001'),
  ('Priya Sharma', '1234567891', '+977-9800000002'),
  ('Raj Patel', '1234567892', '+977-9800000003')
ON CONFLICT DO NOTHING;

INSERT INTO accounts (account_name, account_number, bank_name, available_balance) VALUES
  ('Adhikar Chaudhary', '1234567890', 'national', 50000),
  ('Priya Sharma', '1234567891', 'himalayan', 75000),
  ('Raj Patel', '1234567892', 'nabil', 100000)
ON CONFLICT DO NOTHING;
