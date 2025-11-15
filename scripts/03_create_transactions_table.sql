CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  transaction_id VARCHAR(255) UNIQUE NOT NULL,
  receiver_name VARCHAR(255) NOT NULL,
  receiver_account VARCHAR(50) NOT NULL,
  amount DECIMAL(15, 2) NOT NULL,
  description TEXT,
  encrypted_data TEXT,
  signature TEXT,
  status VARCHAR(50) DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_transaction_id ON transactions(transaction_id);
CREATE INDEX idx_created_at ON transactions(created_at);
