-- Drop existing table if needed (uncomment to reset)
-- DROP TABLE IF EXISTS transactions;

-- Create transactions table for quantum-safe banking
CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  transaction_id VARCHAR(255) UNIQUE NOT NULL,
  receiver_name VARCHAR(255) NOT NULL,
  receiver_account VARCHAR(50) NOT NULL,
  amount DECIMAL(15, 2) NOT NULL,
  description TEXT,
  encrypted_data TEXT NOT NULL,
  signature TEXT NOT NULL,
  status VARCHAR(50) DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_transaction_id ON transactions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_receiver_account ON transactions(receiver_account);
CREATE INDEX IF NOT EXISTS idx_status ON transactions(status);

-- Verify the table was created
SELECT 'Transactions table created successfully!' as message;
SELECT COUNT(*) as existing_transactions FROM transactions;
