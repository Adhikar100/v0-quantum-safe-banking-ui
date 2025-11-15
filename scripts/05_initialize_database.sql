CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(255) UNIQUE NOT NULL,
    receiver_name VARCHAR(255) NOT NULL,
    receiver_account VARCHAR(50) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    encrypted_data TEXT,
    signature TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_transaction_id ON transactions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_receiver_account ON transactions(receiver_account);
CREATE INDEX IF NOT EXISTS idx_created_at ON transactions(created_at);

-- Insert sample data for testing
INSERT INTO transactions (transaction_id, receiver_name, receiver_account, amount, status)
VALUES 
    ('TXN-' || gen_random_uuid(), 'John Doe', '1234567890', 1000.00, 'completed'),
    ('TXN-' || gen_random_uuid(), 'Jane Smith', '0987654321', 500.00, 'completed')
ON CONFLICT (transaction_id) DO NOTHING;

SELECT * FROM transactions ORDER BY created_at DESC LIMIT 10;
