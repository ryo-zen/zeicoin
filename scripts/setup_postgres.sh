#!/bin/bash
# Setup PostgreSQL for ZeiCoin indexer

# Default to testnet if not specified
NETWORK="${1:-testnet}"
DB_NAME="zeicoin_${NETWORK}"

echo "Setting up PostgreSQL for ZeiCoin indexer..."
echo "Network: $NETWORK"
echo "Database: $DB_NAME"

# Create user with simple password
sudo -u postgres psql << EOF
-- Drop existing database and user
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS zeicoin;

-- Create user with simple password
CREATE USER zeicoin WITH PASSWORD '******';

-- Create database
CREATE DATABASE $DB_NAME OWNER zeicoin;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO zeicoin;
EOF

echo "Loading schema..."
# Load schema
PGPASSWORD=****** psql -h localhost -U zeicoin -d $DB_NAME < ../sql/schema.sql

echo "PostgreSQL setup complete!"
echo "Database: $DB_NAME"
echo "User: zeicoin"
echo "Password: ******"
echo ""
echo "Usage:"
echo "  Start indexer: ./zig-out/bin/zeicoin_indexer"
echo "  Query database: PGPASSWORD=****** psql -h localhost -U zeicoin -d $DB_NAME"