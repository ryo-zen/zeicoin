#!/bin/bash

# ZeiCoin Analytics Setup Script
# Sets up PostgreSQL with TimescaleDB for blockchain analytics

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 ZeiCoin Analytics Setup${NC}"
echo "================================"

# Configuration
DB_USER="zeicoin"
DB_PASS="******"
DB_NAME_TESTNET="zeicoin_testnet"
DB_NAME_MAINNET="zeicoin_mainnet"

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo -e "${RED}❌ PostgreSQL is not installed${NC}"
    echo "Please install PostgreSQL first:"
    echo "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
    echo "  MacOS: brew install postgresql"
    exit 1
fi

# Check if running as postgres user or with sudo
if [ "$EUID" -ne 0 ] && [ "$USER" != "postgres" ]; then 
    echo -e "${YELLOW}⚠️  This script needs to run with sudo or as postgres user${NC}"
    echo "Retrying with sudo..."
    exec sudo "$0" "$@"
fi

echo -e "${GREEN}✅ PostgreSQL found${NC}"

# Function to execute SQL as postgres user
exec_sql() {
    sudo -u postgres psql -c "$1" 2>/dev/null || true
}

exec_sql_db() {
    local db=$1
    local sql=$2
    sudo -u postgres psql -d "$db" -c "$sql" 2>/dev/null || true
}

# Create user if not exists
echo -n "Creating database user '$DB_USER'... "
exec_sql "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
echo -e "${GREEN}✓${NC}"

# Create databases
for DB_NAME in $DB_NAME_TESTNET $DB_NAME_MAINNET; do
    echo -n "Creating database '$DB_NAME'... "
    exec_sql "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    echo -e "${GREEN}✓${NC}"
    
    # Grant privileges
    echo -n "Granting privileges on '$DB_NAME'... "
    exec_sql "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    echo -e "${GREEN}✓${NC}"
    
    # Enable TimescaleDB extension
    echo -n "Enabling TimescaleDB on '$DB_NAME'... "
    exec_sql_db "$DB_NAME" "CREATE EXTENSION IF NOT EXISTS timescaledb;"
    echo -e "${GREEN}✓${NC}"
done

# Apply schema for each database
for DB_NAME in $DB_NAME_TESTNET $DB_NAME_MAINNET; do
    echo ""
    echo -e "${YELLOW}Setting up schema for $DB_NAME...${NC}"
    
    # Apply main schema
    if [ -f "sql/timescaledb_schema.sql" ]; then
        echo -n "  Applying TimescaleDB schema... "
        PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -f sql/timescaledb_schema.sql > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}  Schema file not found: sql/timescaledb_schema.sql${NC}"
    fi
    
    # Apply continuous aggregates
    if [ -f "sql/continuous_aggregates.sql" ]; then
        echo -n "  Creating continuous aggregates... "
        PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -f sql/continuous_aggregates.sql > /dev/null 2>&1
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}  Aggregates file not found: sql/continuous_aggregates.sql${NC}"
    fi
done

echo ""
echo -e "${GREEN}✅ Database setup complete!${NC}"
echo ""
echo "Connection details:"
echo "  Host: localhost"
echo "  Port: 5432"
echo "  User: $DB_USER"
echo "  Pass: $DB_PASS"
echo "  TestNet DB: $DB_NAME_TESTNET"
echo "  MainNet DB: $DB_NAME_MAINNET"
echo ""
echo "To test the connection:"
echo "  PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME_TESTNET"
echo ""
echo "To run the indexer:"
echo "  zig build run-indexer"
echo ""
echo "To run the analytics API:"
echo "  zig build run-analytics"