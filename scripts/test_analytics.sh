#!/bin/bash

# ZeiCoin Analytics Test Script
# Tests the indexer and REST API components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 ZeiCoin Analytics Test Suite${NC}"
echo "================================"

# Configuration
DB_USER="zeicoin"
DB_PASS="******"
DB_NAME="zeicoin_testnet"  # TestNet by default
API_PORT=8080

# Function to check if process is running
check_process() {
    if pgrep -f "$1" > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to test database connection
test_db_connection() {
    echo -n "Testing database connection... "
    if PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -c "SELECT 1" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}Database connection failed. Please run ./scripts/setup_analytics.sh first${NC}"
        return 1
    fi
}

# Function to check TimescaleDB
test_timescaledb() {
    echo -n "Checking TimescaleDB extension... "
    result=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM pg_extension WHERE extname = 'timescaledb';" 2>/dev/null | tr -d ' ')
    if [ "$result" = "1" ]; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}TimescaleDB not installed${NC}"
        return 1
    fi
}

# Function to check schema
test_schema() {
    echo -n "Checking database schema... "
    tables=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('blocks', 'transactions', 'accounts', 'indexer_state');" 2>/dev/null | tr -d ' ')
    if [ "$tables" = "4" ]; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗ (found $tables/4 tables)${NC}"
        echo -e "${YELLOW}Run: psql -U $DB_USER -d $DB_NAME -f sql/timescaledb_schema.sql${NC}"
        return 1
    fi
}

# Function to check continuous aggregates
test_aggregates() {
    echo -n "Checking continuous aggregates... "
    aggregates=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM timescaledb_information.continuous_aggregates;" 2>/dev/null | tr -d ' ')
    if [ "$aggregates" -gt "0" ]; then
        echo -e "${GREEN}✓ ($aggregates aggregates)${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ (no aggregates found)${NC}"
        echo -e "${YELLOW}Run: psql -U $DB_USER -d $DB_NAME -f sql/continuous_aggregates.sql${NC}"
        return 0  # Not critical
    fi
}

# Function to test API endpoint
test_api_endpoint() {
    local endpoint=$1
    local description=$2
    
    echo -n "  Testing $description... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$API_PORT$endpoint" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        echo -e "${GREEN}✓ (200 OK)${NC}"
        return 0
    elif [ "$response" = "000" ]; then
        echo -e "${RED}✗ (connection refused)${NC}"
        return 1
    else
        echo -e "${YELLOW}⚠ (HTTP $response)${NC}"
        return 1
    fi
}

# Main test sequence
echo ""
echo -e "${BLUE}1. Database Tests${NC}"
echo "-----------------"
test_db_connection || exit 1
test_timescaledb || exit 1
test_schema || exit 1
test_aggregates

echo ""
echo -e "${BLUE}2. Component Tests${NC}"
echo "------------------"

# Check if ZeiCoin server is running
echo -n "Checking ZeiCoin server... "
if check_process "zen_server"; then
    echo -e "${GREEN}✓ (running)${NC}"
else
    echo -e "${YELLOW}⚠ (not running)${NC}"
    echo -e "${YELLOW}  Start with: ./zig-out/bin/zen_server${NC}"
fi

# Test indexer
echo -n "Testing indexer build... "
if [ -f "./zig-out/bin/zeicoin_indexer" ]; then
    echo -e "${GREEN}✓${NC}"
    
    # Get current blockchain height
    echo -n "  Getting blockchain height... "
    blocks_count=$(ls zeicoin_data_testnet/blocks/*.block 2>/dev/null | wc -l || echo "0")
    echo -e "${GREEN}$blocks_count blocks${NC}"
    
    # Get indexed height
    echo -n "  Getting indexed height... "
    indexed_height=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT value FROM indexer_state WHERE key = 'last_indexed_height';" 2>/dev/null | tr -d ' ' || echo "0")
    echo -e "${GREEN}$indexed_height blocks${NC}"
    
    if [ "$blocks_count" -gt "$indexed_height" ]; then
        echo -e "${YELLOW}  ℹ ${blocks_count - indexed_height} blocks to index${NC}"
        echo -e "${YELLOW}  Run: zig build run-indexer${NC}"
    fi
else
    echo -e "${RED}✗${NC}"
    echo -e "${RED}  Build with: zig build${NC}"
fi

# Test REST API
echo -n "Testing REST API build... "
if [ -f "./zig-out/bin/analytics_api" ]; then
    echo -e "${GREEN}✓${NC}"
    
    # Check if API is running
    echo -n "  Checking if API is running... "
    if check_process "analytics_api"; then
        echo -e "${GREEN}✓${NC}"
        
        # Test endpoints
        echo "  Testing endpoints:"
        test_api_endpoint "/health" "Health check"
        test_api_endpoint "/api/network/health" "Network health"
        test_api_endpoint "/api/transactions/volume" "Transaction volume"
    else
        echo -e "${YELLOW}⚠ (not running)${NC}"
        echo -e "${YELLOW}  Start with: zig build run-analytics${NC}"
    fi
else
    echo -e "${RED}✗${NC}"
    echo -e "${RED}  Build with: zig build${NC}"
fi

echo ""
echo -e "${BLUE}3. Data Statistics${NC}"
echo "------------------"

if test_db_connection 2>/dev/null; then
    # Get statistics
    block_count=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM blocks;" 2>/dev/null | tr -d ' ' || echo "0")
    tx_count=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM transactions;" 2>/dev/null | tr -d ' ' || echo "0")
    account_count=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT COUNT(*) FROM accounts WHERE balance > 0;" 2>/dev/null | tr -d ' ' || echo "0")
    
    echo "Indexed blocks:      $block_count"
    echo "Indexed transactions: $tx_count"
    echo "Active accounts:     $account_count"
    
    if [ "$block_count" -gt "0" ]; then
        # Get latest block info
        latest=$(PGPASSWORD=$DB_PASS psql -U $DB_USER -h localhost -d $DB_NAME -t -c "SELECT height, timestamp FROM blocks ORDER BY height DESC LIMIT 1;" 2>/dev/null || echo "N/A")
        echo "Latest block:        $latest"
    fi
fi

echo ""
echo -e "${BLUE}4. Quick Start Commands${NC}"
echo "----------------------"
echo "Start server:     ./zig-out/bin/zen_server"
echo "Run indexer:      zig build run-indexer"
echo "Run API:          zig build run-analytics"
echo "Test API:         curl http://localhost:8080/health"
echo ""

# Summary
echo -e "${BLUE}Test Summary${NC}"
echo "============"
if test_db_connection 2>/dev/null && test_timescaledb 2>/dev/null && test_schema 2>/dev/null; then
    echo -e "${GREEN}✅ Analytics infrastructure is ready!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Start the ZeiCoin server if not running"
    echo "2. Run the indexer to sync blockchain data"  
    echo "3. Start the REST API to serve analytics"
else
    echo -e "${YELLOW}⚠️ Some components need setup${NC}"
    echo ""
    echo "Run ./scripts/setup_analytics.sh to complete setup"
fi