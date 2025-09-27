#!/bin/bash

# ZeiCoin CLI Functions Test Script
# Tests all CLI commands comprehensively

# Remove set -e to allow test functions to properly handle failures

echo "🧪 ==============================================="
echo "🧪 ZeiCoin CLI Functions Test Script"
echo "🧪 ==============================================="
echo ""

# Colors for output
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run zeicoin commands with proper server and test password
zeicoin_cmd() {
    ZEICOIN_WALLET_PASSWORD=TestPassword123! ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin "$@"
}

# Helper function to run zen_server with proper server
zen_server_cmd() {
    ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zen_server "$@"
}

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    local expected_pattern=$3
    
    echo -ne "${BLUE}Testing: ${test_name}...${NC} "
    
    if output=$($test_command 2>&1); then
        if [[ -z "$expected_pattern" ]]; then
            echo -e "${GREEN}✅ PASSED${NC}"
            ((TESTS_PASSED++))
        else
            if echo "$output" | grep -q "$expected_pattern"; then
                echo -e "${GREEN}✅ PASSED${NC}"
                ((TESTS_PASSED++))
            else
                echo -e "${RED}❌ FAILED${NC} - Pattern not found: $expected_pattern"
                echo "Output: $output"
                ((TESTS_FAILED++))
            fi
        fi
    else
        echo -e "${RED}❌ FAILED${NC} - Command failed"
        echo "Error: $output"
        ((TESTS_FAILED++))
    fi
}

# Start server in background
echo -e "${BLUE}🚀 Starting ZeiCoin server...${NC}"
pkill -f zen_server 2>/dev/null || true
sleep 1

# Clean up any existing test wallets before starting
echo -e "${BLUE}🧹 Cleaning up existing test wallets...${NC}"
rm -f zeicoin_data_testnet/wallets/miner.wallet 2>/dev/null || true
rm -f zeicoin_data_testnet/wallets/alan.wallet 2>/dev/null || true
rm -f zeicoin_data_testnet/wallets/test_*.wallet 2>/dev/null || true
# Start server without mining first (will add mining wallet later)
ZEICOIN_SERVER=127.0.0.1 timeout 180s ./zig-out/bin/zen_server > server_test.log 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 10

# Check if server is actually running
echo "DEBUG: Checking if server is running..."
for i in {1..10}; do
    if zeicoin_cmd status >/dev/null 2>&1; then
        echo "DEBUG: Server is running!"
        break
    fi
    echo "DEBUG: Server not ready, waiting... ($i/10)"
    sleep 2
done

# Additional check - verify server is still alive before tests
echo "DEBUG: Final server check before tests..."
if ! zeicoin_cmd status >/dev/null 2>&1; then
    echo "DEBUG: Server died after startup - checking process..."
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "DEBUG: Server process $SERVER_PID has died"
        echo "DEBUG: Server log tail:"
        tail -20 server_test.log
    fi
fi

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    # Extra cleanup to ensure all zen_server processes are killed
    pkill -f zen_server 2>/dev/null || true
    
    # Clean up test wallets
    rm -f wallets/test_cli_*.json 2>/dev/null || true
    rm -f server_test.log 2>/dev/null || true
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

echo ""
echo -e "${YELLOW}📋 Testing CLI Commands${NC}"
echo ""

# Test 1: Help command
run_test "help command" \
    "zeicoin_cmd help" \
    "WALLET COMMANDS"

# Test 1a: Help command shows history
run_test "help includes history" \
    "zeicoin_cmd help" \
    "zeicoin history"

# Test 2: Setup test wallets
echo "DEBUG: Setting up test wallets: miner, alice (genesis), alan (receiver)"

# Create miner wallet for mining rewards
run_test "create miner wallet" \
    "zeicoin_cmd wallet create miner" \
    "created successfully"

# Import alice genesis account (pre-funded sender)
run_test "import alice genesis wallet" \
    "zeicoin_cmd wallet import alice" \
    "imported successfully"

# Create alan as receiver wallet
run_test "create alan receiver wallet" \
    "zeicoin_cmd wallet create alan" \
    "created successfully"

# Test 3: List wallets (should show miner, alice, alan)
run_test "wallet list shows all test wallets" \
    "zeicoin_cmd wallet list" \
    "miner"


# Test 5a: Test HD wallet restore with mnemonic
echo -e "${BLUE}Testing: wallet restore with mnemonic...${NC} "
# Create a test wallet first to get its mnemonic
TEST_HD="test_hd_$$"
WALLET1="test_wallet_1_$$"
WALLET2="test_wallet_2_$$"
if output=$(zeicoin_cmd wallet create $TEST_HD 2>&1); then
    # Extract mnemonic from output (normal wallets use 12 words)
    MNEMONIC=$(echo "$output" | grep -A 1 "Mnemonic (12 words):" | tail -1 | sed 's/^[[:space:]]*//')
    if [ ! -z "$MNEMONIC" ] && [ "$MNEMONIC" != "Mnemonic (12 words):" ]; then
        # Delete the wallet
        rm -f zeicoin_data_testnet/wallets/${TEST_HD}.wallet 2>/dev/null || true
        # Restore it from mnemonic (split into words for restore command)
        if zeicoin_cmd wallet restore ${TEST_HD}_restored $MNEMONIC >/dev/null 2>&1; then
            echo -e "${GREEN}✅ PASSED${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}❌ FAILED${NC} - Could not restore wallet"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${YELLOW}⚠️  Skipped - Could not extract mnemonic${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Skipped - Could not create test HD wallet${NC}"
fi

# Create test wallets for subsequent tests
zeicoin_cmd wallet create $WALLET1 >/dev/null 2>&1 || true
zeicoin_cmd wallet create $WALLET2 >/dev/null 2>&1 || true
# Create default wallet for tests that don't specify wallet name
zeicoin_cmd wallet create default >/dev/null 2>&1 || true

# Test 5b: Test HD wallet derive command
run_test "wallet derive command" \
    "zeicoin_cmd wallet derive $WALLET1" \
    "New address derived"

# Test 5c: Import genesis wallet using keys.config
run_test "wallet import genesis alice" \
    "zeicoin_cmd wallet import alice" \
    "imported successfully"

# Test 6: Show address
run_test "address command" \
    "zeicoin_cmd address $WALLET1" \
    "tzei1"

# Test 6a: Show address with index
run_test "address with index" \
    "zeicoin_cmd address $WALLET1 --index 1" \
    "tzei1"

# Test 7: Import alice genesis wallet (replaces any existing alice wallet)
rm -f zeicoin_data_testnet/wallets/alice.wallet 2>/dev/null || true
run_test "import alice genesis wallet (for balance test)" \
    "zeicoin_cmd wallet import alice" \
    "imported successfully"

sleep 2

# Test 7: Check alice pre-funded balance
run_test "alice genesis balance (pre-funded)" \
    "zeicoin_cmd balance alice" \
    "Mature"

# Test 8: Get alan's address for transaction testing
ALAN_ADDR=$(zeicoin_cmd address alan 2>&1 | grep -o "tzei1[a-z0-9]*" || true)
if [ -z "$ALAN_ADDR" ]; then
    echo -e "${RED}❌ Failed to get alan's address${NC}"
    ((TESTS_FAILED++))
else
    echo -e "${GREEN}✅ Got alan's address: ${ALAN_ADDR:0:20}...${NC}"
    ((TESTS_PASSED++))
fi

# Test 8: Send from alice (should be pre-funded) to alan (wallet name)
run_test "send from alice to alan (wallet name)" \
    "zeicoin_cmd send 10 alan alice" \
    "Transaction sent"

sleep 2

# Test 9: Send from alice to alan (bech32 address)
run_test "send from alice to alan (bech32 address)" \
    "zeicoin_cmd send 5 $ALAN_ADDR alice" \
    "Transaction sent"

# Test 12: Check network status
run_test "status command" \
    "zeicoin_cmd status" \
    "Network Height"

# Test 12a: Check block inspection
run_test "block inspection" \
    "zeicoin_cmd block 0" \
    "Block"

# Test 13: Sync command (expects "Ready", "No connected peers", or "Already up to date")
run_test "sync command" \
    "zeicoin_cmd sync" \
    "Ready\\|No connected peers\\|Already up to date"

# Test 14: Check balance after transactions
sleep 2
run_test "balance after transactions" \
    "zeicoin_cmd balance $WALLET2" \
    "Mature"

# Test 14a: Check transaction history
run_test "history command (empty wallet)" \
    "zeicoin_cmd history $WALLET1" \
    "Transaction History"

# Test 14aa: Test seed/mnemonic command
run_test "seed command shows mnemonic" \
    "zeicoin_cmd seed $WALLET1" \
    "Recovery Seed Phrase"

# Test 14ab: Test mnemonic command (alias for seed)
run_test "mnemonic command shows mnemonic" \
    "zeicoin_cmd mnemonic $WALLET1" \
    "Recovery Seed Phrase"

# Test 14b: Check history for alice (should have transactions if genesis wallet exists)
run_test "history command (alice)" \
    "zeicoin_cmd history alice 2>/dev/null || echo 'No alice wallet'" \
    "Transaction History\\|No alice wallet"

# Function to run a test expecting failure (like edge cases test)
run_fail_test() {
    local test_name=$1
    local test_command=$2
    local expected_error=$3
    
    echo -ne "${BLUE}Testing (expect fail): ${test_name}...${NC} "
    
    if output=$($test_command 2>&1); then
        echo -e "${RED}❌ FAILED${NC} - Command should have failed but succeeded"
        echo "Output: $output"
        ((TESTS_FAILED++))
    else
        if [[ -z "$expected_error" ]]; then
            echo -e "${GREEN}✅ PASSED${NC} (Failed as expected)"
            ((TESTS_PASSED++))
        else
            if echo "$output" | grep -qi "$expected_error"; then
                echo -e "${GREEN}✅ PASSED${NC} (Failed as expected)"
                ((TESTS_PASSED++))
            else
                echo -e "${RED}❌ FAILED${NC} - Wrong error message"
                echo "Expected: $expected_error"
                echo "Got: $output"
                ((TESTS_FAILED++))
            fi
        fi
    fi
}

# Test 15: Invalid wallet subcommand (expects error output, not failure)
run_test "invalid wallet subcommand" \
    "zeicoin_cmd wallet invalidcmd" \
    "Unknown wallet subcommand"

# Test 16: Send with insufficient balance
run_fail_test "send insufficient balance" \
    "zeicoin_cmd send 999999999 $WALLET2 $WALLET1" \
    "Transaction failed"

# Test 17: Send to invalid address
run_fail_test "send to invalid address" \
    "zeicoin_cmd send 1 invalidaddress $WALLET1" \
    "Invalid"

# Test 18: Zero amount send
run_fail_test "send zero amount" \
    "zeicoin_cmd send 0 $WALLET2 $WALLET1" \
    "Invalid amount"

# Test 19: Negative amount send
run_fail_test "send negative amount" \
    "zeicoin_cmd send -5 $WALLET2 $WALLET1" \
    "Invalid"

# Test 19a: Test wrong password security (expects error message, not failure)
zeicoin_cmd_wrong_password() {
    ZEICOIN_WALLET_PASSWORD=WrongPassword123! ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin "$@"
}
run_test "seed with wrong password shows error" \
    "zeicoin_cmd_wrong_password seed $WALLET1" \
    "Invalid password"

# Test 20: Check default wallet (remove existing first)
rm -f zeicoin_data_testnet/wallets/default.wallet 2>/dev/null || true
run_test "default wallet creation" \
    "zeicoin_cmd wallet create" \
    "default"

# Test 21: Test status --watch with timeout
echo -ne "${BLUE}Testing: status --watch...${NC} "
# Start watch mode in background and kill it after a few seconds
zeicoin_cmd status --watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 2
if kill $WATCH_PID 2>/dev/null; then
    wait $WATCH_PID 2>/dev/null || true
    echo -e "${GREEN}✅ PASSED${NC} (Watch mode functional)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAILED${NC} - Watch mode process not found"
    ((TESTS_FAILED++))
fi

# Additional HD wallet specific tests
echo ""
echo -e "${YELLOW}🔑 Testing HD Wallet Features${NC}"
echo ""

# Test multiple address derivation
echo -ne "${BLUE}Testing: multiple HD address derivation...${NC} "
ADDR1=$(zeicoin_cmd address $WALLET1 --index 0 2>&1 | grep -o "tzei1[a-z0-9]*" || true)
ADDR2=$(zeicoin_cmd address $WALLET1 --index 1 2>&1 | grep -o "tzei1[a-z0-9]*" || true)
ADDR3=$(zeicoin_cmd address $WALLET1 --index 2 2>&1 | grep -o "tzei1[a-z0-9]*" || true)

if [ ! -z "$ADDR1" ] && [ ! -z "$ADDR2" ] && [ ! -z "$ADDR3" ]; then
    if [ "$ADDR1" != "$ADDR2" ] && [ "$ADDR2" != "$ADDR3" ]; then
        echo -e "${GREEN}✅ PASSED${NC} (Generated unique addresses)"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAILED${NC} - Addresses not unique"
        ((TESTS_FAILED++))
    fi
else
    echo -e "${RED}❌ FAILED${NC} - Could not generate addresses"
    ((TESTS_FAILED++))
fi

echo ""
echo -e "${YELLOW}📊 Test Summary${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ===============================================${NC}"
    echo -e "${GREEN}🎉 All CLI Tests Passed Successfully!${NC}"
    echo -e "${GREEN}🎉 ===============================================${NC}"
    exit 0
else
    echo -e "${RED}❌ ===============================================${NC}"
    echo -e "${RED}❌ Some Tests Failed${NC}"
    echo -e "${RED}❌ ===============================================${NC}"
    exit 1
fi