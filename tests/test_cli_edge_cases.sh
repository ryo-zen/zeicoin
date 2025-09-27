#!/bin/bash

# ZeiCoin CLI Edge Cases Test Script
# Comprehensive test of all CLI commands against edge cases

echo "🧪 ==============================================="
echo "🧪 ZeiCoin CLI Edge Cases Test Script"
echo "🧪 Testing ALL Commands Against Edge Cases"
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
    ZEICOIN_WALLET_PASSWORD=EdgeTestPass123! ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin "$@"
}

# Function to run a test expecting an error message (but exit code 0)
run_error_test() {
    local test_name=$1
    local test_command=$2
    local expected_error=$3
    
    echo -ne "${BLUE}Testing (expect error): ${test_name}...${NC} "
    
    output=$($test_command 2>&1)
    
    # Check if output contains expected error pattern
    if echo "$output" | grep -qi "$expected_error"; then
        # Also check that it starts with an error indicator
        if echo "$output" | grep -q "^❌"; then
            echo -e "${GREEN}✅ PASSED${NC} (Error shown correctly)"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}❌ FAILED${NC} - Missing error indicator"
            echo "Output: $output"
            ((TESTS_FAILED++))
        fi
    else
        echo -e "${RED}❌ FAILED${NC} - Wrong or missing error message"
        echo "Expected pattern: $expected_error"
        echo "Got: $output"
        ((TESTS_FAILED++))
    fi
}

# Keep the original for commands that truly fail with exit codes
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
                echo -e "${GREEN}✅ PASSED${NC} (Failed with expected error)"
                ((TESTS_PASSED++))
            else
                echo -e "${RED}❌ FAILED${NC} - Wrong error message"
                echo "Expected pattern: $expected_error"
                echo "Got: $output"
                ((TESTS_FAILED++))
            fi
        fi
    fi
}

# Function to run a test expecting success
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

# Function to cleanup
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    pkill -f zen_server 2>/dev/null || true
    
    # Clean up all test wallets
    rm -f zeicoin_data_testnet/wallets/edge_*.wallet 2>/dev/null || true
    rm -f zeicoin_data_testnet/wallets/test_*.wallet 2>/dev/null || true
    rm -f zeicoin_data_testnet/wallets/*.wallet 2>/dev/null || true
    rm -f server_edge_test.log 2>/dev/null || true
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Clean existing test wallets before starting
echo -e "${BLUE}🧹 Pre-test cleanup...${NC}"
rm -f zeicoin_data_testnet/wallets/edge_*.wallet 2>/dev/null || true
rm -f zeicoin_data_testnet/wallets/test_*.wallet 2>/dev/null || true

# Start server in background
echo -e "${BLUE}🚀 Starting ZeiCoin server...${NC}"
pkill -f zen_server 2>/dev/null || true
sleep 1
ZEICOIN_SERVER=127.0.0.1 timeout 300s ./zig-out/bin/zen_server > server_edge_test.log 2>&1 &
SERVER_PID=$!

# Give server time to start
echo -e "${BLUE}⏳ Waiting for server to start...${NC}"
sleep 5

# Check if server is running
for i in {1..10}; do
    if zeicoin_cmd status >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is running!${NC}"
        break
    fi
    if [ $i -eq 10 ]; then
        echo -e "${RED}❌ Server failed to start${NC}"
        exit 1
    fi
    sleep 1
done

echo ""
echo -e "${YELLOW}=== WALLET COMMANDS EDGE CASES ===${NC}"
echo ""

# Test wallet create edge cases
run_error_test "wallet create - empty name" \
    "zeicoin_cmd wallet create ''" \
    "must start with a letter"

run_error_test "wallet create - spaces in name" \
    "zeicoin_cmd wallet create 'wallet with spaces'" \
    "must start with a letter"

run_error_test "wallet create - special chars (@#$)" \
    "zeicoin_cmd wallet create 'wallet@#\$'" \
    "must start with a letter"

run_error_test "wallet create - starts with dash" \
    "zeicoin_cmd wallet create '-wallet'" \
    "must start with a letter"

run_error_test "wallet create - starts with number" \
    "zeicoin_cmd wallet create '123wallet'" \
    "must start with a letter"

run_test "wallet create - valid name" \
    "zeicoin_cmd wallet create edge_wallet_1" \
    "created successfully"

run_error_test "wallet create - duplicate name" \
    "zeicoin_cmd wallet create edge_wallet_1" \
    "already exists"

run_test "wallet create - max length (63 chars)" \
    "zeicoin_cmd wallet create this_is_exactly_63_characters_long_wallet_name_abcdefghijklmno" \
    "created successfully"

run_error_test "wallet create - too long (>64 chars)" \
    "zeicoin_cmd wallet create this_is_a_very_long_wallet_name_that_exceeds_64_characters_limit_and_should_fail" \
    "too long"

# Test wallet list edge cases
run_test "wallet list - with wallets" \
    "zeicoin_cmd wallet list" \
    "edge_wallet_1"

# Test wallet restore edge cases
run_error_test "wallet restore - empty mnemonic" \
    "zeicoin_cmd wallet restore test_restore" \
    "Invalid usage\|missing"

run_error_test "wallet restore - special chars in name" \
    "zeicoin_cmd wallet restore '@#\$%wallet' word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12" \
    "must start with a letter"

run_error_test "wallet restore - invalid word count (11 words)" \
    "zeicoin_cmd wallet restore test_restore word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11" \
    "wrong word count"

run_error_test "wallet restore - invalid words" \
    "zeicoin_cmd wallet restore test_restore xxx yyy zzz aaa bbb ccc ddd eee fff ggg hhh iii" \
    "Invalid mnemonic"

run_error_test "wallet restore - duplicate words" \
    "zeicoin_cmd wallet restore test_restore abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon" \
    "Invalid mnemonic"

# Test wallet derive edge cases
run_error_test "wallet derive - non-existent wallet" \
    "zeicoin_cmd wallet derive nonexistent_wallet_xyz" \
    "not found"

run_test "wallet derive - valid wallet" \
    "zeicoin_cmd wallet derive edge_wallet_1" \
    "New address derived"

run_test "wallet derive - with index 0" \
    "zeicoin_cmd wallet derive edge_wallet_1 0" \
    "Address #0"

run_test "wallet derive - with index 100" \
    "zeicoin_cmd wallet derive edge_wallet_1 100" \
    "Address #100"

run_error_test "wallet derive - negative index" \
    "zeicoin_cmd wallet derive edge_wallet_1 -1" \
    "Invalid"

run_error_test "wallet derive - invalid index (text)" \
    "zeicoin_cmd wallet derive edge_wallet_1 abc" \
    "Invalid"

# Test wallet import edge cases
run_test "wallet import - alice genesis" \
    "zeicoin_cmd wallet import alice" \
    "imported successfully"

run_error_test "wallet import - invalid genesis name" \
    "zeicoin_cmd wallet import invalid_genesis" \
    "not a valid genesis"

run_error_test "wallet import - empty genesis name" \
    "zeicoin_cmd wallet import ''" \
    "not a valid genesis"

# Test seed/mnemonic edge cases
run_error_test "seed - non-existent wallet" \
    "zeicoin_cmd seed nonexistent_wallet_xyz" \
    "not found"

run_test "seed - valid wallet" \
    "zeicoin_cmd seed edge_wallet_1" \
    "Recovery Seed Phrase"

run_test "mnemonic - valid wallet" \
    "zeicoin_cmd mnemonic edge_wallet_1" \
    "Recovery Seed Phrase"

# Wrong password test
zeicoin_cmd_wrong() {
    ZEICOIN_WALLET_PASSWORD=WrongPassword123! ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin "$@"
}

run_error_test "seed - wrong password" \
    "zeicoin_cmd_wrong seed edge_wallet_1" \
    "Invalid password\\|Authentication failed"

echo ""
echo -e "${YELLOW}=== TRANSACTION COMMANDS EDGE CASES ===${NC}"
echo ""

# Test balance edge cases
run_error_test "balance - non-existent wallet" \
    "zeicoin_cmd balance nonexistent_wallet_xyz" \
    "not found"

run_test "balance - alice genesis" \
    "zeicoin_cmd balance alice" \
    "Mature"

run_error_test "balance - no wallet specified (default)" \
    "zeicoin_cmd balance" \
    "Wallet 'default' not found"

# Create a second wallet for transaction tests
run_test "create recipient wallet" \
    "zeicoin_cmd wallet create edge_wallet_2" \
    "created successfully"

# Get address for testing
ADDR1=$(zeicoin_cmd address edge_wallet_1 2>&1 | grep -o "tzei1[a-z0-9]*" || echo "")
ADDR2=$(zeicoin_cmd address edge_wallet_2 2>&1 | grep -o "tzei1[a-z0-9]*" || echo "")

# Test send edge cases
run_error_test "send - zero amount" \
    "zeicoin_cmd send 0 edge_wallet_2 alice" \
    "Invalid amount"

run_error_test "send - negative amount" \
    "zeicoin_cmd send -10 edge_wallet_2 alice" \
    "Invalid"

run_test "send - minimum amount (1 satoshi)" \
    "zeicoin_cmd send 0.00000001 edge_wallet_2 alice" \
    "Transaction sent"

run_test "send - decimal amount" \
    "zeicoin_cmd send 0.123456 edge_wallet_2 alice" \
    "Transaction sent"

run_error_test "send - too many decimals (>8)" \
    "zeicoin_cmd send 0.000000001 edge_wallet_2 alice" \
    "Invalid"

run_error_test "send - overflow amount" \
    "zeicoin_cmd send 99999999999999999 edge_wallet_2 alice" \
    "Invalid amount\\|Insufficient"

run_error_test "send - invalid recipient address" \
    "zeicoin_cmd send 1 invalidaddress alice" \
    "Invalid"

run_error_test "send - malformed bech32" \
    "zeicoin_cmd send 1 tzei1notvalidaddress alice" \
    "Invalid bech32"

run_error_test "send - wrong network prefix" \
    "zeicoin_cmd send 1 zei1qqqqqqqqqqqqqqqq alice" \
    "Invalid\\|Wrong network"

run_error_test "send - non-existent sender" \
    "zeicoin_cmd send 1 edge_wallet_2 nonexistent_sender" \
    "not found"

run_error_test "send - to self (same wallet)" \
    "zeicoin_cmd send 1 alice alice" \
    "Transaction failed"

if [ ! -z "$ADDR1" ]; then
    run_test "send - to valid bech32 address" \
        "zeicoin_cmd send 0.1 $ADDR1 alice" \
        "Transaction sent"
fi

# Test history edge cases
run_error_test "history - non-existent wallet" \
    "zeicoin_cmd history nonexistent_wallet_xyz" \
    "not found"

run_test "history - valid wallet" \
    "zeicoin_cmd history alice" \
    "Transaction History"

echo ""
echo -e "${YELLOW}=== NETWORK COMMANDS EDGE CASES ===${NC}"
echo ""

# Test status edge cases
run_test "status - basic" \
    "zeicoin_cmd status" \
    "Network Height"

# Test status --watch (run briefly then kill)
echo -ne "${BLUE}Testing: status --watch (brief run)...${NC} "
zeicoin_cmd status --watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 2
if kill $WATCH_PID 2>/dev/null; then
    wait $WATCH_PID 2>/dev/null || true
    echo -e "${GREEN}✅ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAILED${NC}"
    ((TESTS_FAILED++))
fi

# Test sync edge cases
run_test "sync - manual trigger" \
    "zeicoin_cmd sync" \
    "Sync\\|Ready\\|No connected peers"

# Test block edge cases
run_test "block - genesis (0)" \
    "zeicoin_cmd block 0" \
    "Block"

run_error_test "block - negative height" \
    "zeicoin_cmd block -1" \
    "Invalid"

run_error_test "block - non-existent height (9999999)" \
    "zeicoin_cmd block 9999999" \
    "not found\\|doesn't exist"

run_error_test "block - invalid input (text)" \
    "zeicoin_cmd block abc" \
    "Invalid"

run_error_test "block - special characters (!@#$%)" \
    "zeicoin_cmd block '!@#\$%^&*()'" \
    "Invalid block height"

run_error_test "block - brackets and braces" \
    "zeicoin_cmd block '{}[]()'" \
    "Invalid block height"

run_error_test "block - SQL injection attempt" \
    "zeicoin_cmd block '1; DROP TABLE blocks;'" \
    "Invalid block height"

run_error_test "block - command injection attempt" \
    "zeicoin_cmd block '\$(rm -rf /)'" \
    "Invalid block height"

run_error_test "block - unicode characters" \
    "zeicoin_cmd block '块高度'" \
    "Invalid block height"

run_error_test "block - emoji" \
    "zeicoin_cmd block '🔢'" \
    "Invalid block height"

# Test address edge cases
run_error_test "address - non-existent wallet" \
    "zeicoin_cmd address nonexistent_wallet_xyz" \
    "not found"

run_test "address - valid wallet" \
    "zeicoin_cmd address edge_wallet_1" \
    "tzei1"

run_test "address - with index 0" \
    "zeicoin_cmd address edge_wallet_1 --index 0" \
    "tzei1"

run_test "address - with index 10" \
    "zeicoin_cmd address edge_wallet_1 --index 10" \
    "tzei1"

run_test "address - negative index" \
    "zeicoin_cmd address edge_wallet_1 --index -1" \
    "Invalid index"

run_test "address - huge index (allowed)" \
    "zeicoin_cmd address edge_wallet_1 --index 999999999" \
    "Address #999999999"

echo ""
echo -e "${YELLOW}=== SECURITY & INJECTION TESTS ===${NC}"
echo ""

# SQL Injection attempts on various commands
run_error_test "SQL injection - balance" \
    "zeicoin_cmd balance \"'; DROP TABLE wallets; --\"" \
    "not found"

run_error_test "SQL injection - send amount" \
    "zeicoin_cmd send \"1 OR 1=1\" alice bob" \
    "Invalid amount"

run_error_test "SQL injection - history" \
    "zeicoin_cmd history \"' UNION SELECT * FROM keys --\"" \
    "not found"

# Command injection attempts
run_error_test "command injection - balance backticks" \
    "zeicoin_cmd balance \"\`rm -rf /\`\"" \
    "not found"

run_error_test "command injection - send recipient" \
    "zeicoin_cmd send 1 \"\$(cat /etc/passwd)\" alice" \
    "Invalid"

run_error_test "command injection - block height" \
    "zeicoin_cmd block \"\`whoami\`\"" \
    "Invalid block height"

# Path traversal attempts
run_error_test "path traversal - wallet name" \
    "zeicoin_cmd wallet create ../../etc/passwd" \
    "must start with a letter"

run_error_test "path traversal - balance" \
    "zeicoin_cmd balance ../../../root/.ssh/id_rsa" \
    "not found"

# Buffer overflow attempts
run_error_test "buffer overflow - extremely long wallet name" \
    "zeicoin_cmd wallet create AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "too long"

run_error_test "buffer overflow - huge block number" \
    "zeicoin_cmd block 99999999999999999999999999999999999999999999" \
    "Invalid"

# Format string attacks
run_error_test "format string - wallet name" \
    "zeicoin_cmd wallet create '%s%s%s%s%s%s%s'" \
    "must start with a letter"

run_error_test "format string - send amount" \
    "zeicoin_cmd send '%x%x%x%x' alice bob" \
    "Invalid amount"

# Null byte injection (dollar sign test for special char)
run_error_test "null byte/special - wallet name" \
    "zeicoin_cmd wallet create 'wallet\$00txt'" \
    "must start with a letter"

# LDAP injection attempts
run_error_test "LDAP injection - wallet import" \
    "zeicoin_cmd wallet import '*)(&(uid=admin)'" \
    "not a valid genesis"

# XML injection attempts
run_error_test "XML injection - send" \
    "zeicoin_cmd send '<amount>1000000</amount>' alice bob" \
    "Invalid amount"

# JSON injection attempts
run_error_test "JSON injection - wallet create" \
    "zeicoin_cmd wallet create '{\"admin\":true}'" \
    "must start with a letter"

echo ""
echo -e "${YELLOW}=== SPECIAL EDGE CASES ===${NC}"
echo ""

# Test help command
run_test "help command" \
    "zeicoin_cmd help" \
    "WALLET COMMANDS"

# Test invalid commands
run_error_test "invalid command" \
    "zeicoin_cmd invalidcommand" \
    "Unknown command"

run_test "no command (shows help)" \
    "zeicoin_cmd" \
    "WALLET COMMANDS"

# Test environment variable override
echo -ne "${BLUE}Testing: wrong server IP override...${NC} "
output=$(ZEICOIN_SERVER=192.168.255.255 ./zig-out/bin/zeicoin status 2>&1)
if echo "$output" | grep -q "Connection timeout\\|Cannot connect\\|refused"; then
    echo -e "${GREEN}✅ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAILED${NC} - Wrong error"
    echo "Output: $output"
    ((TESTS_FAILED++))
fi

# Test rapid sequential operations
echo -ne "${BLUE}Testing: rapid wallet creation (5 wallets)...${NC} "
success=true
for i in {1..5}; do
    if ! zeicoin_cmd wallet create test_rapid_$i >/dev/null 2>&1; then
        success=false
        break
    fi
done
if $success; then
    echo -e "${GREEN}✅ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAILED${NC}"
    ((TESTS_FAILED++))
fi

# Test Unicode and special characters
run_error_test "unicode in wallet name" \
    "zeicoin_cmd wallet create 钱包" \
    "must start with a letter"

run_error_test "emoji in amount" \
    "zeicoin_cmd send 💰 edge_wallet_2 alice" \
    "Invalid"

run_error_test "special chars in amount" \
    "zeicoin_cmd send \$100 edge_wallet_2 alice" \
    "Invalid"

# Test command injection attempts (security)
run_error_test "command injection in wallet name" \
    "zeicoin_cmd wallet create 'test; rm -rf /'" \
    "must start with a letter"

run_error_test "command injection in amount" \
    "zeicoin_cmd send '1; echo hacked' edge_wallet_2 alice" \
    "Invalid"

echo ""
echo -e "${YELLOW}📊 Edge Case Test Summary${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ===============================================${NC}"
    echo -e "${GREEN}🎉 All Edge Case Tests Passed Successfully!${NC}"
    echo -e "${GREEN}🎉 ===============================================${NC}"
    exit 0
else
    echo -e "${RED}❌ ===============================================${NC}"
    echo -e "${RED}❌ Some Edge Case Tests Failed${NC}"
    echo -e "${RED}❌ ===============================================${NC}"
    exit 1
fi