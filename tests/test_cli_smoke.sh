#!/bin/bash

set -euo pipefail

# Fast CLI integration smoke test.
# Optional memory checking for CLI calls:
#   VALGRIND=1 bash tests/test_cli_smoke.sh

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

SERVER_BIN="./zig-out/bin/zen_server"
CLI_BIN="./zig-out/bin/zeicoin"
SERVER_IP="${ZEICOIN_SERVER:-127.0.0.2}"
WALLET_PASSWORD="${ZEICOIN_WALLET_PASSWORD:-SmokeTestPass123!}"
TEST_WALLET="smoke_$$_$RANDOM"
LOG_FILE="server_smoke_test.log"
VALGRIND="${VALGRIND:-0}"
SERVER_PID=""
SERVER_TIMEOUT_SECS="${SERVER_TIMEOUT_SECS:-180}"

if [[ "$VALGRIND" == "1" && "${SERVER_TIMEOUT_SECS}" == "180" ]]; then
    SERVER_TIMEOUT_SECS=900
fi

valgrind_prefix() {
    if [[ "$VALGRIND" == "1" ]]; then
        echo "valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes --num-callers=25 --error-exitcode=99"
    else
        echo ""
    fi
}

fail() {
    echo -e "${RED}FAIL:${NC} $1"
    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${YELLOW}Server log tail:${NC}"
        tail -n 40 "$LOG_FILE" || true
    fi
    exit 1
}

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE" 2>/dev/null || true
}
trap cleanup EXIT

run_cli() {
    local prefix
    prefix="$(valgrind_prefix)"
    if [[ -n "$prefix" ]]; then
        ZEICOIN_WALLET_PASSWORD="$WALLET_PASSWORD" ZEICOIN_SERVER="$SERVER_IP" \
            bash -lc "$prefix $CLI_BIN $*" 2>&1
    else
        ZEICOIN_WALLET_PASSWORD="$WALLET_PASSWORD" ZEICOIN_SERVER="$SERVER_IP" \
            "$CLI_BIN" "$@" 2>&1
    fi
}

expect_success() {
    local name="$1"
    local pattern="$2"
    shift 2

    echo -ne "${BLUE}Test:${NC} $name ... "
    local output
    if ! output="$(run_cli "$@")"; then
        echo -e "${RED}FAILED${NC}"
        echo "$output"
        fail "$name command failed"
    fi

    if ! echo "$output" | grep -Eq "$pattern"; then
        echo -e "${RED}FAILED${NC}"
        echo "$output"
        fail "$name output missing expected pattern: $pattern"
    fi

    echo -e "${GREEN}OK${NC}"
}

echo "CLI smoke test"
echo "VALGRIND=$VALGRIND"

[[ -x "$SERVER_BIN" ]] || fail "Missing server binary: $SERVER_BIN (run: zig build -Doptimize=Debug)"
[[ -x "$CLI_BIN" ]] || fail "Missing CLI binary: $CLI_BIN (run: zig build -Doptimize=Debug)"
if [[ "$VALGRIND" == "1" ]] && ! command -v valgrind >/dev/null 2>&1; then
    fail "VALGRIND=1 was requested, but 'valgrind' is not installed"
fi

echo "Starting server at $SERVER_IP:10802 (timeout=${SERVER_TIMEOUT_SECS}s) ..."
ZEICOIN_SERVER="$SERVER_IP" ZEICOIN_BIND_IP="$SERVER_IP" ZEICOIN_BOOTSTRAP="" \
    timeout "${SERVER_TIMEOUT_SECS}s" "$SERVER_BIN" >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

for _ in {1..20}; do
    if ZEICOIN_SERVER="$SERVER_IP" "$CLI_BIN" status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! ZEICOIN_SERVER="$SERVER_IP" "$CLI_BIN" status >/dev/null 2>&1; then
    fail "Server did not become ready"
fi

expect_success "help command" "WALLET COMMANDS" help
expect_success "status command" "Network Status|No connected peers|Ready|Cannot connect" status
expect_success "create wallet" "created successfully|already exists" wallet create "$TEST_WALLET"
expect_success "list wallets" "$TEST_WALLET" wallet list
expect_success "address command" "tzei1" address "$TEST_WALLET"
expect_success "balance command" "Balance|ZEI" balance "$TEST_WALLET"

echo -e "${GREEN}Smoke test passed.${NC}"
