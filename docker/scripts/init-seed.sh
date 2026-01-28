#!/bin/bash
set -e

echo "==================================="
echo "Initializing ZeiCoin Seed Node"
echo "==================================="

# Wait a moment for the file system to be ready
sleep 2

# Determine data directory based on network
DATA_DIR="zeicoin_data_testnet"

# Check if miner wallet already exists
WALLET_FILE="${DATA_DIR}/wallets/${ZEICOIN_MINER_WALLET}.wallet"

if [ ! -f "$WALLET_FILE" ]; then
    echo "Wallet doesn't exist, need to create it..."
    echo "Starting temporary server to create wallet..."

    # Start server in background
    ./zig-out/bin/zen_server &
    SERVER_PID=$!

    # Wait for server to be ready (check Client API port)
    echo "Waiting for server startup..."
    for i in {1..30}; do
        if nc -z 127.0.0.1 10802 2>/dev/null; then
            echo "Server is ready!"
            break
        fi
        sleep 1
    done

    # Give it one more second to be fully ready
    sleep 1

    # Create wallet
    echo "Creating miner wallet: ${ZEICOIN_MINER_WALLET}..."
    if [ -n "$ZEICOIN_WALLET_PASSWORD" ]; then
        echo -e "${ZEICOIN_WALLET_PASSWORD}\n${ZEICOIN_WALLET_PASSWORD}" | ./zig-out/bin/zeicoin wallet create ${ZEICOIN_MINER_WALLET}
        echo "✓ Wallet created successfully"
    else
        echo "ERROR: ZEICOIN_WALLET_PASSWORD not set"
        kill $SERVER_PID || true
        exit 1
    fi

    # Stop temporary server
    echo "Stopping temporary server..."
    kill $SERVER_PID
    wait $SERVER_PID 2>/dev/null || true
    sleep 2
else
    echo "✓ Miner wallet ${ZEICOIN_MINER_WALLET} already exists"
fi

echo "Starting seed node with mining enabled..."
echo "P2P Port: ${ZEICOIN_P2P_PORT}"
echo "Bind IP: ${ZEICOIN_BIND_IP}"
echo "Network: ${ZEICOIN_NETWORK}"
echo "Mining: Enabled (wallet: ${ZEICOIN_MINER_WALLET})"
echo "==================================="

# Start the server with mining
exec ./zig-out/bin/zen_server --mine ${ZEICOIN_MINER_WALLET}
