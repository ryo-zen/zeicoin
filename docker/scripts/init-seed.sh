#!/bin/bash
set -e

echo "==================================="
echo "Initializing ZeiCoin Seed Node"
echo "==================================="

# Wait a moment for the file system to be ready
sleep 2

# Check if miner wallet already exists
WALLET_FILE="/zeicoin/zeicoin_data/wallets/${ZEICOIN_MINER_WALLET}.wallet"

if [ ! -f "$WALLET_FILE" ]; then
    echo "Creating miner wallet: ${ZEICOIN_MINER_WALLET}..."

    # Create wallet with auto-password from environment
    if [ -n "$ZEICOIN_WALLET_PASSWORD" ]; then
        # Use expect-like approach with echo piping
        echo -e "${ZEICOIN_WALLET_PASSWORD}\n${ZEICOIN_WALLET_PASSWORD}" | ./zig-out/bin/zeicoin wallet create ${ZEICOIN_MINER_WALLET} || true
    else
        echo "ERROR: ZEICOIN_WALLET_PASSWORD not set"
        exit 1
    fi

    echo "Miner wallet ${ZEICOIN_MINER_WALLET} created successfully"
else
    echo "Miner wallet ${ZEICOIN_MINER_WALLET} already exists, skipping creation"
fi

echo "Starting seed node with mining enabled..."
echo "P2P Port: ${ZEICOIN_P2P_PORT}"
echo "Bind IP: ${ZEICOIN_BIND_IP}"
echo "Network: ${ZEICOIN_NETWORK}"
echo "Mining: Enabled (wallet: ${ZEICOIN_MINER_WALLET})"
echo "==================================="

# Start the server with mining
exec ./zig-out/bin/zen_server --mine ${ZEICOIN_MINER_WALLET}
