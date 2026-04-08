#!/bin/bash
set -e

echo "==================================="
echo "Initializing ZeiCoin Peer Node"
echo "==================================="

# Wait for seed node to be fully ready
echo "Waiting for seed node to be available..."
sleep 5

# Extract first bootstrap multiaddr for connectivity check
# Format: /ip4/<ip>/tcp/<port>[/p2p/<peer-id>]
FIRST_BOOTSTRAP=$(echo "$ZEICOIN_BOOTSTRAP" | cut -d',' -f1)
BOOTSTRAP_HOST=$(echo "$FIRST_BOOTSTRAP" | sed -E 's|/ip4/([^/]+)/tcp/.*|\1|')
BOOTSTRAP_PORT=$(echo "$FIRST_BOOTSTRAP" | sed -E 's|.*/tcp/([0-9]+).*|\1|')

echo "Checking connectivity to $BOOTSTRAP_HOST:$BOOTSTRAP_PORT..."
max_attempts=${MAX_CONNECT_ATTEMPTS:-30}
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if nc -z "$BOOTSTRAP_HOST" "$BOOTSTRAP_PORT" 2>/dev/null; then
        echo "Successfully connected to bootstrap node!"
        break
    fi
    attempt=$((attempt + 1))
    echo "Attempt $attempt/$max_attempts: Waiting for bootstrap node..."
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo "WARNING: Could not connect to bootstrap node, but starting anyway..."
fi

echo "Starting peer node..."
echo "P2P Port: ${ZEICOIN_P2P_PORT}"
echo "Bind IP: ${ZEICOIN_BIND_IP}"
echo "Network: ${ZEICOIN_NETWORK}"
echo "Bootstrap: ${ZEICOIN_BOOTSTRAP}"

# Create miner wallet if mining is enabled
if [ "$ZEICOIN_MINE_ENABLED" = "true" ]; then
    echo "Mining: Enabled (wallet: ${ZEICOIN_MINER_WALLET})"

    DATA_DIR="zeicoin_data_testnet"
    WALLET_FILE="${DATA_DIR}/wallets/${ZEICOIN_MINER_WALLET}.wallet"
    if [ ! -f "$WALLET_FILE" ]; then
        echo "Creating miner wallet: ${ZEICOIN_MINER_WALLET}..."
        if [ -n "$ZEICOIN_WALLET_PASSWORD" ]; then
            echo -e "${ZEICOIN_WALLET_PASSWORD}\n${ZEICOIN_WALLET_PASSWORD}" | ./zig-out/bin/zeicoin wallet create "${ZEICOIN_MINER_WALLET}" || true
        fi
    fi
else
    echo "Mining: Disabled (sync only)"
fi

echo "==================================="

# Start the server — zen_server reads ZEICOIN_BOOTSTRAP from the environment directly
if [ "$ZEICOIN_MINE_ENABLED" = "true" ]; then
    exec ./zig-out/bin/zen_server --mine "$ZEICOIN_MINER_WALLET"
else
    exec ./zig-out/bin/zen_server
fi
