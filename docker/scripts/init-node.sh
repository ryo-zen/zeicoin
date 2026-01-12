#!/bin/bash
set -e

echo "==================================="
echo "Initializing ZeiCoin Peer Node"
echo "==================================="

# Wait for seed node to be fully ready
echo "Waiting for seed node to be available..."
sleep 5

# Extract first bootstrap node for connectivity check
FIRST_BOOTSTRAP=$(echo $ZEICOIN_BOOTSTRAP | cut -d',' -f1)
BOOTSTRAP_HOST=$(echo $FIRST_BOOTSTRAP | cut -d':' -f1)
BOOTSTRAP_PORT=$(echo $FIRST_BOOTSTRAP | cut -d':' -f2)

echo "Checking connectivity to $BOOTSTRAP_HOST:$BOOTSTRAP_PORT..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if nc -z $BOOTSTRAP_HOST $BOOTSTRAP_PORT 2>/dev/null; then
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

# Check if mining is enabled
if [ "$ZEICOIN_MINE_ENABLED" = "true" ]; then
    echo "Mining: Enabled (wallet: ${ZEICOIN_MINER_WALLET})"

    # Create miner wallet if it doesn't exist
    WALLET_FILE="/zeicoin/zeicoin_data/wallets/${ZEICOIN_MINER_WALLET}.wallet"
    if [ ! -f "$WALLET_FILE" ]; then
        echo "Creating miner wallet: ${ZEICOIN_MINER_WALLET}..."
        if [ -n "$ZEICOIN_WALLET_PASSWORD" ]; then
            echo -e "${ZEICOIN_WALLET_PASSWORD}\n${ZEICOIN_WALLET_PASSWORD}" | ./zig-out/bin/zeicoin wallet create ${ZEICOIN_MINER_WALLET} || true
        fi
    fi
else
    echo "Mining: Disabled (sync only)"
fi

echo "==================================="

# Resolve hostnames to IPs in bootstrap list
# ZeiCoin only accepts IP addresses, not hostnames
BOOTSTRAP_IPS=""
IFS=',' read -ra NODES <<< "$ZEICOIN_BOOTSTRAP"
for node in "${NODES[@]}"; do
    host=$(echo $node | cut -d':' -f1)
    port=$(echo $node | cut -d':' -f2)

    # Resolve hostname to IP
    ip=$(getent hosts $host | awk '{ print $1 }' | head -1)

    if [ -n "$ip" ]; then
        if [ -z "$BOOTSTRAP_IPS" ]; then
            BOOTSTRAP_IPS="$ip:$port"
        else
            BOOTSTRAP_IPS="$BOOTSTRAP_IPS,$ip:$port"
        fi
        echo "Resolved $host to $ip"
    else
        echo "WARNING: Could not resolve $host"
    fi
done

echo "Bootstrap IPs: $BOOTSTRAP_IPS"

# Start the server with resolved IPs and optional mining
if [ "$ZEICOIN_MINE_ENABLED" = "true" ]; then
    if [ -n "$BOOTSTRAP_IPS" ]; then
        exec ./zig-out/bin/zen_server --bootstrap "$BOOTSTRAP_IPS" --mine "$ZEICOIN_MINER_WALLET"
    else
        exec ./zig-out/bin/zen_server --mine "$ZEICOIN_MINER_WALLET"
    fi
else
    if [ -n "$BOOTSTRAP_IPS" ]; then
        exec ./zig-out/bin/zen_server --bootstrap "$BOOTSTRAP_IPS"
    else
        exec ./zig-out/bin/zen_server
    fi
fi
