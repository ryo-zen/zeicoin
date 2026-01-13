#!/bin/bash
set -e

# Ensure we are running from the directory containing docker-compose.yml
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DOCKER_DIR"

# Configuration for Deep Reorg
BLOCK_HEIGHT=50
# Mining 50 blocks takes time. Assuming ~10s per block on testnet (very rough estimate depending on difficulty),
# we need at least 500s. Let's give it 600s (10 mins) to be safe for divergence.
WAIT_TIME=180 
# Syncing 50 blocks might take a bit longer than 5.
SYNC_WAIT_TIME=300

echo "🚀 Starting DEEP Reorganization Test (Height: ${BLOCK_HEIGHT})..."
echo "⚠️  This test will take approximately $((WAIT_TIME + SYNC_WAIT_TIME)) seconds."

# 1. Start Environment
echo "🧹 Cleaning up previous run..."
docker compose down -v || true

echo "📦 Starting Docker environment..."
# Ensure we use existing images without rebuilding
docker compose up -d

# 1b. Simulate Network Partition (Divergence) IMMEDIATELY
# For a deep reorg, we want them to split right from the start or very early
# so they build long separate chains.
echo "✂️  Disconnecting Miner 2 from network to force divergence..."
docker network disconnect docker_zeicoin-network zeicoin-miner-2

# 2. Divergence Phase
echo "⏳ Waiting ${WAIT_TIME}s for chains to diverge to height ~${BLOCK_HEIGHT}..."
sleep $WAIT_TIME

echo "🔍 Checking for divergence at height ${BLOCK_HEIGHT}..."

# Get raw output from Miner 1
RAW1=$(docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
# Extract hash
HASH1=$(echo "$RAW1" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 1 Hash: $HASH1"

# Get raw output from Miner 2
RAW2=$(docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
# Extract hash
HASH2=$(echo "$RAW2" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 2 Hash: $HASH2"

# Validation
if [ -z "$HASH1" ] || [ -z "$HASH2" ]; then
    echo "❌ TEST FAILED: Could not retrieve block hashes."
    echo "   Miners likely did not reach height ${BLOCK_HEIGHT} in the allotted time."
    echo "   Current Heights:"
    docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status | grep "Height"
    docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status | grep "Height"
    exit 1
fi

if [ "$HASH1" == "$HASH2" ]; then
    echo "❌ TEST FAILED: Chains did not diverge! (Hashes are identical)"
    exit 1
fi

echo "✅ SUCCESS: Chains have diverged (hashes differ)!"

# 3. Convergence Phase
echo "🔗 Reconnecting Miner 2 to network..."
docker network connect docker_zeicoin-network zeicoin-miner-2

echo "🔄 Restarting Miner 2 to force immediate reconnection..."
docker restart zeicoin-miner-2

echo "⏳ Waiting ${SYNC_WAIT_TIME}s for deep synchronization/reorganization..."
sleep $SYNC_WAIT_TIME

echo "🔍 Checking for convergence at height ${BLOCK_HEIGHT}..."

# Get hash from Miner 1 again 
RAW1_NEW=$(docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
HASH1_NEW=$(echo "$RAW1_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 1 Hash: $HASH1_NEW"

# Get hash from Miner 2 
RAW2_NEW=$(docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
HASH2_NEW=$(echo "$RAW2_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 2 Hash: $HASH2_NEW"

if [ -z "$HASH1_NEW" ] || [ -z "$HASH2_NEW" ]; then
    echo "❌ TEST FAILED: Could not retrieve block hashes during convergence check."
    exit 1
fi

if [ "$HASH1_NEW" != "$HASH2_NEW" ]; then
    echo "❌ TEST FAILED: Chains did not converge!"
    echo "   Miner 1: $HASH1_NEW"
    echo "   Miner 2: $HASH2_NEW"
    
    echo "🔍 Debugging information:"
    echo "--- Miner 1 Status ---"
    docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status
    echo "--- Miner 2 Status ---"
    docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status
    
    # Check if Miner 2 is stuck in sync
    echo "--- Miner 2 Logs (Last 50 lines) ---"
    docker logs --tail 50 zeicoin-miner-2
    exit 1
fi

echo "✅ SUCCESS: Deep reorganization complete (hashes are identical)!"
echo "🎉 DEEP REORG TEST PASSED!"

# Cleanup
echo "🧹 Cleaning up..."
docker compose down -v
