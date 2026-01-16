#!/bin/bash
set -e

# Ensure we are running from the directory containing docker-compose.yml
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DOCKER_DIR"

# Configuration
BLOCK_HEIGHT=5
WAIT_TIME=60
SYNC_WAIT_TIME=45

echo "🚀 Starting Reorganization Test..."

# 1. Start Environment
echo "🧹 Cleaning up previous run..."
docker compose down -v || true

echo "📦 Starting Docker environment..."
docker compose up -d

# 1b. Simulate Network Partition (Divergence)
echo "✂️  Disconnecting Miner 2 from network to force divergence..."
docker network disconnect docker_zeicoin-network zeicoin-miner-2

# 2. Divergence Phase
echo "⏳ Waiting ${WAIT_TIME}s for chains to diverge..."
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

if [ -z "$HASH1" ] || [ -z "$HASH2" ]; then
    echo "❌ TEST FAILED: Could not retrieve block hashes."
    echo "   Ensure miners have reached height ${BLOCK_HEIGHT}."
    echo "   Miner 1 Raw Output:"
    echo "$RAW1"
    echo "   Miner 2 Raw Output:"
    echo "$RAW2"
    
    docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status
    docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status
    exit 1
fi

if [ "$HASH1" == "$HASH2" ]; then
    echo "❌ TEST FAILED: Chains did not diverge! (Hashes are identical)"
    echo "   Ensure miners are isolated and mining."
    docker compose logs | tail -n 20
    exit 1
fi

echo "✅ SUCCESS: Chains have diverged (hashes differ)!"

# 3. Convergence Phase
echo "🔗 Reconnecting Miner 2 to network..."
docker network connect docker_zeicoin-network zeicoin-miner-2

echo "🔄 Restarting Miner 2 to force immediate reconnection..."
docker restart zeicoin-miner-2

# Increase wait time for restart + sync
SYNC_WAIT_TIME=60

echo "⏳ Waiting ${SYNC_WAIT_TIME}s for synchronization/reorganization..."
sleep $SYNC_WAIT_TIME

echo "🔍 Checking for convergence at height ${BLOCK_HEIGHT}..."

# Get hash from Miner 1 again (should be same or advanced)
RAW1_NEW=$(docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
HASH1_NEW=$(echo "$RAW1_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 1 Hash: $HASH1_NEW"

# Get hash from Miner 2 (should now match Miner 1)
RAW2_NEW=$(docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
HASH2_NEW=$(echo "$RAW2_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner 2 Hash: $HASH2_NEW"

if [ -z "$HASH1_NEW" ] || [ -z "$HASH2_NEW" ]; then
    echo "❌ TEST FAILED: Could not retrieve block hashes during convergence check."
    echo "   Miner 1 Raw Output:"
    echo "$RAW1_NEW"
    echo "   Miner 2 Raw Output:"
    echo "$RAW2_NEW"
    exit 1
fi

if [ "$HASH1_NEW" != "$HASH2_NEW" ]; then
    echo "❌ TEST FAILED: Chains did not converge!"
    echo "   Miner 1: $HASH1_NEW"
    echo "   Miner 2: $HASH2_NEW"
    echo "   Reorganization failed or sync incomplete."
    
    echo "🔍 Debugging information:"
    echo "--- Miner 1 Status ---"
    docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status
    echo "--- Miner 2 Status ---"
    docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status
    
    echo "--- Miner 2 Logs (Last 100 lines) ---"
    docker logs --tail 100 zeicoin-miner-2
    
    echo "--- Miner 1 Logs (Last 100 lines) ---"
    docker logs --tail 100 zeicoin-miner-1
    exit 1
fi

echo "✅ SUCCESS: Chains have converged (hashes are identical)!"
echo "🎉 REORGANIZATION TEST PASSED!"

# Cleanup
echo "🧹 Cleaning up..."
docker compose down -v