#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

set -e

# -------------------------------------------------
# Configuration
# -------------------------------------------------
BLOCK_HEIGHT=3               # Height we will compare
WAIT_TIME=100                # Time to let the two chains diverge
SYNC_WAIT_TIME=10            # Time after reconnection before checking (we poll mostly)
MAX_RETRIES=12               # How many hash‑checks we perform (10 s apart)
MAX_SYNC_WAIT=300            # Max wait for sync (5 min)

echo "🚀 Starting Reorganization Test..."

# 1️⃣ Clean and start the Docker compose stack
echo "🧹 Cleaning up previous run..."
docker compose down -v || true

echo "📦 Starting Docker environment..."
docker compose up -d

# 2️⃣ Disconnect miner‑2 → force divergence
echo "✂️  Disconnecting Miner‑2 from network to force divergence..."
docker network disconnect docker_zeicoin-network zeicoin-miner-2

echo "⏳ Waiting ${WAIT_TIME}s for chains to diverge..."
sleep $WAIT_TIME

# 3️⃣ Check that the two chains really differ
echo "🔍 Checking for divergence at height ${BLOCK_HEIGHT}..."
RAW1=$(docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)
RAW2=$(docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1)

HASH1=$(echo "$RAW1" | grep '"hash":' | awk -F'"' '{print $4}')
HASH2=$(echo "$RAW2" | grep '"hash":' | awk -F'"' '{print $4}')
echo "   Miner‑1 Hash: $HASH1"
echo "   Miner‑2 Hash: $HASH2"

if [[ -z "$HASH1" || -z "$HASH2" ]]; then
    echo "❌ TEST FAILED: Could not retrieve block hashes (one node may not have reached $BLOCK_HEIGHT)."
    docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status
    docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status
    exit 1
fi
if [[ "$HASH1" == "$HASH2" ]]; then
    echo "❌ TEST FAILED: Chains did not diverge (hashes are identical)."
    exit 1
fi
echo "✅ SUCCESS: Chains have diverged (hashes differ)!"

# 4️⃣ Re‑connect miner‑2 and give it a chance to sync
echo "🔗 Reconnecting Miner‑2 to network..."
docker network connect docker_zeicoin-network zeicoin-miner-2

echo "🔄 Restarting Miner‑2 to force immediate reconnection..."
docker restart zeicoin-miner-2

# Give the node a moment to initialize its API server
echo "⏳ Waiting 5s for Miner-2 API to start..."
sleep 5

echo "⏳ Waiting for sync..."

# Poll for convergence
attempt=0
while (( attempt < MAX_RETRIES )); do
    ((++attempt))
    echo "🔍 Attempt $attempt/$MAX_RETRIES: checking convergence..."
    
    # Use || true to prevent script exit if node is not yet ready (set -e)
    RAW1_NEW=$(docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1 || true)
    RAW2_NEW=$(docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin block $BLOCK_HEIGHT 2>&1 || true)
    
    HASH1_NEW=$(echo "$RAW1_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
    HASH2_NEW=$(echo "$RAW2_NEW" | grep '"hash":' | awk -F'"' '{print $4}')
    
    echo "   Miner‑1 Hash: $HASH1_NEW"
    echo "   Miner‑2 Hash: $HASH2_NEW"
    
    if [[ -n "$HASH1_NEW" && -n "$HASH2_NEW" && "$HASH1_NEW" == "$HASH2_NEW" ]]; then
        echo "✅ SUCCESS: Chains have converged (hashes are identical)!"
        echo "🎉 REORGANIZATION TEST PASSED!"
        echo "🧹 Cleaning up..."
        docker compose down -v
        exit 0
    fi
    
    echo "   Not yet converged – waiting 10 s before next attempt"
    sleep 10
done

# ----- If we get here the hashes never matched -----
echo "❌ TEST FAILED: Chains did not converge after $MAX_RETRIES attempts"
docker exec zeicoin-miner-1 ./zig-out/bin/zeicoin status
docker exec zeicoin-miner-2 ./zig-out/bin/zeicoin status
docker logs --tail 100 zeicoin-miner-1
docker logs --tail 100 zeicoin-miner-2
docker compose down -v
exit 1
