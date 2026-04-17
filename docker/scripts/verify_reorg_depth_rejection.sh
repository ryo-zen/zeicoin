#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DOCKER_DIR"

REORG_MAX_DEPTH="${ZEICOIN_MAX_REORG_DEPTH:-20}"
TARGET_MARGIN=6
ATTACKER_OVERTAKE_MARGIN=3
TARGET_DEPTH=$((REORG_MAX_DEPTH + TARGET_MARGIN))
HEIGHT_TIMEOUT=240
RECONNECT_TIMEOUT=120
POLL_INTERVAL=5

HONEST_MINER="zeicoin-miner-1"
ATTACKER_MINER="zeicoin-miner-2"
OBSERVER_NODE="zeicoin-node-1"
NETWORK_NAME="docker_zeicoin-network"

cleanup() {
    echo "🧹 Cleaning up..."
    docker rm -f "$ATTACKER_MINER" >/dev/null 2>&1 || true
    docker rm -f "$HONEST_MINER" >/dev/null 2>&1 || true
    docker compose down -v >/dev/null 2>&1 || true
}

fail() {
    echo "❌ TEST FAILED: $1"
    echo
    echo "🔍 Debugging information:"
    for container in "$HONEST_MINER" "$ATTACKER_MINER"; do
        echo "--- ${container} status ---"
        docker exec "$container" ./zig-out/bin/zeicoin status 2>&1 || true
    done
    echo "--- ${HONEST_MINER} logs (last 120 lines) ---"
    docker logs --tail 120 "$HONEST_MINER" 2>&1 || true
    echo "--- ${ATTACKER_MINER} logs (last 120 lines) ---"
    docker logs --tail 120 "$ATTACKER_MINER" 2>&1 || true
    cleanup
    exit 1
}

trap cleanup EXIT

extract_hash() {
    awk -F'"' '/"hash":/ {print $4; exit}'
}

get_block_hash() {
    local container="$1"
    local height="$2"
    local output

    output=$(docker exec "$container" ./zig-out/bin/zeicoin block "$height" 2>&1 || true)
    printf '%s\n' "$output" | extract_hash
}

get_height() {
    local container="$1"
    local output
    local height

    output=$(docker exec "$container" ./zig-out/bin/zeicoin status 2>&1 || true)
    height=$(printf '%s\n' "$output" | sed -n 's/.*Network Height: \([0-9][0-9]*\).*/\1/p' | head -n 1)
    if [[ -z "$height" ]]; then
        return 1
    fi

    printf '%s\n' "$height"
}

wait_for_api() {
    local container="$1"
    local deadline=$((SECONDS + 90))

    while (( SECONDS < deadline )); do
        if docker exec "$container" ./zig-out/bin/zeicoin status >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done

    return 1
}

wait_for_height() {
    local container="$1"
    local minimum_height="$2"
    local timeout="$3"
    local deadline=$((SECONDS + timeout))
    local height

    while (( SECONDS < deadline )); do
        if height=$(get_height "$container"); then
            echo "   ${container} height: ${height} / ${minimum_height}"
            if (( height >= minimum_height )); then
                return 0
            fi
        fi
        sleep "$POLL_INTERVAL"
    done

    return 1
}

find_fork_point() {
    local container_a="$1"
    local container_b="$2"
    local max_height="$3"
    local last_common=0
    local height=1
    local hash_a
    local hash_b

    while (( height <= max_height )); do
        hash_a=$(get_block_hash "$container_a" "$height")
        hash_b=$(get_block_hash "$container_b" "$height")

        if [[ -z "$hash_a" || -z "$hash_b" ]]; then
            break
        fi

        if [[ "$hash_a" != "$hash_b" ]]; then
            break
        fi

        last_common=$height
        ((height += 1))
    done

    printf '%s\n' "$last_common"
}

run_passive_miner() {
    local bootstrap="$1"
    local image_id="$2"

    docker rm -f "$HONEST_MINER" >/dev/null 2>&1 || true
    docker run -d --name "$HONEST_MINER" \
      --network "$NETWORK_NAME" \
      --ip 172.33.0.10 \
      --network-alias miner-1 \
      -v docker_miner1-data:/zeicoin/zeicoin_data_testnet \
      -e ZEICOIN_NETWORK=testnet \
      -e ZEICOIN_TEST_MODE=true \
      -e ZEICOIN_BIND_IP=0.0.0.0 \
      -e ZEICOIN_P2P_PORT=10801 \
      -e ZEICOIN_API_PORT=10802 \
      -e ZEICOIN_SERVER=127.0.0.1 \
      -e ZEICOIN_BOOTSTRAP="$bootstrap" \
      -e ZEICOIN_REACHABILITY=public \
      -e ZEICOIN_MINE_ENABLED=false \
      "$image_id" \
      ./zig-out/bin/zen_server >/dev/null
}

run_passive_attacker() {
    local image_id="$1"

    docker rm -f "$ATTACKER_MINER" >/dev/null 2>&1 || true
    docker run -d --name "$ATTACKER_MINER" \
      --network "$NETWORK_NAME" \
      --ip 172.33.0.11 \
      --network-alias miner-2 \
      -v docker_miner2-data:/zeicoin/zeicoin_data_testnet \
      -e ZEICOIN_NETWORK=testnet \
      -e ZEICOIN_TEST_MODE=true \
      -e ZEICOIN_BIND_IP=0.0.0.0 \
      -e ZEICOIN_P2P_PORT=10801 \
      -e ZEICOIN_API_PORT=10802 \
      -e ZEICOIN_SERVER=127.0.0.1 \
      -e ZEICOIN_BOOTSTRAP="" \
      -e ZEICOIN_REACHABILITY=public \
      -e ZEICOIN_MINE_ENABLED=false \
      "$image_id" \
      ./zig-out/bin/zen_server >/dev/null
}

echo "🚀 Starting deep reorg rejection test..."
echo "   Honest node target: ${HONEST_MINER}"
echo "   Configured max reorg depth: ${REORG_MAX_DEPTH}"
echo "   Required observed depth: > ${REORG_MAX_DEPTH}"

echo "🧹 Cleaning up previous run..."
docker rm -f "$ATTACKER_MINER" >/dev/null 2>&1 || true
docker rm -f "$HONEST_MINER" >/dev/null 2>&1 || true
docker compose down -v >/dev/null 2>&1 || true

echo "📦 Starting Docker environment..."
docker compose up -d --build >/dev/null

echo "⏳ Waiting for miner APIs to become reachable..."
wait_for_api "$HONEST_MINER" || fail "miner-1 API never became ready"
wait_for_api "$ATTACKER_MINER" || fail "miner-2 API never became ready"

echo "🛑 Stopping unused observer node to keep the topology aligned with the working reorg scripts..."
docker rm -f "$OBSERVER_NODE" >/dev/null 2>&1 || true

echo "✂️  Disconnecting attacker miner from the network..."
docker network disconnect "$NETWORK_NAME" "$ATTACKER_MINER" >/dev/null || fail "failed to disconnect attacker miner"

echo "⏳ Waiting for both chains to exceed the reorg depth cap..."
wait_for_height "$HONEST_MINER" "$TARGET_DEPTH" "$HEIGHT_TIMEOUT" || fail "miner-1 did not reach target height ${TARGET_DEPTH}"
wait_for_height "$ATTACKER_MINER" "$TARGET_DEPTH" "$HEIGHT_TIMEOUT" || fail "miner-2 did not reach target height ${TARGET_DEPTH}"

honest_height=$(get_height "$HONEST_MINER") || fail "could not read honest miner height"
attacker_height=$(get_height "$ATTACKER_MINER") || fail "could not read attacker height"
shared_max=$honest_height
if (( attacker_height < shared_max )); then
    shared_max=$attacker_height
fi

fork_point=$(find_fork_point "$HONEST_MINER" "$ATTACKER_MINER" "$shared_max")
if (( fork_point >= shared_max )); then
    fail "miners never diverged before reconnect"
fi

depth=$((honest_height - fork_point))
if (( depth <= REORG_MAX_DEPTH )); then
    fail "observed depth ${depth} did not exceed configured maximum ${REORG_MAX_DEPTH}"
fi

verification_height=$((fork_point + 1))
honest_hash=$(get_block_hash "$HONEST_MINER" "$verification_height")
attacker_hash=$(get_block_hash "$ATTACKER_MINER" "$verification_height")
if [[ -z "$honest_hash" || -z "$attacker_hash" ]]; then
    fail "could not retrieve verification-height hashes before reconnect"
fi
if [[ "$honest_hash" == "$attacker_hash" ]]; then
    fail "verification height ${verification_height} is not on divergent branches"
fi

echo "✅ Divergence confirmed:"
echo "   Honest height: ${honest_height}"
echo "   Attacker height: ${attacker_height}"
echo "   Fork point: ${fork_point}"
echo "   Observed depth: ${depth}"
echo "   Verification height: ${verification_height}"
echo "   Honest hash: ${honest_hash}"
echo "   Attacker hash: ${attacker_hash}"

echo "❄️  Freezing honest miner at height ${honest_height}..."
MINER_IMAGE_ID=$(docker compose images -q miner-1)
if [[ -z "$MINER_IMAGE_ID" ]]; then
    fail "could not determine miner-1 image ID"
fi

docker stop "$HONEST_MINER" >/dev/null
run_passive_miner "" "$MINER_IMAGE_ID"
wait_for_api "$HONEST_MINER" || fail "frozen honest miner API never became ready"

overtake_target=$((honest_height + ATTACKER_OVERTAKE_MARGIN))
echo "⏳ Waiting for attacker to overtake the frozen honest chain (target height ${overtake_target})..."
wait_for_height "$ATTACKER_MINER" "$overtake_target" "$HEIGHT_TIMEOUT" || fail "attacker miner never overtook the frozen honest chain"

ATTACKER_IMAGE_ID=$(docker compose images -q miner-2)
if [[ -z "$ATTACKER_IMAGE_ID" ]]; then
    fail "could not determine miner-2 image ID"
fi

echo "❄️  Freezing attacker chain at the overtaken tip..."
docker stop "$ATTACKER_MINER" >/dev/null

echo "🛑 Taking the honest miner offline until the attacker is fully reconnected..."
docker stop "$HONEST_MINER" >/dev/null

echo "🔄 Restarting attacker as a passive higher-tip peer..."
run_passive_attacker "$ATTACKER_IMAGE_ID"
wait_for_api "$ATTACKER_MINER" || fail "attacker passive node never became ready"

echo "🔄 Restarting honest miner with attacker-only bootstrap so it must evaluate the competing branch..."
run_passive_miner "/ip4/172.33.0.11/tcp/10801" "$MINER_IMAGE_ID"
wait_for_api "$HONEST_MINER" || fail "honest miner API never recovered after restart"

echo "⏳ Waiting for the honest miner to detect and reject the deep reorg..."
deadline=$((SECONDS + RECONNECT_TIMEOUT))
while (( SECONDS < deadline )); do
    logs=$(docker logs "$HONEST_MINER" 2>&1 || true)
    if [[ "$logs" == *"[REORG ALERT] Deep reorg candidate detected"* ]] && \
       [[ "$logs" == *"[REORG POLICY] Rejecting competing chain because reorg depth"* ]]; then
        break
    fi
    sleep "$POLL_INTERVAL"
done

logs=$(docker logs "$HONEST_MINER" 2>&1 || true)
if [[ "$logs" != *"[REORG ALERT] Deep reorg candidate detected"* ]]; then
    fail "honest miner never emitted the deep reorg alert"
fi
if [[ "$logs" != *"[REORG POLICY] Rejecting competing chain because reorg depth"* ]]; then
    fail "honest miner never emitted the reorg policy rejection"
fi
if [[ "$logs" == *"[REORG] Fetching competing chain blocks for local work verification..."* ]]; then
    fail "honest miner fetched competing reorg blocks even though the over-depth branch should be rejected first"
fi

honest_post_hash=$(get_block_hash "$HONEST_MINER" "$verification_height")
attacker_post_hash=$(get_block_hash "$ATTACKER_MINER" "$verification_height")
if [[ -z "$honest_post_hash" || -z "$attacker_post_hash" ]]; then
    fail "could not retrieve verification-height hashes after reconnect"
fi
if [[ "$honest_post_hash" != "$honest_hash" ]]; then
    fail "honest miner changed canonical history at the verification height"
fi
if [[ "$honest_post_hash" == "$attacker_post_hash" ]]; then
    fail "honest miner adopted the attacker's branch despite over-depth rejection"
fi

echo "✅ Honest miner rejected the deep reorg:"
echo "   miner-1 hash at height ${verification_height}: ${honest_post_hash}"
echo "   miner-2 hash at height ${verification_height}: ${attacker_post_hash}"
echo "🎉 ZEI-52 deep reorg rejection test PASSED!"
