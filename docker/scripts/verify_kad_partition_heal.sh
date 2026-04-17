#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

# verify_kad_partition_heal.sh — End-to-end Docker validation for Kad recovery
#
# Verifies that the real zen_server runtime can recover from a temporary network
# partition of a non-seed node:
# - the initial 3-node topology converges into a full direct mesh
# - miner-2 is then restarted in passive mode so the test tracks recovery
#   against a single canonical mining chain rather than multi-miner reorg races
# - isolating node-1 does not break miner-to-miner connectivity or progress
# - reconnecting node-1 restores Kad refresh/direct sessions
# - node-1 catches back up to the current chain after healing

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/tmp/zen-kad-partition-heal-$RUN_ID}"
HOST_ZIG_VERSION="$(zig version)"
NETWORK_NAME="docker_zeicoin-network"

CONTAINERS=(zeicoin-miner-1 zeicoin-miner-2 zeicoin-node-1)
ISOLATED_NODE="zeicoin-node-1"

mkdir -p "$LOG_DIR"

ZIG_CACHE="$ROOT_DIR/.docker-cache"
ZIG_TARBALL="$ZIG_CACHE/zig-nightly.tar.xz"
if [[ ! -f "$ZIG_TARBALL" ]]; then
    mkdir -p "$ZIG_CACHE"
    HOST_TARBALL=""
    for candidate in \
        "$HOME/Downloads/zig-x86_64-linux-$HOST_ZIG_VERSION.tar.xz" \
        "$HOME/zig-latest-nightly/zig-x86_64-linux-$HOST_ZIG_VERSION.tar.xz"
    do
        if [[ -f "$candidate" ]]; then
            HOST_TARBALL="$candidate"
            break
        fi
    done
    HOST_TARBALL="${HOST_ZIG_TARBALL:-$HOST_TARBALL}"
    if [[ -z "$HOST_TARBALL" || ! -f "$HOST_TARBALL" ]]; then
        echo "ERROR: Cannot find Zig $HOST_ZIG_VERSION tarball."
        echo "Set HOST_ZIG_TARBALL=/path/to/zig-x86_64-linux-*.tar.xz"
        exit 1
    fi
    cp -f "$HOST_TARBALL" "$ZIG_TARBALL"
    echo "Cached Zig tarball: $HOST_TARBALL -> $ZIG_TARBALL"
fi

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

log() {
    echo "[kad-heal $(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/test.log"
}

container_logs() {
    docker logs "$1" 2>&1
}

save_all_logs() {
    for c in "${CONTAINERS[@]}"; do
        container_logs "$c" > "$LOG_DIR/$c.log" 2>&1 || true
    done
}

healthy() {
    docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "missing"
}

attached_to_network() {
    local container="$1"
    if docker inspect -f '{{range $k, $_ := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$container" 2>/dev/null \
        | grep -qx "$NETWORK_NAME"; then
        echo "yes"
    else
        echo "no"
    fi
}

server_host() {
    case "$1" in
        zeicoin-miner-1) echo "172.33.0.10" ;;
        zeicoin-miner-2) echo "172.33.0.11" ;;
        zeicoin-node-1) echo "172.33.0.12" ;;
        *) return 1 ;;
    esac
}

peer_count() {
    local container="$1"
    local host
    local attempt output count
    host="$(server_host "$container")"
    for attempt in 1 2 3; do
        output="$(timeout 15s docker exec "$container" \
            env ZEICOIN_SERVER="$host" ./zig-out/bin/zeicoin status 2>&1 || true)"
        count="$(printf '%s\n' "$output" \
            | sed -n 's/.*Connected Peers:[[:space:]]*\([0-9]*\).*/\1/p' \
            | tail -n1)"
        if [[ -n "$count" ]]; then
            echo "$count"
            return 0
        fi
        sleep 1
    done
    echo "-1"
}

block_height() {
    local container="$1"
    local host
    local output
    host="$(server_host "$container")"
    output="$(timeout 15s docker exec "$container" \
        env ZEICOIN_SERVER="$host" ./zig-out/bin/zeicoin status 2>&1 || true)"
    printf '%s\n' "$output" | sed -n 's/.*Network Height:[[:space:]]*\([0-9]*\).*/\1/p' | tail -n1
}

block_hash() {
    local container="$1"
    local height="$2"
    local host
    local output
    host="$(server_host "$container")"
    output="$(timeout 15s docker exec "$container" \
        env ZEICOIN_SERVER="$host" ./zig-out/bin/zeicoin block "$height" 2>&1 || true)"
    printf '%s\n' "$output" | awk -F'"' '/"hash":/ {print $4; exit}'
}

last_kad_metric() {
    local container="$1"
    local key="$2"
    local value
    value="$(container_logs "$container" \
        | sed -n "s/.*kad_status: .*${key}=\([0-9]*\).*/\1/p" \
        | tail -n1)"
    echo "${value:-0}"
}

routing_peers() {
    last_kad_metric "$1" "routing_peers"
}

kad_addrs() {
    last_kad_metric "$1" "kad_addrs"
}

refresh_count() {
    local container="$1"
    local count
    count="$(container_logs "$container" | grep -c "kad_status: reason=refresh" || true)"
    echo "${count:-0}"
}

format_peer_count() {
    local count="$1"
    if (( count < 0 )); then
        echo "unknown"
    else
        echo "$count"
    fi
}

run_passive_miner2() {
    local image_id="$1"

    docker rm -f zeicoin-miner-2 >/dev/null 2>&1 || true
    docker run -d --name zeicoin-miner-2 \
      --network "$NETWORK_NAME" \
      --ip 172.33.0.11 \
      --network-alias miner-2 \
      -v docker_miner2-data:/zeicoin/zeicoin_data_testnet \
      -e ZEICOIN_NETWORK=testnet \
      -e ZEICOIN_TEST_MODE=true \
      -e ZEICOIN_BIND_IP=172.33.0.11 \
      -e ZEICOIN_P2P_PORT=10801 \
      -e ZEICOIN_API_PORT=10802 \
      -e ZEICOIN_SERVER=172.33.0.11 \
      -e ZEICOIN_BOOTSTRAP=/ip4/172.33.0.10/tcp/10801 \
      -e ZEICOIN_REACHABILITY=public \
      -e ZEICOIN_MINE_ENABLED=false \
      "$image_id" \
      ./zig-out/bin/zen_server >/dev/null
}

ephemeral_refused_count() {
    local container="$1"
    (container_logs "$container" \
        | grep -E "ConnectionRefused" \
        | grep -E "/ip4/172\.33\.0\.(11|12)/tcp/[1-9][0-9]{4}" \
        | grep -v "/tcp/10801" \
        | wc -l) || true
}

fail() {
    log "FAIL: $*"
    save_all_logs
    log "Logs saved to $LOG_DIR"
    echo ""
    echo "FAIL"
    exit 1
}

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "Cleaning up any previous run"
compose down -v --remove-orphans >/dev/null 2>&1 || true

log "Building and starting 3-node zen_server cluster"
compose up -d --build 2>&1 | tail -5

log "Waiting for all containers to become healthy (up to 180s)"
deadline=$((SECONDS + 180))
while true; do
    all_healthy=1
    for c in "${CONTAINERS[@]}"; do
        if [[ "$(healthy "$c")" != "healthy" ]]; then
            all_healthy=0
            break
        fi
    done
    if (( all_healthy )); then
        log "All containers healthy"
        break
    fi
    if (( SECONDS > deadline )); then
        for c in "${CONTAINERS[@]}"; do
            log "  $c: $(healthy "$c")"
        done
        fail "Timeout waiting for healthy containers"
    fi
    sleep 3
done

log "Waiting for full Kad/direct-session convergence before partitioning (up to 120s)"
deadline=$((SECONDS + 120))
stable_successes=0
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)

    m1_routing=$(routing_peers zeicoin-miner-1)
    m2_routing=$(routing_peers zeicoin-miner-2)
    n1_routing=$(routing_peers zeicoin-node-1)

    m2_kad_addrs=$(kad_addrs zeicoin-miner-2)
    n1_kad_addrs=$(kad_addrs zeicoin-node-1)

    m1_refreshes=$(refresh_count zeicoin-miner-1)
    m2_refreshes=$(refresh_count zeicoin-miner-2)
    n1_refreshes=$(refresh_count zeicoin-node-1)

    if (( m1_peers >= 2 && m2_peers >= 2 && n1_peers >= 2 &&
          m1_routing >= 2 && m2_routing >= 2 && n1_routing >= 2 &&
          m2_kad_addrs >= 1 && n1_kad_addrs >= 1 &&
          m1_refreshes >= 1 && m2_refreshes >= 1 && n1_refreshes >= 1 )); then
        stable_successes=$((stable_successes + 1))
        if (( stable_successes >= 2 )); then
            log "  peers — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
            log "  routing_peers — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
            log "  kad_addrs — miner-2=$m2_kad_addrs node-1=$n1_kad_addrs"
            log "  refreshes — miner-1=$m1_refreshes miner-2=$m2_refreshes node-1=$n1_refreshes"
            break
        fi
    else
        stable_successes=0
    fi

    if (( SECONDS > deadline )); then
        log "  peers — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        log "  routing_peers — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
        log "  kad_addrs — miner-2=$m2_kad_addrs node-1=$n1_kad_addrs"
        log "  refreshes — miner-1=$m1_refreshes miner-2=$m2_refreshes node-1=$n1_refreshes"
        fail "Cluster never reached full Kad/direct-session convergence before partition"
    fi
    sleep 3
done

log "Restarting miner-2 in passive mode to remove competing-miner reorg noise from the recovery proof"
miner2_image_id="$(compose images -q miner-2)"
if [[ -z "$miner2_image_id" ]]; then
    fail "Could not determine miner-2 image ID"
fi
docker stop zeicoin-miner-2 >/dev/null
run_passive_miner2 "$miner2_image_id"

log "Waiting for passive miner-2 to rejoin the full mesh (up to 120s)"
deadline=$((SECONDS + 120))
stable_successes=0
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)
    if (( m1_peers >= 2 && m2_peers >= 2 && n1_peers >= 2 )); then
        stable_successes=$((stable_successes + 1))
        if (( stable_successes >= 2 )); then
            log "  mesh restored with passive miner-2 — peers: miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
            break
        fi
    else
        stable_successes=0
    fi
    if (( SECONDS > deadline )); then
        log "  peers after passive miner-2 restart — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        fail "Passive miner-2 never rejoined the full mesh"
    fi
    sleep 3
done

canonical_height="$(block_height zeicoin-miner-1)"
if [[ -z "$canonical_height" ]]; then
    fail "Could not read canonical height before partition"
fi
log "Waiting for all nodes to agree on the pre-partition canonical chain at height $canonical_height (up to 120s)"
deadline=$((SECONDS + 120))
while true; do
    m2_height="$(block_height zeicoin-miner-2)"
    n1_height="$(block_height zeicoin-node-1)"

    if [[ -n "$m2_height" && -n "$n1_height" ]] &&
       (( m2_height >= canonical_height && n1_height >= canonical_height )); then
        m1_hash="$(block_hash zeicoin-miner-1 "$canonical_height")"
        m2_hash="$(block_hash zeicoin-miner-2 "$canonical_height")"
        n1_hash="$(block_hash zeicoin-node-1 "$canonical_height")"
        if [[ -n "$m1_hash" && "$m1_hash" == "$m2_hash" && "$m1_hash" == "$n1_hash" ]]; then
            log "  canonical hash agreement confirmed at height $canonical_height"
            break
        fi
    fi

    if (( SECONDS > deadline )); then
        log "  heights before partition — miner-2=${m2_height:-unknown} node-1=${n1_height:-unknown} target=$canonical_height"
        fail "Nodes never converged on a single canonical chain before partition"
    fi
    sleep 3
done

node_refresh_before_partition=$(refresh_count "$ISOLATED_NODE")
miner1_height_before_partition="$(block_height zeicoin-miner-1)"
miner2_height_before_partition="$(block_height zeicoin-miner-2)"
if [[ -z "$miner1_height_before_partition" || -z "$miner2_height_before_partition" ]]; then
    fail "Could not read baseline heights before partition"
fi
partition_target_height="$miner2_height_before_partition"
if (( miner1_height_before_partition > partition_target_height )); then
    partition_target_height="$miner1_height_before_partition"
fi
partition_target_height=$((partition_target_height + 2))

log "Partitioning node-1 away from the Docker network"
docker network disconnect "$NETWORK_NAME" "$ISOLATED_NODE" >/dev/null

log "Waiting for the partition to fully manifest and the mining side to stay live (up to 120s)"
deadline=$((SECONDS + 120))
stable_successes=0
while true; do
    attached="$(attached_to_network "$ISOLATED_NODE")"
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)
    m1_height="$(block_height zeicoin-miner-1)"
    m2_height="$(block_height zeicoin-miner-2)"

    if [[ "$attached" == "no" ]] &&
       (( m1_peers == 1 && m2_peers == 1 && n1_peers <= 0 )) &&
       [[ -n "$m1_height" && -n "$m2_height" ]] &&
       (( m1_height >= partition_target_height || m2_height >= partition_target_height )); then
        stable_successes=$((stable_successes + 1))
        if (( stable_successes >= 2 )); then
            log "  node-1 detached from network and peer sessions drained"
            log "  peers while partitioned — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
            log "  heights while partitioned — miner-1=$m1_height miner-2=$m2_height"
            break
        fi
    else
        stable_successes=0
    fi

    if (( SECONDS > deadline )); then
        log "  node-1 attached_to_network=$attached"
        log "  peers while partitioned — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        log "  heights while partitioned — miner-1=${m1_height:-unknown} miner-2=${m2_height:-unknown}"
        fail "Partition never fully manifested into drained peer sessions while mining stayed live"
    fi
    sleep 3
done

log "Reconnecting node-1 to the Docker network"
docker network connect --ip 172.33.0.12 "$NETWORK_NAME" "$ISOLATED_NODE" >/dev/null

log "Waiting for node-1 to become healthy again (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    if [[ "$(healthy "$ISOLATED_NODE")" == "healthy" ]]; then
        log "  node-1 healthy after reconnect"
        break
    fi
    if (( SECONDS > deadline )); then
        log "  node-1 health: $(healthy "$ISOLATED_NODE")"
        fail "node-1 did not become healthy after reconnect"
    fi
    sleep 3
done

heal_target_height="$(block_height zeicoin-miner-1)"
current_miner2_height="$(block_height zeicoin-miner-2)"
if [[ -z "$heal_target_height" || -z "$current_miner2_height" ]]; then
    fail "Could not read heal target heights after reconnect"
fi
if (( current_miner2_height > heal_target_height )); then
    heal_target_height="$current_miner2_height"
fi

log "Waiting for full-mesh recovery, Kad refresh, and node-1 catch-up (up to 180s)"
deadline=$((SECONDS + 180))
stable_successes=0
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)

    m1_routing=$(routing_peers zeicoin-miner-1)
    m2_routing=$(routing_peers zeicoin-miner-2)
    n1_routing=$(routing_peers zeicoin-node-1)

    n1_refreshes=$(refresh_count zeicoin-node-1)
    n1_height="$(block_height zeicoin-node-1)"

    if (( m1_peers >= 2 && m2_peers >= 2 && n1_peers >= 2 &&
          m1_routing >= 2 && m2_routing >= 2 && n1_routing >= 2 &&
          n1_refreshes > node_refresh_before_partition )) &&
       [[ -n "$n1_height" ]] &&
       (( n1_height >= heal_target_height )); then
        stable_successes=$((stable_successes + 1))
        if (( stable_successes >= 2 )); then
            log "  peers after heal — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
            log "  routing_peers after heal — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
            log "  node-1 refreshes: before=$node_refresh_before_partition after=$n1_refreshes"
            log "  node-1 height after heal: $n1_height (target >= $heal_target_height)"
            break
        fi
    else
        stable_successes=0
    fi

    if (( SECONDS > deadline )); then
        log "  peers after heal — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        log "  routing_peers after heal — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
        log "  node-1 refreshes: before=$node_refresh_before_partition after=$n1_refreshes"
        log "  node-1 height after heal: ${n1_height:-unknown} (target >= $heal_target_height)"
        fail "Node-1 never healed back into the full mesh and caught up"
    fi
    sleep 3
done

reference_hash="$(block_hash zeicoin-miner-1 "$heal_target_height")"
miner2_hash="$(block_hash zeicoin-miner-2 "$heal_target_height")"
node1_hash="$(block_hash zeicoin-node-1 "$heal_target_height")"
if [[ -z "$reference_hash" || -z "$miner2_hash" || -z "$node1_hash" ]]; then
    fail "Could not read verification hashes at healed height $heal_target_height"
fi
if [[ "$reference_hash" != "$miner2_hash" || "$reference_hash" != "$node1_hash" ]]; then
    log "  verification height: $heal_target_height"
    log "  miner-1 hash: $reference_hash"
    log "  miner-2 hash: $miner2_hash"
    log "  node-1 hash: $node1_hash"
    fail "Healed cluster does not agree on block hash at the post-heal verification height"
fi

log "Checking for repeated ConnectionRefused dials against ephemeral ports after healing"
m2_refused=$(ephemeral_refused_count zeicoin-miner-2)
n1_refused=$(ephemeral_refused_count zeicoin-node-1)
log "  miner-2 ephemeral refused dials=$m2_refused"
log "  node-1 ephemeral refused dials=$n1_refused"
if (( m2_refused > 0 || n1_refused > 0 )); then
    fail "Observed ConnectionRefused dials against ephemeral peer ports after partition heal"
fi

save_all_logs

log ""
log "Final state:"
for c in "${CONTAINERS[@]}"; do
    p=$(peer_count "$c")
    h=$(block_height "$c")
    r=$(routing_peers "$c")
    k=$(kad_addrs "$c")
    f=$(refresh_count "$c")
    log "  $c — peers=$p height=$h routing_peers=$r kad_addrs=$k refreshes=$f"
done

log ""
log "Logs saved to $LOG_DIR"
echo ""
echo "PASS"
