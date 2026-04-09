#!/usr/bin/env bash
# test_libp2p_zen_server.sh — End-to-end Docker validation for ZEI-98
#
# Verifies that zen_server containers expose Kad behavior in the real runtime:
# - all non-seed nodes start with only the seed as bootstrap input
# - Kad refreshes appear in runtime logs
# - Kad routing converges on the 3-node topology in the real runtime
# - block sync still works
# - the restarted bootstrap node refreshes and reconnects to both peers
#
# Usage:
#   ./docker/scripts/test_libp2p_zen_server.sh
#
# Pass/fail is indicated by exit code and final PASS/FAIL line.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/tmp/zen-server-docker-$RUN_ID}"
HOST_ZIG_VERSION="$(zig version)"

CONTAINERS=(zeicoin-miner-1 zeicoin-miner-2 zeicoin-node-1)

mkdir -p "$LOG_DIR"

# ── Prepare Zig tarball for Docker build ────────────────────────────
# The Dockerfile COPYs .docker-cache/zig-nightly.tar.xz instead of wget.
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
    echo "[zen-docker $(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/test.log"
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

server_host() {
    case "$1" in
        zeicoin-miner-1) echo "172.33.0.10" ;;
        zeicoin-miner-2) echo "172.33.0.11" ;;
        zeicoin-node-1) echo "172.33.0.12" ;;
        *) return 1 ;;
    esac
}

# Extract peer count from `zeicoin status` output inside a container
# Note: zeicoin CLI uses std.debug.print which writes to stderr
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
    host="$(server_host "$container")"
    docker exec "$container" \
        env ZEICOIN_SERVER="$host" ./zig-out/bin/zeicoin status 2>&1 \
        | sed -n 's/.*Network Height:[[:space:]]*\([0-9]*\).*/\1/p' || echo "0"
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

# ── Phase 1: Build & Start ──────────────────────────────────────────

log "Cleaning up any previous run"
compose down -v --remove-orphans >/dev/null 2>&1 || true

log "Building and starting 3-node cluster"
compose up -d --build 2>&1 | tail -5

# ── Phase 2: Wait for healthy ───────────────────────────────────────

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

# ── Phase 3: Verify runtime log markers ─────────────────────────────

log "Checking libp2p and Kad runtime markers"
sleep 10  # let connections settle

save_all_logs

for c in "${CONTAINERS[@]}"; do
    if ! grep -q "Node identity:" "$LOG_DIR/$c.log"; then
        fail "$c missing 'Node identity:' — libp2p not initializing"
    fi
    if ! grep -q "Kad runtime enabled:" "$LOG_DIR/$c.log"; then
        fail "$c missing 'Kad runtime enabled:' — Kad service not configured in zen_server"
    fi
done
log "  Node identity and Kad runtime markers present on all containers"

# No container should show legacy format error
for c in "${CONTAINERS[@]}"; do
    if grep -q "legacy ip:port format" "$LOG_DIR/$c.log"; then
        fail "$c logged 'legacy ip:port format' — bootstrap config is wrong"
    fi
done
log "  No legacy format errors"

# miner-2 and node-1 should show bootstrap connection attempts
for c in zeicoin-miner-2 zeicoin-node-1; do
    if ! grep -q "bootstrap" "$LOG_DIR/$c.log"; then
        log "  WARNING: $c has no bootstrap log lines (may be OK if connection was instant)"
    fi
done

# ── Phase 4: Wait for Kad refresh markers ───────────────────────────

log "Waiting for Kad refresh logs from all zen_server nodes (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    m1_refreshes=$(refresh_count zeicoin-miner-1)
    m2_refreshes=$(refresh_count zeicoin-miner-2)
    n1_refreshes=$(refresh_count zeicoin-node-1)

    if (( m1_refreshes >= 1 && m2_refreshes >= 1 && n1_refreshes >= 1 )); then
        log "  refresh counts — miner-1=$m1_refreshes miner-2=$m2_refreshes node-1=$n1_refreshes"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  refresh counts — miner-1=$m1_refreshes miner-2=$m2_refreshes node-1=$n1_refreshes"
        fail "Timeout waiting for Kad refresh log markers"
    fi
    sleep 3
done

# ── Phase 5: Verify Kad routing convergence and direct session promotion ─────

log "Waiting for Kad routing convergence, Kad-learned addresses, and full transport mesh (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)

    m1_routing=$(routing_peers zeicoin-miner-1)
    m2_routing=$(routing_peers zeicoin-miner-2)
    n1_routing=$(routing_peers zeicoin-node-1)

    m2_kad_addrs=$(kad_addrs zeicoin-miner-2)
    n1_kad_addrs=$(kad_addrs zeicoin-node-1)

    if (( m1_peers >= 2 && m2_peers >= 2 && n1_peers >= 2 &&
          m1_routing >= 2 && m2_routing >= 2 && n1_routing >= 2 &&
          m2_kad_addrs >= 1 && n1_kad_addrs >= 1 )); then
        log "  connected peers — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        log "  routing_peers — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
        log "  kad_addrs — miner-2=$m2_kad_addrs node-1=$n1_kad_addrs"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  connected peers — miner-1=$(format_peer_count "$m1_peers") miner-2=$(format_peer_count "$m2_peers") node-1=$(format_peer_count "$n1_peers")"
        log "  routing_peers — miner-1=$m1_routing miner-2=$m2_routing node-1=$n1_routing"
        log "  kad_addrs — miner-2=$m2_kad_addrs node-1=$n1_kad_addrs"
        fail "Timeout waiting for Kad routing convergence and direct non-seed session promotion in zen_server"
    fi
    sleep 3
done

log "Checking for repeated ConnectionRefused dials against ephemeral ports"
m2_refused=$(ephemeral_refused_count zeicoin-miner-2)
n1_refused=$(ephemeral_refused_count zeicoin-node-1)
log "  miner-2 ephemeral refused dials=$m2_refused"
log "  node-1 ephemeral refused dials=$n1_refused"
if (( m2_refused > 0 || n1_refused > 0 )); then
    fail "Observed ConnectionRefused dials against ephemeral peer ports"
fi

# ── Phase 6: Verify repeated Kad refreshes ─────────────────────────

log "Waiting for repeated Kad refreshes on non-seed nodes (up to 30s)"
deadline=$((SECONDS + 30))
while true; do
    m2_refreshes=$(refresh_count zeicoin-miner-2)
    n1_refreshes=$(refresh_count zeicoin-node-1)

    if (( m2_refreshes >= 2 && n1_refreshes >= 2 )); then
        log "  repeated refresh counts — miner-2=$m2_refreshes node-1=$n1_refreshes"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  repeated refresh counts — miner-2=$m2_refreshes node-1=$n1_refreshes"
        fail "Timed out waiting for repeated Kad refreshes in zen_server logs"
    fi
    sleep 3
done

# ── Phase 7: Verify block sync ─────────────────────────────────────

log "Waiting for mining to produce blocks (up to 120s)"
deadline=$((SECONDS + 120))
while true; do
    m1_height=$(block_height zeicoin-miner-1)
    m2_height=$(block_height zeicoin-miner-2)

    if (( m1_height >= 2 || m2_height >= 2 )); then
        log "  miner-1 height: $m1_height, miner-2 height: $m2_height"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  miner-1 height: $m1_height, miner-2 height: $m2_height"
        fail "Timeout waiting for blocks to be mined"
    fi
    sleep 5
done

# Check node-1 is syncing (should have at least height 1 by now)
sleep 10
n1_height=$(block_height zeicoin-node-1)
log "  node-1 height: $n1_height"
if (( n1_height < 1 )); then
    fail "node-1 not syncing (height=$n1_height)"
fi

# ── Phase 8: Restart/reconnect test ────────────────────────────────

log "Restarting miner-1 (bootstrap node) for reconnect test"
m1_refresh_before_restart=$(refresh_count zeicoin-miner-1)
docker restart zeicoin-miner-1 >/dev/null

log "Waiting for miner-1 to become healthy again (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    if [[ "$(healthy zeicoin-miner-1)" == "healthy" ]]; then
        log "  miner-1 healthy after restart"
        break
    fi
    if (( SECONDS > deadline )); then
        fail "miner-1 did not become healthy after restart"
    fi
    sleep 3
done

log "Waiting for miner-1 to refresh and reconnect to both peers (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m1_routing=$(routing_peers zeicoin-miner-1)
    m1_refreshes=$(refresh_count zeicoin-miner-1)
    if (( m1_peers >= 2 && m1_routing >= 2 && m1_refreshes > m1_refresh_before_restart )); then
        log "  miner-1 after restart — peers=$m1_peers routing_peers=$m1_routing refreshes=$m1_refreshes"
        break
    fi
    if (( SECONDS > deadline )); then
        log "  miner-1 after restart — peers=$m1_peers routing_peers=$m1_routing refreshes=$m1_refreshes"
        fail "miner-1 did not refresh and reconnect to both peers after restart"
    fi
    sleep 3
done

# ── Phase 9: Final summary ─────────────────────────────────────────

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
