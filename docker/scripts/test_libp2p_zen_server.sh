#!/usr/bin/env bash
# test_libp2p_zen_server.sh — End-to-end Docker validation for ZEI-60
#
# Verifies that zen_server containers connect via libp2p (Noise XX + yamux),
# sync blocks, and recover from a bootstrap node restart.
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

# Extract peer count from `zeicoin status` output inside a container
# Note: zeicoin CLI uses std.debug.print which writes to stderr
peer_count() {
    local container="$1"
    docker exec "$container" \
        env ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin status 2>&1 \
        | sed -n 's/.*Connected Peers:[[:space:]]*\([0-9]*\).*/\1/p' || echo "0"
}

block_height() {
    local container="$1"
    docker exec "$container" \
        env ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin status 2>&1 \
        | sed -n 's/.*Network Height:[[:space:]]*\([0-9]*\).*/\1/p' || echo "0"
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

# ── Phase 3: Verify libp2p markers in logs ──────────────────────────

log "Checking libp2p log markers"
sleep 10  # let connections settle

save_all_logs

# miner-1 (seed) must show Node identity
if ! grep -q "Node identity:" "$LOG_DIR/zeicoin-miner-1.log"; then
    fail "miner-1 missing 'Node identity:' — libp2p not initializing"
fi
log "  miner-1: Node identity present"

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

# ── Phase 4: Verify peer connectivity ──────────────────────────────

log "Waiting for peer connections (up to 60s)"
deadline=$((SECONDS + 60))
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)

    if (( m1_peers >= 1 && m2_peers >= 1 && n1_peers >= 1 )); then
        log "  miner-1: $m1_peers peers, miner-2: $m2_peers peers, node-1: $n1_peers peers"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  miner-1: $m1_peers, miner-2: $m2_peers, node-1: $n1_peers"
        fail "Timeout waiting for peer connections"
    fi
    sleep 5
done

# ── Phase 5: Verify block sync ─────────────────────────────────────

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

# ── Phase 6: Restart/reconnect test ────────────────────────────────

log "Restarting miner-1 (bootstrap node) for reconnect test"
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

log "Waiting for peers to reconnect to miner-1 (up to 60s)"
deadline=$((SECONDS + 60))
while true; do
    m1_peers=$(peer_count zeicoin-miner-1)
    if (( m1_peers >= 1 )); then
        log "  miner-1 has $m1_peers peer(s) after restart"
        break
    fi
    if (( SECONDS > deadline )); then
        fail "No peers reconnected to miner-1 after restart (peers=$m1_peers)"
    fi
    sleep 5
done

# ── Phase 7: Final summary ─────────────────────────────────────────

save_all_logs

log ""
log "Final state:"
for c in "${CONTAINERS[@]}"; do
    p=$(peer_count "$c")
    h=$(block_height "$c")
    log "  $c — peers=$p height=$h"
done

log ""
log "Logs saved to $LOG_DIR"
echo ""
echo "PASS"
