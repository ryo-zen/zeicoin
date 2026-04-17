#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

# test_libp2p_kad_smoke.sh — Dedicated Docker smoke for the isolated Kad testnode
#
# Verifies that four libp2p testnodes running /kad/1.0.0 can:
# - bootstrap from a single seed
# - discover the other non-seed peers via Kad
# - retain direct non-seed connectivity after the seed stops

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/libp2p/docker/docker-compose.libp2p-test.yml"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/tmp/libp2p-kad-docker-$RUN_ID}"
HOST_ZIG_VERSION="$(zig version)"

CONTAINERS=(libp2p-seed libp2p-node-1 libp2p-node-2 libp2p-node-3)
NON_SEED_CONTAINERS=(libp2p-node-1 libp2p-node-2 libp2p-node-3)

mkdir -p "$(dirname "$LOG_DIR")" "$LOG_DIR"

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
    mkdir -p "$(dirname "$LOG_DIR")" "$LOG_DIR"
    echo "[kad-docker $(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/test.log"
}

container_logs() {
    docker logs "$1" 2>&1
}

save_all_logs() {
    mkdir -p "$(dirname "$LOG_DIR")" "$LOG_DIR"
    for c in "${CONTAINERS[@]}"; do
        container_logs "$c" > "$LOG_DIR/$c.log" 2>&1 || true
    done
}

healthy() {
    docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "missing"
}

running() {
    docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo "false"
}

last_metric() {
    local container="$1"
    local key="$2"
    container_logs "$container" \
        | sed -n "s/.*kad_status: .*${key}=\([0-9]*\).*/\1/p" \
        | tail -n1
}

routing_peers() {
    local value
    value="$(last_metric "$1" "routing_peers")"
    echo "${value:-0}"
}

outbound_sessions() {
    local value
    value="$(last_metric "$1" "outbound_sessions")"
    echo "${value:-0}"
}

live_sessions() {
    local value
    value="$(last_metric "$1" "live_sessions")"
    echo "${value:-0}"
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

log "Building and starting Kad testnode cluster"
compose up -d --build 2>&1 | tail -5

log "Waiting for all Kad containers to become healthy (up to 180s)"
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
        log "All Kad containers healthy"
        break
    fi
    if (( SECONDS > deadline )); then
        for c in "${CONTAINERS[@]}"; do
            log "  $c: $(healthy "$c")"
        done
        fail "Timeout waiting for healthy Kad containers"
    fi
    sleep 3
done

log "Waiting for all nodes to discover the full 4-node topology (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
    seed_peers="$(routing_peers libp2p-seed)"
    n1_peers="$(routing_peers libp2p-node-1)"
    n2_peers="$(routing_peers libp2p-node-2)"
    n3_peers="$(routing_peers libp2p-node-3)"

    if (( seed_peers >= 3 && n1_peers >= 3 && n2_peers >= 3 && n3_peers >= 3 )); then
        log "  seed=$seed_peers node-1=$n1_peers node-2=$n2_peers node-3=$n3_peers"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  seed=$seed_peers node-1=$n1_peers node-2=$n2_peers node-3=$n3_peers"
        fail "Timeout waiting for Kad discovery convergence"
    fi
    sleep 3
done

log "Stopping the bootstrap seed to confirm non-seed sessions survive"
docker stop libp2p-seed >/dev/null

log "Waiting for each non-seed node to retain at least one live non-seed session (up to 45s)"
deadline=$((SECONDS + 45))
while true; do
    n1_sessions="$(live_sessions libp2p-node-1)"
    n2_sessions="$(live_sessions libp2p-node-2)"
    n3_sessions="$(live_sessions libp2p-node-3)"
    total_sessions=$((n1_sessions + n2_sessions + n3_sessions))

    all_running=1
    for c in "${NON_SEED_CONTAINERS[@]}"; do
        if [[ "$(running "$c")" != "true" ]]; then
            all_running=0
            break
        fi
    done

    if (( all_running && n1_sessions >= 1 && n2_sessions >= 1 && n3_sessions >= 1 )); then
        log "  node-1 live_sessions=$n1_sessions node-2 live_sessions=$n2_sessions node-3 live_sessions=$n3_sessions total=$total_sessions"
        break
    fi

    if (( SECONDS > deadline )); then
        log "  node-1 live_sessions=$n1_sessions node-2 live_sessions=$n2_sessions node-3 live_sessions=$n3_sessions total=$total_sessions"
        fail "One or more non-seed nodes lost all live peer sessions after seed shutdown"
    fi
    sleep 3
done

save_all_logs

log ""
log "Final state:"
for c in "${NON_SEED_CONTAINERS[@]}"; do
    log "  $c — routing_peers=$(routing_peers "$c") outbound_sessions=$(outbound_sessions "$c") live_sessions=$(live_sessions "$c")"
done
log "  libp2p-seed — stopped intentionally"
log ""
log "Logs saved to $LOG_DIR"
echo ""
echo "PASS"
