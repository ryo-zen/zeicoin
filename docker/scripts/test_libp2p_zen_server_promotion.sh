#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

# test_libp2p_zen_server_promotion.sh — Focused regression harness for ZEI-99
#
# Verifies the specific zen_server runtime issue where non-seed nodes learn each
# other through Kad/identify but fail to promote that knowledge into direct
# transport sessions because candidate dials target ephemeral observed ports.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/tmp/zen-server-promotion-$RUN_ID}"
HOST_ZIG_VERSION="$(zig version)"

CONTAINERS=(zeicoin-miner-1 zeicoin-miner-2 zeicoin-node-1)
NON_SEEDS=(zeicoin-miner-2 zeicoin-node-1)

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
    echo "[zen-promo $(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/test.log"
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

format_peer_count() {
    local count="$1"
    if (( count < 0 )); then
        echo "unknown"
    else
        echo "$count"
    fi
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

log "Building and starting zen_server promotion topology"
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
        break
    fi
    if (( SECONDS > deadline )); then
        fail "Timeout waiting for healthy containers"
    fi
    sleep 3
done

log "Waiting for stable direct non-seed session promotion (up to 180s)"
deadline=$((SECONDS + 180))
stable_successes=0
while true; do
    m2_peers=$(peer_count zeicoin-miner-2)
    n1_peers=$(peer_count zeicoin-node-1)
    log "  miner-2 peers=$(format_peer_count "$m2_peers") node-1 peers=$(format_peer_count "$n1_peers")"
    if (( m2_peers >= 2 && n1_peers >= 2 )); then
        stable_successes=$((stable_successes + 1))
        if (( stable_successes >= 2 )); then
            break
        fi
    else
        stable_successes=0
    fi
    if (( SECONDS > deadline )); then
        log "  miner-2 routing_peers=$(routing_peers zeicoin-miner-2) kad_addrs=$(kad_addrs zeicoin-miner-2)"
        log "  node-1 routing_peers=$(routing_peers zeicoin-node-1) kad_addrs=$(kad_addrs zeicoin-node-1)"
        fail "Non-seed nodes never promoted Kad discovery into direct transport sessions"
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

save_all_logs

log ""
log "Final state:"
for c in "${CONTAINERS[@]}"; do
    p=$(peer_count "$c")
    r=$(routing_peers "$c")
    k=$(kad_addrs "$c")
    f=$(refresh_count "$c")
    log "  $c — peers=$p routing_peers=$r kad_addrs=$k refreshes=$f"
done

log ""
log "Logs saved to $LOG_DIR"
echo ""
echo "PASS"
