#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

# Simple test to verify peer connection and handshake exchange

set -e

echo "🤝 Testing Peer Connection & Handshake"
echo "======================================"

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    pkill -f zen_server || true
    sleep 2
    rm -rf test_node1_data test_node2_data
}

trap cleanup EXIT

# Clean start
cleanup

echo ""
echo "📦 Building..."
zig build -Doptimize=ReleaseFast || { echo "❌ Build failed"; exit 1; }

echo ""
echo "🚀 Starting Node 1 (port 12801)..."
ZEICOIN_SERVER=127.0.0.1 \
ZEICOIN_BIND_IP=127.0.0.1 \
ZEICOIN_P2P_PORT=12801 \
ZEICOIN_CLIENT_PORT=12802 \
ZEICOIN_RPC_PORT=12803 \
ZEICOIN_BOOTSTRAP="" \
ZEICOIN_DATA_DIR=test_node1_data \
ZEICOIN_MINE_ENABLED=false \
./zig-out/bin/zen_server > node1.log 2>&1 &
NODE1_PID=$!

sleep 3

if ! kill -0 $NODE1_PID 2>/dev/null; then
    echo "❌ Node 1 failed to start or died immediately"
    echo "Log contents:"
    cat node1.log
    exit 1
fi

# Double check it's still alive
sleep 1
if ! kill -0 $NODE1_PID 2>/dev/null; then
    echo "❌ Node 1 died after starting"
    echo "Log contents:"
    cat node1.log
    exit 1
fi

echo "✅ Node 1 started and running (PID: $NODE1_PID)"

echo ""
echo "🚀 Starting Node 2 (port 12901, connecting to Node 1)..."
ZEICOIN_SERVER=127.0.0.1 \
ZEICOIN_BIND_IP=127.0.0.1 \
ZEICOIN_P2P_PORT=12901 \
ZEICOIN_CLIENT_PORT=12902 \
ZEICOIN_RPC_PORT=12903 \
ZEICOIN_DATA_DIR=test_node2_data \
ZEICOIN_BOOTSTRAP=/ip4/127.0.0.1/tcp/12801 \
ZEICOIN_MINE_ENABLED=false \
./zig-out/bin/zen_server > node2.log 2>&1 &
NODE2_PID=$!

sleep 3

if ! kill -0 $NODE2_PID 2>/dev/null; then
    echo "❌ Node 2 failed to start or died immediately"
    echo "Log contents:"
    cat node2.log
    exit 1
fi

# Double check it's still alive
sleep 1
if ! kill -0 $NODE2_PID 2>/dev/null; then
    echo "❌ Node 2 died after starting"
    echo "Log contents:"
    cat node2.log
    exit 1
fi

echo "✅ Node 2 started and running (PID: $NODE2_PID)"

echo ""
echo "⏳ Waiting 5 seconds for peer connection..."
sleep 5

echo ""
echo "📊 Checking Node 1 logs for handshake..."
test_failed=0
if grep -q "🤝 \[HANDSHAKE\] Received from peer" node1.log; then
    echo "✅ Node 1 RECEIVED handshake from Node 2"
else
    echo "❌ Node 1 did NOT receive handshake"
    test_failed=1
    echo ""
    echo "Node 1 relevant logs:"
    grep -E "Peer.*connected|Sending handshake|HANDSHAKE|onPeerConnected" node1.log || echo "  (no relevant logs)"
fi

echo ""
echo "📊 Checking Node 2 logs for handshake..."
if grep -q "🤝 \[HANDSHAKE\] Received from peer" node2.log; then
    echo "✅ Node 2 RECEIVED handshake from Node 1"
else
    echo "❌ Node 2 did NOT receive handshake"
    test_failed=1
    echo ""
    echo "Node 2 relevant logs:"
    grep -E "Peer.*connected|Sending handshake|HANDSHAKE|onPeerConnected" node2.log || echo "  (no relevant logs)"
fi

echo ""
echo "📊 Checking for onPeerConnected calls..."
if grep -q "👥 \[PEER CONNECT\]" node1.log; then
    echo "✅ Node 1 called onPeerConnected"
else
    echo "❌ Node 1 did NOT call onPeerConnected"
    test_failed=1
fi

if grep -q "👥 \[PEER CONNECT\]" node2.log; then
    echo "✅ Node 2 called onPeerConnected"
else
    echo "❌ Node 2 did NOT call onPeerConnected"
    test_failed=1
fi

echo ""
echo "📋 Full Node 1 log:"
echo "===================="
cat node1.log

echo ""
echo "📋 Full Node 2 log:"
echo "===================="
cat node2.log

echo ""
if [[ $test_failed -ne 0 ]]; then
    echo "❌ Handshake test failed"
    exit 1
fi

echo "✅ Handshake test passed"
