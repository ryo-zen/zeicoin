#!/bin/bash
# start_zeicoin_server.sh - Start ZeiCoin server (server.zig)

echo "🚀 ZeiCoin Server Startup"
echo "========================="

# Check if zig is installed
if ! command -v zig &> /dev/null; then
    echo "❌ Zig not found. Please install Zig 0.14.1+ first."
    echo "   Visit: https://ziglang.org/download/"
    exit 1
fi

# Check Zig version
ZIG_VERSION=$(zig version)
echo "🔧 Found Zig version: $ZIG_VERSION"

# Get local IP for display
LOCAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "Unknown")
echo "🌐 Local IP: $LOCAL_IP"
echo "🔌 ZeiCoin ports: 10800 (UDP discovery), 10801 (P2P), 10802 (Client API)"

# Check if ports are available
if netstat -an 2>/dev/null | grep -q ":10801 "; then
    echo "⚠️  Port 10801 already in use. Stopping existing ZeiCoin processes..."
    pkill -f zen_server 2>/dev/null || true
    sleep 2
fi

if netstat -an 2>/dev/null | grep -q ":10802 "; then
    echo "⚠️  Port 10802 already in use. Stopping existing ZeiCoin processes..."
    pkill -f zen_server 2>/dev/null || true
    sleep 2
fi

# Change to ZeiCoin directory and stay there
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

# Create data directory structure
mkdir -p zeicoin_data/{blocks,accounts,wallets}
echo "📁 Created ZeiCoin data directories"

echo ""
echo "🎯 Starting ZeiCoin Server..."
echo "   - P2P Network: $LOCAL_IP:10801"
echo "   - Client API: $LOCAL_IP:10802"
echo "   - Blockchain data: ./zeicoin_data/"
echo "   - Press Ctrl+C to stop"
echo ""

# Build and run server.zig
echo "🔨 Building ZeiCoin server..."
if ! zig build; then
    echo "❌ Build failed! Check your Zig installation and code."
    exit 1
fi

# Check if the executable was actually created
if [ ! -f "./zig-out/bin/zen_server" ]; then
    echo "❌ Build completed but zen_server executable not found!"
    echo "🔍 Checking what was built:"
    ls -la zig-out/bin/ 2>/dev/null || echo "   No zig-out/bin/ directory found"
    echo "🔍 Current directory: $(pwd)"
    echo "🔍 Directory contents:"
    ls -la
    echo ""
    echo "💡 Try running 'zig build --help' to see available targets"
    echo "💡 Or check build.zig for the correct executable name"
    exit 1
fi

echo "🌐 Starting zen blockchain server..."
exec ./zig-out/bin/zen_server