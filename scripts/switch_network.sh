#!/bin/bash
# switch_network.sh - Helper script to switch between TestNet and MainNet

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <testnet|mainnet>"
    echo ""
    echo "Current network configuration:"
    grep "CURRENT_NETWORK:" types.zig
    exit 1
fi

NETWORK=$1

case $NETWORK in
    testnet)
        echo "🔧 Switching to TestNet..."
        sed -i 's/pub const CURRENT_NETWORK: NetworkType = .[a-z]*/pub const CURRENT_NETWORK: NetworkType = .testnet/' types.zig
        echo "✅ Switched to TestNet"
        echo "   - 1 byte difficulty (fast mining)"
        echo "   - Light RandomX mode (256MB RAM)"
        echo "   - 10 second block time"
        echo "   - 1 ZEI block reward"
        echo "   - Data directory: zeicoin_data_testnet/"
        ;;
    mainnet)
        echo "🔧 Switching to MainNet..."
        sed -i 's/pub const CURRENT_NETWORK: NetworkType = .[a-z]*/pub const CURRENT_NETWORK: NetworkType = .mainnet/' types.zig
        echo "✅ Switched to MainNet"
        echo "   - 2 byte difficulty (secure mining)"
        echo "   - Fast RandomX mode (2GB RAM)"
        echo "   - 2 minute block time"
        echo "   - 0.5 ZEI block reward"
        echo "   - Data directory: zeicoin_data_mainnet/"
        ;;
    *)
        echo "❌ Invalid network: $NETWORK"
        echo "Use 'testnet' or 'mainnet'"
        exit 1
        ;;
esac

echo ""
echo "🔨 Rebuilding with new configuration..."
zig build

echo ""
echo "📋 New configuration:"
echo "Network: $NETWORK"
echo ""
echo "To start server with new settings:"
echo "  make server"