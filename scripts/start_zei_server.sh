#!/bin/bash
# start_zei_server.sh - Start ZeiCoin server for public deployment
# Supports both local development and public server deployment

echo "🚀 ZeiCoin Server Startup"
echo "========================="
echo ""
echo "💡 To start mining to a specific wallet, use:"
echo "   ZEICOIN_MINER_WALLET=ryo scripts/start_zei_server.sh"
echo "   (Replace 'ryo' with your wallet name)"
echo ""

# Check if zig is installed
if ! command -v zig &> /dev/null; then
    echo "❌ Zig not found. Please install Zig 0.14.1+ first."
    echo "   Visit: https://ziglang.org/download/"
    exit 1
fi

# Check Zig version
ZIG_VERSION=$(zig version)
echo "🔧 Found Zig version: $ZIG_VERSION"

# Determine server binding IP
if [ -n "$ZEICOIN_BIND_IP" ]; then
    BIND_IP="$ZEICOIN_BIND_IP"
    echo "🌐 Using configured bind IP: $BIND_IP"
else
    # Auto-detect: try public IP, fallback to local IP
    PUBLIC_IP=$(curl -s http://ipinfo.io/ip 2>/dev/null || echo "")
    LOCAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")
    
    if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "$LOCAL_IP" ]; then
        BIND_IP="$PUBLIC_IP"
        echo "🌐 Auto-detected public IP: $PUBLIC_IP (local: $LOCAL_IP)"
        # Export for server process
        export ZEICOIN_BIND_IP="$BIND_IP"
    else
        BIND_IP="$LOCAL_IP"
        echo "🌐 Using local IP: $LOCAL_IP"
        # Export for server process
        export ZEICOIN_BIND_IP="$BIND_IP"
    fi
fi

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

# Create data directory structure for both networks
# The server will use the appropriate one based on CURRENT_NETWORK in types.zig
mkdir -p zeicoin_data_testnet/{blocks,accounts,wallets}
mkdir -p zeicoin_data_mainnet/{blocks,accounts,wallets}
echo "📁 Created ZeiCoin data directories (testnet and mainnet)"

echo ""
echo "🎯 Starting ZeiCoin Server..."
echo "   - P2P Network: $BIND_IP:10801"
echo "   - Client API: $BIND_IP:10802"
echo "   - UDP Discovery: $BIND_IP:10800"
echo "   - Blockchain data: ./zeicoin_data_testnet/ or ./zeicoin_data_mainnet/"
echo "   - Active network determined by types.zig CURRENT_NETWORK setting"
echo "   - Press Ctrl+C to stop"
echo ""

# Show network configuration advice for public servers
if [ "$BIND_IP" != "127.0.0.1" ] && [ "$BIND_IP" != "localhost" ]; then
    echo "🔒 Public Server Configuration:"
    echo "   - Ensure firewall allows ports 10800-10802"
    echo "   - Consider running behind reverse proxy for API (10802)"
    echo "   - Monitor server resources and connections"
    echo ""
fi

# Build and run server (Release mode for RandomX mining)
echo "🔨 Building ZeiCoin server (Release mode)..."
if ! zig build -Doptimize=ReleaseFast; then
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

echo "🌐 Starting ZeiCoin blockchain server..."
echo "   - Bind IP: $BIND_IP"
echo "   - Build mode: Production (RandomX mining)"
echo ""

# Mining wallet setup
MINER_WALLET=""
if [ -n "$ZEICOIN_MINER_WALLET" ]; then
    MINER_WALLET="$ZEICOIN_MINER_WALLET"
    echo "🔧 Using wallet from environment: $MINER_WALLET"
else
    echo ""
    echo "⛏️  MINING SETUP"
    echo "==============="
    echo "To enable mining, you need to specify a wallet name."
    echo "This wallet will receive all mining rewards."
    echo ""
    
    # Prompt for wallet name
    while [ -z "$MINER_WALLET" ]; do
        echo -n "Enter wallet name for mining (or 'skip' to run without mining): "
        read -r wallet_input
        
        if [ "$wallet_input" = "skip" ]; then
            echo "⏭️  Skipping mining setup - server will run without mining"
            break
        elif [ -n "$wallet_input" ]; then
            MINER_WALLET="$wallet_input"
            echo "✅ Selected wallet: $MINER_WALLET"
        else
            echo "❌ Please enter a valid wallet name or 'skip'"
        fi
    done
fi

# Create wallet if it doesn't exist and mining is enabled
if [ -n "$MINER_WALLET" ]; then
    echo ""
    echo "🔍 Checking if wallet '$MINER_WALLET' exists..."
    
    # Check if wallet file exists
    if [ -f "zeicoin_data_testnet/wallets/$MINER_WALLET.wallet" ] || [ -f "zeicoin_data_mainnet/wallets/$MINER_WALLET.wallet" ]; then
        echo "✅ Wallet '$MINER_WALLET' found"
    else
        echo "❌ Wallet '$MINER_WALLET' not found"
        echo ""
        echo "Would you like to create a new wallet named '$MINER_WALLET'?"
        echo -n "Type 'yes' to create, 'no' to cancel, or 'skip' to run without mining: "
        read -r create_choice
        
        case "$create_choice" in
            yes|y|Y|YES)
                echo ""
                echo "📝 Creating new wallet '$MINER_WALLET'..."
                
                # Create the wallet directory if it doesn't exist
                mkdir -p zeicoin_data_testnet/wallets zeicoin_data_mainnet/wallets
                
                # Create the wallet using the CLI (works offline)
                if ./zig-out/bin/zeicoin wallet create "$MINER_WALLET"; then
                    echo "✅ Wallet '$MINER_WALLET' created successfully!"
                    echo "💡 After the server starts, you can fund this wallet with:"
                    echo "   ZEICOIN_SERVER=$BIND_IP ./zig-out/bin/zeicoin fund $MINER_WALLET"
                    echo ""
                else
                    echo "❌ Failed to create wallet '$MINER_WALLET'"
                    echo "💡 You can create it manually with: ./zig-out/bin/zeicoin wallet create $MINER_WALLET"
                    exit 1
                fi
                ;;
            skip|s|S|SKIP)
                echo "⏭️  Skipping mining setup - server will run without mining"
                MINER_WALLET=""
                ;;
            *)
                echo "❌ Cancelled - wallet '$MINER_WALLET' not created"
                echo "💡 Create the wallet manually with: ./zig-out/bin/zeicoin wallet create $MINER_WALLET"
                echo "💡 Or run this script again"
                exit 1
                ;;
        esac
    fi
fi

# Add server startup options
SERVER_ARGS=""
if [ -n "$MINER_WALLET" ]; then
    SERVER_ARGS="--mine $MINER_WALLET"
    echo "⛏️  Mining enabled with wallet: $MINER_WALLET"
else
    echo "⏭️  Mining disabled - server will run without mining"
fi

if [ -n "$ZEICOIN_BOOTSTRAP" ]; then
    SERVER_ARGS="$SERVER_ARGS --bootstrap $ZEICOIN_BOOTSTRAP"
    echo "🔗 Bootstrap nodes: $ZEICOIN_BOOTSTRAP"
fi

echo "Starting server with args: $SERVER_ARGS"
echo "🌐 Server will bind to: $BIND_IP"
exec ./zig-out/bin/zen_server $SERVER_ARGS