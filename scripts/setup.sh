#!/bin/bash
# setup.sh - One-time setup script for ZeiCoin

set -e

echo "🚀 ZeiCoin Setup Script"
echo "======================"

# Check if we're in the right directory
if [ ! -f "src/apps/main.zig" ] || [ ! -f "build.zig" ]; then
    echo "❌ Please run this script from the ZeiCoin root directory"
    echo "   (Should contain src/apps/main.zig and build.zig)"
    exit 1
fi

# Check dependencies
echo "🔍 Checking dependencies..."
missing_deps=""

if ! command -v git &> /dev/null; then
    missing_deps="$missing_deps git"
fi

if ! command -v cmake &> /dev/null; then
    missing_deps="$missing_deps cmake"
fi

if ! command -v make &> /dev/null; then
    missing_deps="$missing_deps make"
fi

if ! command -v gcc &> /dev/null; then
    missing_deps="$missing_deps gcc"
fi

if ! command -v zig &> /dev/null; then
    missing_deps="$missing_deps zig"
fi

if [ -n "$missing_deps" ]; then
    echo "❌ Missing dependencies:$missing_deps"
    echo ""
    echo "🚀 Quick fix - run the dependency installer:"
    echo "  ./scripts/install_dependencies.sh"
    echo ""
    echo "Or install manually:"
    echo "  Ubuntu/Debian: sudo apt update && sudo apt install build-essential cmake git"
    echo "  CentOS/RHEL: sudo yum groupinstall 'Development Tools' && sudo yum install cmake git"
    echo "  For Zig: Download from https://ziglang.org/download/"
    exit 1
fi

echo "✅ All dependencies found!"

# Build RandomX if needed
if [ ! -f "randomx/randomx_helper" ] || [ ! -f "randomx/randomx_install/lib/librandomx.a" ]; then
    echo "🔧 Building RandomX (this may take a few minutes)..."
    
    # Create directories
    mkdir -p randomx/randomx_build
    cd randomx/randomx_build
    
    # Download RandomX if not exists
    if [ ! -d "RandomX" ]; then
        echo "📥 Downloading RandomX v1.2.1..."
        git clone https://github.com/tevador/RandomX.git
        cd RandomX
        git checkout v1.2.1
        cd ..
    fi
    
    # Build RandomX
    cd RandomX
    mkdir -p build
    cd build
    
    echo "🛠️  Compiling RandomX library..."
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="../../randomx_install"
    make -j$(nproc)
    make install
    
    cd ../../../..
    
    # Build RandomX helper (now back to project root)
    echo "🔗 Building RandomX helper..."
    gcc -o randomx/randomx_helper randomx/randomx_helper.c randomx/wrapper.c \
        -Irandomx/randomx_build/randomx_install/include \
        -Lrandomx/randomx_build/randomx_install/lib -lrandomx -lstdc++ -lm
    
    echo "✅ RandomX built successfully!"
else
    echo "✅ RandomX already built!"
fi

# Build ZeiCoin (Release mode for RandomX mining)
echo "🔨 Building ZeiCoin (Release mode)..."
zig build -Doptimize=ReleaseFast

# Create mining wallet
echo "👛 Creating mining wallet..."
if [ ! -d "wallets" ]; then
    mkdir -p wallets
fi

# Create Alice wallet if it doesn't exist
if [ ! -f "wallets/Alice.wallet" ]; then
    echo "Creating 'Alice' wallet for mining..."
    ./zig-out/bin/zeicoin wallet create Alice
    echo "✅ Alice wallet created!"
else
    echo "✅ Alice wallet already exists"
fi

# Configure firewall for ZeiCoin ports
echo "🔥 Configuring firewall..."
if command -v ufw &> /dev/null; then
    # UFW (Ubuntu/Debian)
    sudo ufw allow 10800/udp comment "ZeiCoin UDP Discovery"
    sudo ufw allow 10801/tcp comment "ZeiCoin P2P"
    sudo ufw allow 10802/tcp comment "ZeiCoin Client API"
    sudo ufw allow 10803/tcp comment "ZeiCoin Metrics"
    echo "✅ UFW firewall configured"
elif command -v firewall-cmd &> /dev/null; then
    # firewalld (CentOS/RHEL)
    sudo firewall-cmd --permanent --add-port=10800/udp
    sudo firewall-cmd --permanent --add-port=10801/tcp
    sudo firewall-cmd --permanent --add-port=10802/tcp
    sudo firewall-cmd --permanent --add-port=10803/tcp
    sudo firewall-cmd --reload
    echo "✅ Firewalld configured"
else
    echo "⚠️  No firewall detected - manually open ports: 10800/udp, 10801/tcp, 10802/tcp, 10803/tcp"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Quick start:"
echo "  scripts/start_zei_server.sh    # Start public server"
echo "  zig build test                 # Run all tests"
echo ""
echo "Mining wallet created: Alice"
echo "  ./zig-out/bin/zeicoin balance Alice"
echo "  ./zig-out/bin/zeicoin address Alice"
echo ""
echo "Start server with mining:"
echo "  ./zig-out/bin/zen_server --mine Alice"
echo ""
echo "For public server deployment with mining:"
echo "  ZEICOIN_MINER_WALLET=ryo scripts/start_zei_server.sh"
echo "  # Replace 'ryo' with your wallet name"
echo "  # Server will auto-detect public IP and start RandomX mining"
echo ""
# Create systemd service for production deployment
if command -v systemctl &> /dev/null; then
    echo "🔧 Creating systemd service..."
    
    CURRENT_DIR=$(pwd)
    
    sudo tee /etc/systemd/system/zeicoin-mining.service > /dev/null <<EOF
[Unit]
Description=ZeiCoin Mining Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$CURRENT_DIR
Environment="ZEICOIN_SERVER=127.0.0.1"
Environment="ZEICOIN_BIND_IP=0.0.0.0"
ExecStart=$CURRENT_DIR/zig-out/bin/zen_server --mine Alice
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable zeicoin-mining.service
    
    echo "✅ Systemd service created and enabled!"
    
    # Test the service
    echo "🧪 Testing service configuration..."
    if sudo systemctl start zeicoin-mining.service; then
        sleep 3
        if sudo systemctl is-active --quiet zeicoin-mining.service; then
            echo "✅ Service started successfully!"
            sudo systemctl stop zeicoin-mining.service
        else
            echo "❌ Service failed to start - check logs: sudo journalctl -u zeicoin-mining.service"
        fi
    else
        echo "❌ Service failed to start - check configuration"
    fi
    
    echo ""
    echo "Service management:"
    echo "  sudo systemctl start zeicoin-mining.service     # Start service"
    echo "  sudo systemctl status zeicoin-mining.service    # Check status"
    echo "  sudo journalctl -u zeicoin-mining.service -f    # View logs"
fi