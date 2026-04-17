#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

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

# Check for RocksDB
echo "🔍 Checking for RocksDB..."
rocksdb_found=false
if pkg-config --exists rocksdb 2>/dev/null; then
    rocksdb_found=true
elif [ -f "/usr/lib/librocksdb.so" ] || [ -f "/usr/local/lib/librocksdb.so" ] || [ -f "/usr/lib/librocksdb.a" ]; then
    rocksdb_found=true
fi

if [ "$rocksdb_found" = false ]; then
    echo "📦 RocksDB not found. Installing RocksDB..."
    
    # Detect OS and install RocksDB
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    fi
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        echo "🔧 Installing RocksDB on Ubuntu/Debian..."
        sudo apt update
        sudo apt install -y librocksdb-dev
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]]; then
        echo "🔧 Installing RocksDB on Fedora/CentOS/RHEL..."
        sudo dnf install -y rocksdb-devel || sudo yum install -y rocksdb-devel
    elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
        echo "🔧 Installing RocksDB on Arch Linux..."
        sudo pacman -S --noconfirm rocksdb
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "🔧 Installing RocksDB on macOS..."
        if command -v brew &> /dev/null; then
            brew install rocksdb
        else
            echo "❌ Homebrew not found. Please install Homebrew first:"
            echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
    else
        echo "⚠️  Unknown OS. Please install RocksDB manually:"
        echo "  Ubuntu/Debian: sudo apt install librocksdb-dev"
        echo "  Fedora/CentOS: sudo dnf install rocksdb-devel"
        echo "  Arch Linux: sudo pacman -S rocksdb"
        echo "  macOS: brew install rocksdb"
        echo "  Or build from source: https://github.com/facebook/rocksdb"
        exit 1
    fi
    
    # Verify installation
    if pkg-config --exists rocksdb 2>/dev/null || [ -f "/usr/lib/librocksdb.so" ] || [ -f "/usr/local/lib/librocksdb.so" ]; then
        echo "✅ RocksDB installed successfully!"
    else
        echo "❌ RocksDB installation failed. Please install manually."
        exit 1
    fi
else
    echo "✅ RocksDB already installed!"
fi

if [ -n "$missing_deps" ]; then
    echo "❌ Missing dependencies:$missing_deps"
    echo ""
    echo "🚀 Quick fix - run the dependency installer:"
    echo "  ./scripts/install_dependencies.sh"
    echo ""
    echo "Or install manually:"
    echo "  Ubuntu/Debian: sudo apt update && sudo apt install build-essential cmake git librocksdb-dev"
    echo "  CentOS/RHEL: sudo yum groupinstall 'Development Tools' && sudo yum install cmake git rocksdb-devel"
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

# Create or use existing mining wallet
echo "👛 Setting up mining wallet..."

# Check if we already have a saved miner name
if [ -f ".miner_name" ]; then
    EXISTING_MINER=$(cat .miner_name)
    echo "📝 Found existing miner configuration: $EXISTING_MINER"
    
    # Verify wallet still exists
    if ./zig-out/bin/zeicoin balance "$EXISTING_MINER" > /dev/null 2>&1; then
        MINER_NAME="$EXISTING_MINER"
        echo "✅ Using existing wallet: $MINER_NAME"
    else
        echo "⚠️  Saved wallet '$EXISTING_MINER' not found, creating new one..."
        MINER_NAME=""
    fi
else
    MINER_NAME=""
fi

# Create new wallet if needed
if [ -z "$MINER_NAME" ]; then
    # Generate unique miner name with random number
    RANDOM_ID=$(shuf -i 1000000000-9999999999 -n 1)
    MINER_NAME="miner-$RANDOM_ID"
    
    echo "Creating new wallet '$MINER_NAME' for mining..."
    if ZEICOIN_TEST_MODE=1 ./zig-out/bin/zeicoin wallet create "$MINER_NAME"; then
        echo "✅ $MINER_NAME wallet created!"
        # Save miner name for easy reference
        echo "$MINER_NAME" > .miner_name
        echo "📝 Miner name saved to .miner_name file"
        echo "💡 TestNet wallet created without encryption for easier development"
    else
        echo "❌ Failed to create wallet. Continuing with existing wallets..."
        # Try to find any existing wallet
        if [ -f ".miner_name" ]; then
            MINER_NAME=$(cat .miner_name)
            echo "📝 Using previously saved miner: $MINER_NAME"
        else
            MINER_NAME="alice"  # Fallback to genesis wallet
            echo "📝 Using fallback wallet: $MINER_NAME"
        fi
    fi
fi

# Setup .env configuration
echo "⚙️  Configuring environment..."
if [ -f ".env.testnet" ]; then
    echo "📋 Using existing .env.testnet for server configuration..."
    echo "✅ Environment configuration ready!"
elif [ -f ".env.example" ]; then
    echo "📋 Copying .env.example to .env.testnet..."
    cp .env.example .env.testnet
    echo "⚠️  Please edit .env.testnet with your specific configuration"
else
    echo "⚠️  No .env.testnet or .env.example found - manual configuration needed"
fi

# Ensure test mode is enabled in .env.testnet for systemd service
if [ -f ".env.testnet" ] && [ -n "$MINER_NAME" ]; then
    echo "🔧 Ensuring test mode is enabled in .env.testnet for systemd service..."
    # Make sure ZEICOIN_TEST_MODE=1 is set (should already be there from .env.testnet)
    if ! grep -q "ZEICOIN_TEST_MODE=1" .env.testnet; then
        echo "" >> .env.testnet
        echo "# Test mode for systemd service (no password required)" >> .env.testnet
        echo "ZEICOIN_TEST_MODE=1" >> .env.testnet
    fi
    echo "✅ Test mode configured for systemd service"
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
echo "Mining wallet created: $MINER_NAME"
echo "  ./zig-out/bin/zeicoin balance $MINER_NAME"
echo "  ./zig-out/bin/zeicoin address $MINER_NAME"
echo ""
echo "Start server with mining:"
echo "  ./zig-out/bin/zen_server --mine $MINER_NAME"
echo "  # OR use convenient script: scripts/start_mining.sh"
echo "  # OR use saved name: ./zig-out/bin/zen_server --mine \$(cat .miner_name)"
echo ""
echo "For public server deployment with mining:"
echo "  ZEICOIN_MINER_WALLET=$MINER_NAME scripts/start_zei_server.sh"
echo "  # Your unique miner wallet name: $MINER_NAME"
echo "  # Server will auto-detect public IP and start RandomX mining"
echo ""
# Create systemd service for production deployment
if command -v systemctl &> /dev/null; then
    echo "🔧 Creating systemd service..."
    
    CURRENT_DIR=$(pwd)
    
    sudo tee /etc/systemd/system/zeicoin-mining.service > /dev/null <<EOF
[Unit]
Description=ZeiCoin Mining Server ($MINER_NAME)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$CURRENT_DIR
EnvironmentFile=$CURRENT_DIR/.env.testnet
EnvironmentFile=-$CURRENT_DIR/.env.local
Environment="ZEICOIN_SERVER=127.0.0.1"
Environment="ZEICOIN_BIND_IP=0.0.0.0"
Environment="ZEICOIN_MINE_ENABLED=true"
Environment="ZEICOIN_MINER_WALLET=$MINER_NAME"
ExecStart=$CURRENT_DIR/zig-out/bin/zen_server --mine $MINER_NAME
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
    echo "⚠️  Service is created but not started - you control when mining begins"
    
    echo ""
    echo "Service management:"
    echo "  sudo systemctl start zeicoin-mining.service     # Start service"
    echo "  sudo systemctl status zeicoin-mining.service    # Check status"
    echo "  sudo journalctl -u zeicoin-mining.service -f    # View logs"
fi
