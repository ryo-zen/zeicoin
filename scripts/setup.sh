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

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Quick start:"
echo "  scripts/start_zei_server.sh    # Start public server"
echo "  zig build test                 # Run all tests"
echo ""
echo "Create your first wallet:"
echo "  ./zig-out/bin/zeicoin wallet create mywallet"
echo "  ./zig-out/bin/zeicoin balance mywallet"
echo ""
echo "Start server with mining:"
echo "  ./zig-out/bin/zen_server --mine mywallet"
echo ""
echo "For public server deployment with mining:"
echo "  ZEICOIN_MINER_WALLET=ryo scripts/start_zei_server.sh"
echo "  # Replace 'ryo' with your wallet name"
echo "  # Server will auto-detect public IP and start RandomX mining"