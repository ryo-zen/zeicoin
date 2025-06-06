#!/bin/bash
# setup.sh - One-time setup script for ZeiCoin

set -e

echo "🚀 ZeiCoin Setup Script"
echo "======================"

# Check if we're in the right directory
if [ ! -f "main.zig" ]; then
    echo "❌ Please run this script from the ZeiCoin root directory"
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
    echo "On Ubuntu/Debian, install with:"
    echo "  sudo apt update"
    echo "  sudo apt install build-essential cmake git"
    echo ""
    echo "For Zig, download from: https://ziglang.org/download/"
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
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="../randomx_install"
    make -j$(nproc)
    make install
    
    cd ../../../..
    
    # Build RandomX helper (now back to project root)
    echo "🔗 Building RandomX helper..."
    gcc -o randomx/randomx_helper randomx/randomx_helper.c randomx/wrapper.c \
        -Irandomx/randomx_build/RandomX/randomx_install/include \
        -Lrandomx/randomx_build/RandomX/randomx_install/lib -lrandomx -lstdc++ -lm
    
    echo "✅ RandomX built successfully!"
else
    echo "✅ RandomX already built!"
fi

# Build ZeiCoin
echo "🔨 Building ZeiCoin..."
zig build

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Quick start:"
echo "  make server     # Start mining server"
echo "  make help       # Show all commands"
echo ""
echo "Create your first wallet:"
echo "  ./zig-out/bin/zeicoin wallet create mywallet"
echo "  ./zig-out/bin/zeicoin balance mywalletlist"