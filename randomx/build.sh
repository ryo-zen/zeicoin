#!/bin/bash

# build_randomx.sh - Build RandomX library for Zeicoin integration
# This script downloads, builds, and installs RandomX for the demo

set -e  # Exit on any error

echo "🚀 Building RandomX for Zeicoin Integration"
echo "==========================================="

# Configuration
RANDOMX_VERSION="v1.2.1"
BUILD_DIR="./randomx_build"
INSTALL_PREFIX="$PWD/randomx_install"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v git &> /dev/null; then
        log_error "git is required but not installed"
        exit 1
    fi
    
    if ! command -v cmake &> /dev/null; then
        log_error "cmake is required but not installed"
        log_info "Install with: sudo apt install cmake"
        exit 1
    fi
    
    if ! command -v make &> /dev/null; then
        log_error "make is required but not installed"
        log_info "Install with: sudo apt install build-essential"
        exit 1
    fi
    
    if ! command -v g++ &> /dev/null; then
        log_error "g++ is required but not installed"
        log_info "Install with: sudo apt install build-essential"
        exit 1
    fi
    
    log_info "All dependencies found!"
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    rm -rf "$BUILD_DIR"
    rm -rf "$INSTALL_PREFIX"
}

# Download RandomX
download_randomx() {
    log_info "Downloading RandomX $RANDOMX_VERSION..."
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    git clone https://github.com/tevador/RandomX.git
    cd RandomX
    git checkout "$RANDOMX_VERSION"
    
    log_info "RandomX downloaded successfully"
}

# Build RandomX
build_randomx() {
    log_info "Building RandomX..."
    
    if [ ! -d "$BUILD_DIR/RandomX" ]; then
        log_error "RandomX source directory not found at $BUILD_DIR/RandomX"
        return 1
    fi
    
    cd "$BUILD_DIR/RandomX"
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure with cmake
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
    
    # Build
    make -j$(nproc)
    
    # Install
    make install
    
    log_info "RandomX built and installed successfully"
}

# Main execution
main() {
    log_info "Starting RandomX build process..."
    
    check_dependencies
    clean_build
    download_randomx
    build_randomx
    
    log_info "RandomX build completed successfully!"
    log_info "Library installed to: $INSTALL_PREFIX"
    log_info "You can now build the ZeiCoin RandomX demo"
}

# Run main function
main "$@"