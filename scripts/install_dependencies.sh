#!/bin/bash
# install_dependencies.sh - Install all ZeiCoin server dependencies
# Supports Ubuntu/Debian, CentOS/RHEL, and other Linux distributions

set -e

echo "🔧 ZeiCoin Dependency Installation Script"
echo "========================================="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "🐧 Detected OS: $OS $VERSION"

# Update package manager
echo "📦 Updating package manager..."
case $OS in
    ubuntu|debian)
        sudo apt update
        ;;
    centos|rhel|fedora)
        if command -v dnf &> /dev/null; then
            sudo dnf update -y
        else
            sudo yum update -y
        fi
        ;;
    arch)
        sudo pacman -Sy
        ;;
    *)
        echo "⚠️  Unknown OS. Attempting generic installation..."
        ;;
esac

# Install core development tools
echo "🛠️  Installing core development tools..."
case $OS in
    ubuntu|debian)
        sudo apt install -y \
            build-essential \
            cmake \
            git \
            curl \
            wget \
            unzip \
            pkg-config \
            libc6-dev \
            linux-headers-generic \
            ca-certificates
        ;;
    centos|rhel)
        if command -v dnf &> /dev/null; then
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y cmake git curl wget unzip pkgconfig glibc-devel kernel-headers ca-certificates
        else
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y cmake git curl wget unzip pkgconfig glibc-devel kernel-headers ca-certificates
        fi
        ;;
    fedora)
        sudo dnf groupinstall -y "C Development Tools and Libraries"
        sudo dnf install -y cmake git curl wget unzip pkgconfig glibc-devel kernel-headers ca-certificates
        ;;
    arch)
        sudo pacman -S --noconfirm base-devel cmake git curl wget unzip pkgconfig linux-headers ca-certificates
        ;;
    *)
        echo "❌ Unsupported OS for automatic installation. Please install manually:"
        echo "   - build-essential/development tools"
        echo "   - cmake, git, curl, wget"
        echo "   - C compiler (gcc/clang)"
        exit 1
        ;;
esac

# Install Zig
echo "⚡ Installing Zig programming language..."
ZIG_VERSION="0.14.1"
ZIG_TARBALL="zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
ZIG_DIR="zig-x86_64-linux-${ZIG_VERSION}"
INSTALL_PATH="/opt/zig-${ZIG_VERSION}"
SYMLINK="/usr/local/bin/zig"

# Check if Zig is already installed
if command -v zig &> /dev/null; then
    CURRENT_VERSION=$(zig version)
    if [ "$CURRENT_VERSION" = "$ZIG_VERSION" ]; then
        echo "✅ Zig $ZIG_VERSION already installed"
    else
        echo "⚠️  Zig $CURRENT_VERSION found, upgrading to $ZIG_VERSION..."
        sudo rm -f "$SYMLINK"
    fi
else
    echo "📥 Downloading Zig $ZIG_VERSION..."
fi

if [ ! -f "$SYMLINK" ] || [ "$(zig version 2>/dev/null)" != "$ZIG_VERSION" ]; then
    # Download and install Zig
    cd /tmp
    wget -q "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TARBALL}"
    
    echo "📦 Extracting Zig..."
    tar -xf "${ZIG_TARBALL}"
    
    echo "🏗️  Installing Zig to $INSTALL_PATH..."
    sudo rm -rf "${INSTALL_PATH}" 2>/dev/null || true
    sudo mv "${ZIG_DIR}" "${INSTALL_PATH}"
    
    echo "🔗 Creating symlink..."
    sudo ln -sf "${INSTALL_PATH}/zig" "${SYMLINK}"
    
    echo "🧹 Cleaning up..."
    rm "${ZIG_TARBALL}"
    
    cd - > /dev/null
fi

# Install RocksDB
echo "🗄️  Installing RocksDB database..."
case $OS in
    ubuntu|debian)
        sudo apt install -y librocksdb-dev
        ;;
    centos|rhel)
        if command -v dnf &> /dev/null; then
            sudo dnf install -y rocksdb-devel
        else
            # For older CentOS/RHEL, might need EPEL
            sudo yum install -y epel-release
            sudo yum install -y rocksdb-devel
        fi
        ;;
    fedora)
        sudo dnf install -y rocksdb-devel
        ;;
    arch)
        sudo pacman -S --noconfirm rocksdb
        ;;
    *)
        echo "⚠️  Please install RocksDB manually for your OS"
        echo "   Ubuntu/Debian: sudo apt install librocksdb-dev"
        echo "   Fedora/CentOS: sudo dnf install rocksdb-devel"
        echo "   Arch Linux: sudo pacman -S rocksdb"
        ;;
esac

# Verify RocksDB installation
if pkg-config --exists rocksdb 2>/dev/null || [ -f "/usr/lib/librocksdb.so" ] || [ -f "/usr/local/lib/librocksdb.so" ]; then
    echo "✅ RocksDB installed successfully!"
else
    echo "⚠️  RocksDB installation verification failed, but continuing..."
fi

# Install optional but useful tools for server management
echo "🔧 Installing additional server tools..."
case $OS in
    ubuntu|debian)
        sudo apt install -y \
            htop \
            net-tools \
            lsof \
            tmux \
            fish \
            jq \
            tree 2>/dev/null || echo "Some optional tools failed to install (non-critical)"
        ;;
    centos|rhel|fedora)
        if command -v dnf &> /dev/null; then
            sudo dnf install -y htop net-tools lsof tmux fish jq tree 2>/dev/null || echo "Some optional tools failed to install (non-critical)"
        else
            sudo yum install -y htop net-tools lsof tmux fish jq tree 2>/dev/null || echo "Some optional tools failed to install (non-critical)"
        fi
        ;;
    arch)
        sudo pacman -S --noconfirm htop net-tools lsof tmux fish jq tree 2>/dev/null || echo "Some optional tools failed to install (non-critical)"
        ;;
esac

# Configure firewall for ZeiCoin ports (optional)
echo "🔥 Configuring firewall for ZeiCoin ports..."
if command -v ufw &> /dev/null; then
    echo "📡 Opening ZeiCoin ports (10800-10802) in UFW..."
    sudo ufw allow 10800:10802/tcp comment "ZeiCoin blockchain"
    sudo ufw allow 10800/udp comment "ZeiCoin discovery"
    echo "✅ UFW rules added (use 'sudo ufw enable' to activate)"
elif command -v firewall-cmd &> /dev/null; then
    echo "📡 Opening ZeiCoin ports (10800-10802) in firewalld..."
    sudo firewall-cmd --permanent --add-port=10800-10802/tcp
    sudo firewall-cmd --permanent --add-port=10800/udp
    sudo firewall-cmd --reload
    echo "✅ Firewalld rules added"
else
    echo "⚠️  No firewall manager detected. Manually open ports 10800-10802 if needed."
fi

# Verify installations
echo ""
echo "🔍 Verifying installations..."

# Check core tools
for cmd in gcc make cmake git curl wget; do
    if command -v $cmd &> /dev/null; then
        echo "✅ $cmd: $(command -v $cmd)"
    else
        echo "❌ $cmd: Not found"
    fi
done

# Check Zig specifically
if command -v zig &> /dev/null; then
    ZIG_INSTALLED_VERSION=$(zig version)
    echo "✅ Zig: $ZIG_INSTALLED_VERSION at $(command -v zig)"
    if [ "$ZIG_INSTALLED_VERSION" = "$ZIG_VERSION" ]; then
        echo "   ✅ Correct version installed"
    else
        echo "   ⚠️  Version mismatch (expected $ZIG_VERSION)"
    fi
else
    echo "❌ Zig: Not found or not in PATH"
fi

echo ""
echo "🎉 Dependency installation complete!"
echo ""
echo "📋 Summary:"
echo "  ✅ Core development tools (gcc, make, cmake, git)"
echo "  ✅ Zig programming language v$ZIG_VERSION"
echo "  ✅ Additional server utilities"
echo "  ✅ Firewall configuration (if available)"
echo ""
echo "🚀 Next steps:"
echo "  1. Run: cd ~/zeicoin && ./scripts/setup.sh"
echo "  2. Start server: ./scripts/start_zei_server.sh"
echo ""
echo "🔧 Troubleshooting:"
echo "  - If Zig not in PATH: source ~/.bashrc or logout/login"
echo "  - Check firewall: make sure ports 10800-10802 are open"
echo "  - For RandomX issues: ensure sufficient RAM (>2GB recommended)"