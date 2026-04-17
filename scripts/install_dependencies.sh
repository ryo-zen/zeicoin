#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT

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

# Install PostgreSQL client library (required for zeicoin_error_monitor)
echo "🐘 Installing PostgreSQL client library..."
case $OS in
    ubuntu|debian)
        sudo apt install -y libpq-dev
        ;;
    centos|rhel)
        if command -v dnf &> /dev/null; then
            sudo dnf install -y libpq-devel
        else
            sudo yum install -y postgresql-devel
        fi
        ;;
    fedora)
        sudo dnf install -y libpq-devel
        ;;
    arch)
        sudo pacman -S --noconfirm postgresql-libs
        ;;
    *)
        echo "⚠️  Please install PostgreSQL client library manually for your OS"
        echo "   Ubuntu/Debian: sudo apt install libpq-dev"
        echo "   Fedora/CentOS: sudo dnf install libpq-devel"
        echo "   Arch Linux: sudo pacman -S postgresql-libs"
        ;;
esac

if pkg-config --exists libpq 2>/dev/null || [ -f "/usr/lib/x86_64-linux-gnu/libpq.so" ] || [ -f "/usr/lib/libpq.so" ]; then
    echo "✅ PostgreSQL client library installed successfully!"
else
    echo "⚠️  PostgreSQL client library verification failed, but continuing..."
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

# Check Zig
if command -v zig &> /dev/null; then
    echo "✅ Zig: $(zig version) at $(command -v zig)"
else
    echo "⚠️  Zig: Not installed — run ./scripts/update_zig_nightly.sh"
fi

echo ""
echo "🎉 Dependency installation complete!"
echo ""
echo "📋 Summary:"
echo "  ✅ Core development tools (gcc, make, cmake, git)"
echo "  ⚠️  Zig: install separately via ./scripts/update_zig_nightly.sh"
echo "  ✅ PostgreSQL client library (libpq)"
echo "  ✅ Additional server utilities"
echo "  ✅ Firewall configuration (if available)"
echo ""
echo "🚀 Next steps:"
echo "  1. Install Zig: ./scripts/update_zig_nightly.sh  (transfers correct version from local machine)"
echo "  2. Build: cd ~/zeicoin && zig build -Doptimize=ReleaseFast"
echo ""
echo "🔧 Troubleshooting:"
echo "  - If Zig not in PATH: source ~/.bashrc or logout/login"
echo "  - Check firewall: make sure ports 10800-10802 are open"
echo "  - For RandomX issues: ensure sufficient RAM (>2GB recommended)"