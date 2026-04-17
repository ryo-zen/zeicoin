#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
# SPDX-License-Identifier: MIT


echo "🚀 RocksDB Installation Script for ZeiCoin"
echo "=========================================="
echo

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        echo "📦 Installing RocksDB on Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y librocksdb-dev
    elif command -v dnf &> /dev/null; then
        echo "📦 Installing RocksDB on Fedora..."
        sudo dnf install -y rocksdb-devel
    elif command -v pacman &> /dev/null; then
        echo "📦 Installing RocksDB on Arch Linux..."
        sudo pacman -S rocksdb
    else
        echo "⚠️  Unknown Linux distribution"
        echo "Please install RocksDB manually:"
        echo "  https://github.com/facebook/rocksdb/blob/main/INSTALL.md"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Installing RocksDB on macOS..."
    if command -v brew &> /dev/null; then
        brew install rocksdb
    else
        echo "⚠️  Homebrew not found. Please install Homebrew first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
else
    echo "⚠️  Unsupported OS: $OSTYPE"
    echo "Please install RocksDB manually:"
    echo "  https://github.com/facebook/rocksdb/blob/main/INSTALL.md"
fi

echo
echo "✅ Installation complete!"
echo
echo "To use RocksDB backend with ZeiCoin:"
echo "  export ZEICOIN_STORAGE_BACKEND=rocksdb"
echo "  zig build"
echo
echo "To migrate existing data:"
echo "  zig build-exe src/tools/migrate.zig"
echo "  ./migrate"