#!/bin/bash

set -e

# Variables
ZIG_VERSION="0.14.1"
ZIG_TARBALL="zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
ZIG_DIR="zig-x86_64-linux-${ZIG_VERSION}"
INSTALL_PATH="/opt/zig-${ZIG_VERSION}"
SYMLINK="/usr/local/bin/zig"

# Download Zig tarball
wget "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TARBALL}"

# Extract
tar -xf "${ZIG_TARBALL}"

# Move to /opt
sudo mv "${ZIG_DIR}" "${INSTALL_PATH}"

# Create symlink
sudo ln -sf "${INSTALL_PATH}/zig" "${SYMLINK}"

# Clean up tarball
rm "${ZIG_TARBALL}"

# Verify
echo "Zig installed at ${INSTALL_PATH}"
zig version
