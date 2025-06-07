#!/bin/bash
# Build script for RandomX helper

echo "Building RandomX helper..."
gcc -o randomx_helper randomx_helper.c wrapper.c \
    -L./randomx_build/RandomX/build \
    -lrandomx \
    -I./randomx_build/RandomX/src \
    -pthread \
    -lstdc++ \
    -lm \
    -Wl,-z,noexecstack

if [ $? -eq 0 ]; then
    echo "✅ RandomX helper built successfully!"
else
    echo "❌ Build failed!"
    exit 1
fi