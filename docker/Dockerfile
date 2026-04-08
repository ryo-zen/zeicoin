# Dockerfile - Complete build (Base + App)
# Combined from Dockerfile.base and Dockerfile.fast for single-step build

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install ALL system dependencies
RUN apt-get update && apt-get install -y \
    xz-utils \
    git \
    build-essential \
    cmake \
    librocksdb-dev \
    libpq-dev \
    libhwloc-dev \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Zig from local tarball (prepared by test script or CI)
COPY .docker-cache/zig-nightly.tar.xz /tmp/zig-nightly.tar.xz
RUN set -eux; \
    tar -xf /tmp/zig-nightly.tar.xz -C /tmp; \
    zig_dir="$(find /tmp -maxdepth 1 -type d -name 'zig-x86_64-linux-*' | head -n1)"; \
    test -n "$zig_dir"; \
    mv "$zig_dir" /usr/local/zig; \
    ln -s /usr/local/zig/zig /usr/local/bin/zig; \
    rm -f /tmp/zig-nightly.tar.xz

WORKDIR /zeicoin

# Pre-download and build RandomX
RUN git clone https://github.com/tevador/RandomX.git && \
    cd RandomX && git checkout v1.2.1 && \
    mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && make install && \
    cd / && rm -rf /zeicoin/RandomX

# --- Application Build ---

# Copy only build files first for better caching
COPY build.zig build.zig.zon ./
COPY randomx ./randomx

# Copy ALL source code
COPY . .

# Build RandomX helper (after COPY to avoid overwriting with host binary)
RUN gcc -o randomx/randomx_helper randomx/randomx_helper.c randomx/wrapper.c \
    -Irandomx -I/usr/local/include \
    -L/usr/local/lib -lrandomx -lstdc++ -lm

# Build ZeiCoin
# Ubuntu 24.04 puts libpq headers in /usr/include/postgresql
ENV C_INCLUDE_PATH=/usr/include/postgresql
RUN zig build

# Create data directory
RUN mkdir -p /zeicoin/zeicoin_data

# Copy scripts, fix line endings, and make executable
RUN mkdir -p /scripts && \
    cp docker/scripts/*.sh /scripts/ 2>/dev/null || true && \
    sed -i 's/\r$//' /scripts/*.sh 2>/dev/null || true && \
    chmod +x /scripts/*.sh 2>/dev/null || true

EXPOSE 10801 10802 10803 8080
CMD ["./zig-out/bin/zen_server"]
