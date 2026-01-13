# Dockerfile - Complete build (Base + App)
# Combined from Dockerfile.base and Dockerfile.fast for single-step build

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install ALL system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    xz-utils \
    git \
    build-essential \
    cmake \
    librocksdb-dev \
    libhwloc-dev \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.14.1
RUN wget https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz && \
    tar -xf zig-x86_64-linux-0.14.1.tar.xz && \
    mv zig-x86_64-linux-0.14.1 /usr/local/zig && \
    ln -s /usr/local/zig/zig /usr/local/bin/zig && \
    rm zig-x86_64-linux-0.14.1.tar.xz

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
RUN zig build

# Create data directory and config
RUN mkdir -p /zeicoin/zeicoin_data && \
    mkdir -p /zeicoin/config && \
    echo '{"network": "testnet", "nodes": []}' > /zeicoin/config/bootstrap_testnet.json && \
    echo '{"network": "mainnet", "nodes": []}' > /zeicoin/config/bootstrap_mainnet.json

# Copy scripts, fix line endings, and make executable
RUN mkdir -p /scripts && \
    cp docker/scripts/*.sh /scripts/ 2>/dev/null || true && \
    sed -i 's/\r$//' /scripts/*.sh 2>/dev/null || true && \
    chmod +x /scripts/*.sh 2>/dev/null || true

EXPOSE 10801 10802 10803 8080
CMD ["./zig-out/bin/zen_server"]
