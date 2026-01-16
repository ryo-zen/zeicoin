# ZeiCoin Systemd Service Setup

This directory contains systemd service files for running ZeiCoin as a production service.

## Service Files

- **zeicoin-mining.service** - Main mining server with crash recovery
- **zeicoin-server.service** - Blockchain server (non-mining mode) with crash recovery
- **zeicoin-indexer.service** - Blockchain indexer (one-shot execution)
- **zeicoin-indexer.timer** - Auto-indexer timer (runs every 30 seconds)
- **zeicoin-transaction-api.service** - Transaction API for RPC operations
- **zeicoin.target** - Combined target for all services

## Prerequisites

1. Build ZeiCoin binaries:
   ```bash
   cd /root/zeicoin
   zig build -Doptimize=ReleaseFast
   ```

2. Set up PostgreSQL (for indexer):
   ```bash
   ./scripts/setup_analytics.sh
   ```

3. Configure environment and secrets:
   ```bash
   cp .env.example .env
   # Secrets go in .env.local (which is ignored by git)
   echo "ZEICOIN_DB_PASSWORD=your_secure_password" > .env.local
   chmod 600 .env.local
   ```

## Installation

1. Copy service files to systemd:
   ```bash
   sudo cp systemd/*.service /etc/systemd/system/
   sudo cp systemd/*.timer /etc/systemd/system/
   sudo cp systemd/*.target /etc/systemd/system/
   ```

2. Reload systemd:
   ```bash
   sudo systemctl daemon-reload
   ```

## Crash Recovery (Unlocking)

The services are configured with `ExecStartPre` logic to handle hard crashes. If the node crashes, RocksDB often leaves a `LOCK` file behind that prevents restarting. Our services automatically:
1. Kill any zombie `zen_server` processes.
2. Remove stale `LOCK` files from the data directories.
3. Start the service fresh.

## 🚀 Auto-Indexer Quick Start

The auto-indexer keeps PostgreSQL in sync with the blockchain.

### Setup (One-time)

```bash
# 1. Ensure secrets are in .env.local
# (Service will automatically load them)

# 2. Enable and start timer
sudo systemctl enable zeicoin-indexer.timer
sudo systemctl start zeicoin-indexer.timer
```

### Monitor

```bash
# Check timer status
systemctl status zeicoin-indexer.timer

# View indexer logs
journalctl -u zeicoin-indexer.service -f

# Check last run
systemctl status zeicoin-indexer.service
```

### Verify It's Working

```bash
# Check database sync
ZEICOIN_DB_PASSWORD=yourpass psql -h localhost -U zeicoin -d zeicoin_testnet \
  -c "SELECT MAX(height) FROM blocks"

# Compare with blockchain
ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin status | grep Height
```

### Start All Services

```bash
# Start everything at once
sudo systemctl start zeicoin.target
```

### Enable Services (Auto-start on Boot)

```bash
# Enable individual services
sudo systemctl enable zeicoin-mining.service
sudo systemctl enable zeicoin-transaction-api.service
sudo systemctl enable zeicoin-indexer.timer

# Or enable all via target
sudo systemctl enable zeicoin.target
```

### Check Status

```bash
# Check service status
sudo systemctl status zeicoin-mining.service
sudo systemctl status zeicoin.target

# View logs
sudo journalctl -u zeicoin-mining.service -f
sudo journalctl -u zeicoin.target -f
```

### Stop Services

```bash
# Stop individual service
sudo systemctl stop zeicoin-mining.service

# Stop all services
sudo systemctl stop zeicoin.target
```

## Configuration

### Environment Variables

The services load variables from **`/root/zeicoin/.env`** and overrides from **`/root/zeicoin/.env.local`**.

```bash
# .env.local (Secrets)
ZEICOIN_DB_PASSWORD=your_secure_password_here

# .env (Config)
ZEICOIN_SERVER=127.0.0.1
ZEICOIN_BIND_IP=0.0.0.0
ZEICOIN_BOOTSTRAP=209.38.31.77:10801,134.199.170.129:10801
```

### Service Dependencies

- **zeicoin-mining.service** - Main server
- **zeicoin-indexer.service** - Requires PostgreSQL and zen_server
- **zeicoin-transaction-api.service** - Independent, provides RPC interface
- **zeicoin-indexer.timer** - Requires zeicoin-indexer.service

## Firewall Configuration

Open required ports:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 10801/tcp comment "ZeiCoin P2P"
sudo ufw allow 10802/tcp comment "ZeiCoin Client API"
sudo ufw allow 10803/tcp comment "ZeiCoin JSON-RPC"
sudo ufw allow 8080/tcp comment "ZeiCoin Transaction API"
```

## Troubleshooting

### Service Won't Start

```bash
# Check detailed logs
sudo journalctl -u zeicoin-mining.service -n 50

# Check if binary exists
ls -la /root/zeicoin/zig-out/bin/zen_server
```

## Low-Memory Environments (1GB RAM)

If running on a VPS with 1GB of RAM or less, the system may kill the miner or indexer (OOM Killer). It is **highly recommended** to configure at least 4GB of swap space:

```bash
# Create and enable a 4GB swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make it permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Service Architecture

```
zeicoin.target
├── zeicoin-mining.service (Exclusive with zeicoin-server)
│   └── zen_server --mine miner
├── zeicoin-transaction-api.service
│   └── transaction_api (port 10803)
└── zeicoin-indexer.timer
    └── zeicoin_indexer (every 30s)
```

## Notes

- All services run as root (modify User= if needed)
- Services use /root/zeicoin as WorkingDirectory
- Logs go to systemd journal (use journalctl to view)
- Services have auto-restart on failure
- Indexer runs every 30 seconds via timer