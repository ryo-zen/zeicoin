# ZeiCoin Systemd Service Setup

This directory contains systemd service files for running ZeiCoin as a production service.

## Service Files

- **zeicoin-mining.service** - Main mining server with auto-restart
- **zeicoin-server.service** - Blockchain server (non-mining mode)
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

3. Configure environment:
   ```bash
   cp .env.testnet .env
   # Edit .env with your settings
   ```

## Installation

1. Copy service files to systemd:
   ```bash
   sudo cp systemd/*.service /etc/systemd/system/
   sudo cp systemd/*.timer /etc/systemd/system/
   sudo cp systemd/*.target /etc/systemd/system/
   ```

2. Update paths in service files if needed:
   ```bash
   # Edit WorkingDirectory and ExecStart paths if not using /root/zeicoin
   sudo nano /etc/systemd/system/zeicoin-mining.service
   ```

3. Reload systemd:
   ```bash
   sudo systemctl daemon-reload
   ```

## Usage

### Start Individual Services

```bash
# Start mining server
sudo systemctl start zeicoin-mining.service

# Start transaction API
sudo systemctl start zeicoin-transaction-api.service

# Start indexer timer (runs every 30s)
sudo systemctl start zeicoin-indexer.timer
```

## 🚀 Auto-Indexer Quick Start

The auto-indexer keeps PostgreSQL in sync with the blockchain for the REST API.

### Setup (One-time)

```bash
# 1. Copy service files to systemd
sudo cp /home/max/zeicoin/systemd/zeicoin-indexer.* /etc/systemd/system/

# 2. Update database password in service file
sudo nano /etc/systemd/system/zeicoin-indexer.service
# Change: Environment="ZEICOIN_DB_PASSWORD=your_password_here"

# 3. Enable and start timer
sudo systemctl daemon-reload
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

# Test API
curl http://localhost:8080/api/transactions/YOUR_ADDRESS
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

Edit `/root/zeicoin/.env` to configure:

```bash
# Network
ZEICOIN_SERVER=127.0.0.1
ZEICOIN_BIND_IP=0.0.0.0
ZEICOIN_BOOTSTRAP=209.38.31.77:10801,134.199.170.129:10801

# Mining
ZEICOIN_MINE_ENABLED=true
ZEICOIN_MINER_WALLET=miner

# Database (for indexer/API)
ZEICOIN_DB_PASSWORD=your_secure_password_here
ZEICOIN_DB_HOST=127.0.0.1
ZEICOIN_DB_NAME=zeicoin_testnet
ZEICOIN_DB_USER=zeicoin
```

### Service Dependencies

- **zeicoin-server.service** - Independent, starts first
- **zeicoin-indexer.service** - Requires PostgreSQL and zeicoin-server
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

# Firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=10801/tcp
sudo firewall-cmd --permanent --add-port=10802/tcp
sudo firewall-cmd --permanent --add-port=10803/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

**Note:** Port 10800 is reserved for future QUIC transport implementation.

## Troubleshooting

### Service Won't Start

```bash
# Check detailed logs
sudo journalctl -u zeicoin-mining.service -n 50

# Check if binary exists
ls -la /root/zeicoin/zig-out/bin/zen_server

# Check permissions
sudo systemctl status zeicoin-mining.service
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
PGPASSWORD=your_password psql -h localhost -U zeicoin -d zeicoin_testnet

# Check if PostgreSQL is running
sudo systemctl status postgresql
```

### Wallet Issues

```bash
# Verify wallet exists
ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin balance miner

# Create wallet if needed
ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin wallet create miner
```

## Quick Start (Full Stack)

```bash
# 1. Install services
sudo cp systemd/* /etc/systemd/system/
sudo systemctl daemon-reload

# 2. Enable all services
sudo systemctl enable zeicoin.target

# 3. Start everything
sudo systemctl start zeicoin.target

# 4. Check status
sudo systemctl status zeicoin.target

# 5. Watch logs
sudo journalctl -u zeicoin.target -f
```

## Service Architecture

```
zeicoin.target
├── zeicoin-mining.service (or zeicoin-server.service)
│   └── zen_server --mine miner
├── zeicoin-transaction-api.service
│   └── transaction_api (port 8080)
└── zeicoin-indexer.timer
    └── zeicoin_indexer (every 30s)
```

## Notes

- All services run as root (modify User= if needed)
- Services use /root/zeicoin as WorkingDirectory
- Logs go to systemd journal (use journalctl to view)
- Services have auto-restart on failure
- Indexer runs every 30 seconds via timer
