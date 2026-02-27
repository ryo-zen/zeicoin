# ZeiCoin Systemd Service Setup

This directory contains systemd service files for running ZeiCoin as a production service.

## Full Install (Agent / Automation Reference)

A single, ordered sequence covering every step from a bare Ubuntu server to a running node.
All commands use absolute paths. Each phase ends with a verification step — do not proceed if
verification fails.

**Variables — set these once before running anything:**
```bash
ZEICOIN_HOME=/root/zeicoin
ZEICOIN_DB_PASSWORD=your_secure_password   # change this
ZEICOIN_BIND_IP=0.0.0.0                    # 0.0.0.0 for mining/bootstrap, 127.0.0.1 for local dev
ZEICOIN_BOOTSTRAP=209.38.31.77:10801,134.199.170.129:10801,209.38.84.23:10801
ZEICOIN_MINE_ENABLED=true                  # false for non-mining nodes
ZEICOIN_MINER_WALLET=miner                 # ignored when MINE_ENABLED=false
```

---

### Phase 1 — System dependencies

```bash
# 1a. Install PostgreSQL (setup_analytics.sh requires psql to already exist)
sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib

# Verify
systemctl is-active postgresql || systemctl is-active "postgresql@$(pg_lsclusters -h | awk '{print $1"-"$2"-main"}')" \
  || { echo "ERROR: PostgreSQL not running"; exit 1; }
```

```bash
# 1b. Swap (required on nodes with ≤2GB RAM; OOM killer will kill the miner otherwise)
if [ ! -f /swapfile ]; then
    sudo fallocate -l 4G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

# Verify
free -h | grep -i swap | awk '{if ($2 == "0B") {print "ERROR: swap not active"; exit 1} else print "Swap OK: " $2}'
```

---

### Phase 2 — Build binaries

```bash
cd "$ZEICOIN_HOME"
zig build -Doptimize=ReleaseFast

# Verify
test -x "$ZEICOIN_HOME/zig-out/bin/zen_server"  || { echo "ERROR: zen_server not built"; exit 1; }
test -x "$ZEICOIN_HOME/zig-out/bin/zeicoin"     || { echo "ERROR: zeicoin CLI not built"; exit 1; }
echo "Binaries OK"
```

---

### Phase 3 — PostgreSQL databases

```bash
cd "$ZEICOIN_HOME"
sudo ./scripts/setup_analytics.sh

# Verify
PGPASSWORD="$ZEICOIN_DB_PASSWORD" psql -h localhost -U zeicoin -d zeicoin_testnet -c "SELECT 1" > /dev/null \
  || { echo "ERROR: cannot connect to zeicoin_testnet"; exit 1; }
echo "Database OK"
```

---

### Phase 4 — Environment configuration

```bash
# Create .env if it doesn't exist
if [ ! -f "$ZEICOIN_HOME/.env" ]; then
    cp "$ZEICOIN_HOME/.env.example" "$ZEICOIN_HOME/.env"
fi

# Write config values
cat > "$ZEICOIN_HOME/.env" <<EOF
ZEICOIN_NETWORK=testnet
ZEICOIN_DATA_DIR=zeicoin_data_testnet
ZEICOIN_P2P_PORT=10801
ZEICOIN_CLIENT_PORT=10802
ZEICOIN_BIND_IP=${ZEICOIN_BIND_IP}
ZEICOIN_BOOTSTRAP=${ZEICOIN_BOOTSTRAP}
ZEICOIN_MINE_ENABLED=${ZEICOIN_MINE_ENABLED}
ZEICOIN_MINER_WALLET=${ZEICOIN_MINER_WALLET}
ZEICOIN_SERVER=127.0.0.1
EOF

# Write secrets (git-ignored)
echo "ZEICOIN_DB_PASSWORD=${ZEICOIN_DB_PASSWORD}" > "$ZEICOIN_HOME/.env.local"
chmod 600 "$ZEICOIN_HOME/.env.local"

# Verify
grep -q "ZEICOIN_BIND_IP" "$ZEICOIN_HOME/.env" || { echo "ERROR: .env not written"; exit 1; }
echo "Config OK"
```

---

### Phase 5 — Install and patch service files

```bash
# Copy service files
sudo cp "$ZEICOIN_HOME"/systemd/*.service /etc/systemd/system/
sudo cp "$ZEICOIN_HOME"/systemd/*.timer   /etc/systemd/system/
sudo cp "$ZEICOIN_HOME"/systemd/*.target  /etc/systemd/system/

# Detect the actual PostgreSQL unit name (Ubuntu uses versioned names like postgresql@16-main.service)
PG_UNIT=$(systemctl list-units --type=service --all | awk '/postgresql/ {print $1; exit}')
if [ -z "$PG_UNIT" ]; then
    echo "ERROR: could not detect PostgreSQL systemd unit"; exit 1
fi
echo "PostgreSQL unit: $PG_UNIT"

# Patch service files if the unit name differs from the generic alias
if [ "$PG_UNIT" != "postgresql.service" ]; then
    for f in /etc/systemd/system/zeicoin-indexer.service \
              /etc/systemd/system/zeicoin-transaction-api.service \
              /etc/systemd/system/zeicoin-error-monitor.service \
              /etc/systemd/system/zeicoin.target; do
        sudo sed -i "s/postgresql\.service/${PG_UNIT}/g" "$f"
    done
    echo "Patched service files to use $PG_UNIT"
fi

sudo systemctl daemon-reload

# Verify
systemctl cat zeicoin-mining.service > /dev/null || { echo "ERROR: service files not loaded"; exit 1; }
echo "Service files OK"
```

---

### Phase 6 — Firewall

```bash
sudo ufw allow 10801/tcp comment "ZeiCoin P2P"
sudo ufw allow 10802/tcp comment "ZeiCoin Client API"
sudo ufw allow 10803/tcp comment "ZeiCoin JSON-RPC"
sudo ufw allow 8080/tcp  comment "ZeiCoin Transaction API"

# Verify (ufw may be inactive on fresh servers — that's fine, ports are open by default)
sudo ufw status | grep -E "10801|inactive" || true
```

---

### Phase 7 — Enable and start services

```bash
sudo systemctl enable zeicoin-mining.service
sudo systemctl enable zeicoin-transaction-api.service
sudo systemctl enable zeicoin-indexer.timer

sudo systemctl start zeicoin-mining.service
sudo systemctl start zeicoin-transaction-api.service
sudo systemctl start zeicoin-indexer.timer
```

---

### Phase 8 — Verify

```bash
# Wait for startup and initial peer connections
sleep 15

# Service health
systemctl is-active zeicoin-mining.service          || { echo "ERROR: mining service not active"; exit 1; }
systemctl is-active zeicoin-transaction-api.service || { echo "ERROR: transaction-api not active"; exit 1; }
systemctl is-active zeicoin-indexer.timer           || { echo "ERROR: indexer timer not active"; exit 1; }

# Node health
ZEICOIN_SERVER=127.0.0.1 "$ZEICOIN_HOME/zig-out/bin/zeicoin" status

# Ports bound correctly
netstat -tlnp | grep -E "10801|10802" || ss -tlnp | grep -E "10801|10802"
```

**Expected output:**
- `zeicoin-mining.service` → `active (running)`
- `zeicoin status` → shows chain height, peers (may be 0 for first ~30s), mining active
- Port 10801 bound to `0.0.0.0:10801` (mining nodes) or `127.0.0.1:10801` (local dev)

> **Note on "Connected Peers: 0"**: If peers remain at 0 after 60s and your `BIND_IP`/`BOOTSTRAP`
> config is correct, the remote bootstrap nodes may be temporarily unreachable. Peers
> auto-reconnect every ~30s. Check logs with:
> `sudo journalctl -u zeicoin-mining.service | grep -i "reset\|refused\|timeout" | tail -20`

---

## Service Files

- **zeicoin-mining.service** - Main mining server with crash recovery
- **zeicoin-server.service** - Blockchain server (non-mining mode) with crash recovery
- **zeicoin-indexer.service** - Blockchain indexer (one-shot execution)
- **zeicoin-indexer.timer** - Auto-indexer timer (runs every 30 seconds)
- **zeicoin-transaction-api.service** - Transaction API for RPC operations
- **zeicoin.target** - Combined target for all services

## Prerequisites

1. **Install system dependencies** (PostgreSQL must be installed before running the setup script):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install -y postgresql postgresql-contrib

   # Verify the service is running
   sudo systemctl status postgresql
   ```

   > **Note**: `./scripts/setup_analytics.sh` checks for `psql` and exits with an error if
   > PostgreSQL is not found. It does not install it automatically.

2. **Configure swap space** (required for VPS nodes with ≤2GB RAM):

   Without swap, the OOM killer will terminate the miner or indexer under memory pressure.
   Set this up before starting any services:
   ```bash
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile

   # Make permanent across reboots
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

3. Build ZeiCoin binaries:
   ```bash
   cd /root/zeicoin
   zig build -Doptimize=ReleaseFast
   ```

4. Set up PostgreSQL databases (for indexer):
   ```bash
   ./scripts/setup_analytics.sh
   ```

5. Configure environment and secrets:
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

## Service Helper Script (`zeicoin-services`)

Use `systemd/zeicoin-services` as a wrapper for start/stop/status/logs.

### Deploy to Server

From your local machine:

```bash
scp systemd/zeicoin-services root@<server-ip>:/root/zeicoin/systemd/zeicoin-services
```

On the server:

```bash
chmod +x /root/zeicoin/systemd/zeicoin-services
ln -sf /root/zeicoin/systemd/zeicoin-services /usr/local/bin/zeicoin-services
```

### Usage

```bash
zeicoin-services status
zeicoin-services restart
zeicoin-services logs monitor
```

### Notes

- Set `ZEICOIN_HOME` if your install path is not `/root/zeicoin`.
- The script manages:
  - `zeicoin-mining.service`
  - `zeicoin-transaction-api.service`
  - `zeicoin-indexer.timer`
  - `zeicoin-error-monitor.service`

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
ZEICOIN_DB_PASSWORD=yourpass psql -h localhost -U zeicoin -d zeicoin_testnet \ -c "SELECT MAX(height) FROM blocks"

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

### PostgreSQL Service Name Mismatch (Ubuntu)

The service files reference `postgresql.service`, but Ubuntu installs a versioned unit such as
`postgresql@16-main.service`. This causes dependency checks (`After=`, `Requires=`) to silently
fail because the generic alias may not be active.

**Diagnosis:**
```bash
# Check what unit name Ubuntu actually uses
systemctl list-units | grep postgresql
# Example output: postgresql@16-main.service
```

**Fix:** After copying the service files, patch the four affected units:
```bash
# Replace postgresql.service with the versioned unit name
PG_UNIT=$(systemctl list-units --type=service | awk '/postgresql/ {print $1; exit}')
echo "Detected PostgreSQL unit: $PG_UNIT"

for f in /etc/systemd/system/zeicoin-indexer.service \
          /etc/systemd/system/zeicoin-transaction-api.service \
          /etc/systemd/system/zeicoin-error-monitor.service \
          /etc/systemd/system/zeicoin.target; do
    sudo sed -i "s/postgresql.service/$PG_UNIT/g" "$f"
done

sudo systemctl daemon-reload
```

### Connected Peers: 0 / Mining: Inactive

After setup, `zeicoin status` may show:

```
Connected Peers: 0
Mining: Inactive
```

**First, verify your own configuration is correct:**
```bash
# Ports must be bound to 0.0.0.0 on a mining/bootstrap node
netstat -tlnp | grep 10801   # Should show 0.0.0.0:10801, not 127.0.0.1:10801
```

Check `CLAUDE.md` → *Network Architecture* for the full list of common misconfigurations
(`BIND_IP`, `BOOTSTRAP`, `MINE_ENABLED`).

**If your config is correct, the issue may be with the remote bootstrap nodes.**

Each bootstrap node maintains an outbound connection to the others. If those remote nodes are
temporarily unreachable or are resetting connections (`ConnectionResetByPeer`), your node will
show 0 peers. This is a network condition on the remote side, not a local misconfiguration.

```bash
# Check connection errors in logs
sudo journalctl -u zeicoin-mining.service | grep -i "reset\|refused\|timeout" | tail -20

# Wait and retry — peers auto-reconnect every ~30s
# Once the remote nodes recover, peer count will climb automatically
ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin status
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


## Service Restarts

Use the helper script for consistent service management:

```bash
./systemd/zeicoin-services.sh restart
```
