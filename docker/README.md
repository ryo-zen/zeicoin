# ZeiCoin Docker Multi-Node Testing Environment

This Docker setup provides a complete 3-node ZeiCoin cluster for testing multi-node synchronization, P2P networking, and blockchain consensus on Windows.

## Architecture

```
zeicoin-network (Docker bridge - ISOLATED from live network)
├── seed-node (zeicoin-seed)
│   ├── Ports: 10801 (P2P), 10802 (Client API), 10803 (RPC)
│   ├── Mining: Enabled (wallet: miner)
│   ├── Bootstrap: None (genesis node, no external connections)
│   └── Data: Docker volume 'seed-data'
│
├── node-1 (zeicoin-node1)
│   ├── Ports: 10811 (P2P), 10812 (Client API), 10813 (RPC)
│   ├── Mining: Disabled
│   ├── Bootstrap: seed-node:10801 (internal only)
│   └── Data: Docker volume 'node1-data'
│
└── node-2 (zeicoin-node2)
    ├── Ports: 10821 (P2P), 10822 (Client API), 10823 (RPC)
    ├── Mining: Disabled
    ├── Bootstrap: seed-node:10801, node-1:10801 (internal only)
    └── Data: Docker volume 'node2-data'
```

**Important**: This Docker setup is completely isolated from the live ZeiCoin testnet. The nodes will NOT connect to the public bootstrap nodes (209.38.31.77, 134.199.170.129). This creates a private testing network for safe experimentation.

## Prerequisites

### Required
- **Docker Desktop for Windows** (latest version)
  - Download: https://www.docker.com/products/docker-desktop
- **WSL 2** enabled (Docker Desktop will guide you)
- **4GB+ RAM** allocated to Docker Desktop
- **10GB+ free disk space**

### System Requirements
- Windows 10/11 (64-bit)
- Virtualization enabled in BIOS
- Internet connection (for building images)

## Quick Start

### 1. Build and Start the Cluster

From the project root directory:

```bash
# Build images and start all nodes
docker-compose up -d

# This will:
# - Build the ZeiCoin Docker image (~5-10 minutes first time)
# - Start seed node and create miner wallet
# - Start peer nodes and connect to seed
# - Begin mining on seed node
```

### 2. View Logs

```bash
# View all nodes
docker-compose logs -f

# View specific node
docker-compose logs -f seed-node
docker-compose logs -f node-1
docker-compose logs -f node-2

# Press Ctrl+C to exit logs
```

### 3. Check Node Status

```bash
# Check seed node (mining)
docker exec zeicoin-seed ./zig-out/bin/zeicoin status

# Check node-1 (syncing)
docker exec zeicoin-node1 ./zig-out/bin/zeicoin status

# Check node-2 (syncing)
docker exec zeicoin-node2 ./zig-out/bin/zeicoin status
```

Expected output:
```
Height: 42 | Peers: 2 | Mempool: 0 | Mining: ✓
```

## Testing Multi-Node Synchronization

### Verify Blockchain Sync

All nodes should reach the same height within seconds:

```bash
# Quick status check for all nodes
echo "=== Seed Node ===" && docker exec zeicoin-seed ./zig-out/bin/zeicoin status
echo "=== Node 1 ===" && docker exec zeicoin-node1 ./zig-out/bin/zeicoin status
echo "=== Node 2 ===" && docker exec zeicoin-node2 ./zig-out/bin/zeicoin status
```

### Create and Test Wallets

```bash
# Create a wallet on seed node
docker exec -it zeicoin-seed ./zig-out/bin/zeicoin wallet create alice
# Enter password when prompted

# Get miner wallet address (to receive test coins)
docker exec zeicoin-seed ./zig-out/bin/zeicoin address miner

# Check miner balance (should have mining rewards)
docker exec zeicoin-seed ./zig-out/bin/zeicoin balance miner

# Get alice's address
docker exec zeicoin-seed ./zig-out/bin/zeicoin address alice

# Send coins from miner to alice
docker exec zeicoin-seed ./zig-out/bin/zeicoin send 100 <alice-address> miner
# Enter miner password: miner123

# Wait for next block, then check alice's balance
docker exec zeicoin-seed ./zig-out/bin/zeicoin balance alice
```

### Test Transaction Propagation

```bash
# View transaction history on seed
docker exec zeicoin-seed ./zig-out/bin/zeicoin history miner

# Create wallet on node-1
docker exec -it zeicoin-node1 ./zig-out/bin/zeicoin wallet create bob

# Get bob's address
docker exec zeicoin-node1 ./zig-out/bin/zeicoin address bob

# Send from alice to bob (cross-node transaction)
docker exec zeicoin-seed ./zig-out/bin/zeicoin send 50 <bob-address> alice

# Verify bob received coins on node-1
docker exec zeicoin-node1 ./zig-out/bin/zeicoin balance bob
```

## Network Resilience Testing

### Test Node Failure and Reconnection

```bash
# Stop node-1
docker-compose stop node-1

# Watch seed node logs (should show peer disconnection)
docker-compose logs -f seed-node

# Restart node-1
docker-compose start node-1

# Watch node-1 logs (should resync)
docker-compose logs -f node-1
```

### Test Network Partition

```bash
# Disconnect node-2 from network
docker network disconnect zeicoin-network zeicoin-node2

# Wait 30 seconds, then reconnect
docker network connect zeicoin-network zeicoin-node2

# Node-2 should automatically reconnect and resync
docker-compose logs -f node-2
```

### Test Mining Interruption

```bash
# Restart seed node (mining stops temporarily)
docker-compose restart seed-node

# Watch it resume mining
docker-compose logs -f seed-node

# Peer nodes should maintain connection and sync new blocks
```

## Advanced Usage

### Access Node Shells

```bash
# Interactive shell in seed node
docker exec -it zeicoin-seed /bin/bash

# Now you can run commands directly
./zig-out/bin/zeicoin status
./zig-out/bin/zeicoin balance miner
exit
```

### View RocksDB Data

```bash
# List blockchain data files
docker exec zeicoin-seed ls -lh /zeicoin/zeicoin_data/

# Check wallet files
docker exec zeicoin-seed ls -lh /zeicoin/zeicoin_data/wallets/
```

### Monitor Resource Usage

```bash
# Check container resource usage
docker stats

# View specific container stats
docker stats zeicoin-seed zeicoin-node1 zeicoin-node2
```

### Inspect Network

```bash
# View network details
docker network inspect zeicoin-network

# See connected containers
docker network inspect zeicoin-network -f '{{range .Containers}}{{.Name}} {{end}}'
```

## Configuration

### Customizing Environment

Copy the example environment file:

```bash
cp docker/.env.example docker/.env
```

Edit `docker/.env` to customize:
- Network type (testnet/mainnet)
- Port mappings
- Consensus mode
- Wallet passwords

### Changing Node Count

Edit `docker-compose.yml` to add/remove nodes:

```yaml
# Add node-3
node-3:
  build:
    context: .
    dockerfile: Dockerfile
  container_name: zeicoin-node3
  ports:
    - "10831:10801"
    - "10832:10802"
    - "10833:10803"
  environment:
    - ZEICOIN_BOOTSTRAP=seed-node:10801,node-1:10801,node-2:10801
  # ... rest of configuration
```

### Enable Mining on Peer Nodes

Edit `docker-compose.yml` for the node you want to mine:

```yaml
environment:
  - ZEICOIN_MINE_ENABLED=true
  - ZEICOIN_MINER_WALLET=node1miner
  - ZEICOIN_WALLET_PASSWORD=password123
```

## Troubleshooting

### Nodes Not Connecting

```bash
# Check if all nodes are running
docker-compose ps

# Check network connectivity
docker exec zeicoin-node1 nc -zv seed-node 10801

# Verify bootstrap configuration
docker exec zeicoin-node1 env | grep BOOTSTRAP
```

### Sync Issues

```bash
# Restart nodes in order
docker-compose restart seed-node
sleep 10
docker-compose restart node-1
sleep 5
docker-compose restart node-2

# Force rebuild if needed
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Wallet Creation Fails

```bash
# Check wallet directory permissions
docker exec zeicoin-seed ls -la /zeicoin/zeicoin_data/wallets/

# Manually create wallet
docker exec -it zeicoin-seed ./zig-out/bin/zeicoin wallet create testuser
```

### Low Disk Space

```bash
# Remove unused Docker resources
docker system prune -a

# Remove only stopped containers
docker container prune

# Remove unused volumes
docker volume prune
```

### Mining Not Working

```bash
# Verify miner wallet exists
docker exec zeicoin-seed ls -la /zeicoin/zeicoin_data/wallets/miner.wallet

# Check mining logs
docker-compose logs seed-node | grep -i mine

# Restart seed node
docker-compose restart seed-node
```

## Cleanup

### Stop Nodes (Keep Data)

```bash
# Stop all nodes
docker-compose down

# Restart later with same data
docker-compose up -d
```

### Complete Reset (Delete All Data)

```bash
# Stop and remove everything including volumes
docker-compose down -v

# Remove images (force rebuild next time)
docker-compose down --rmi all -v

# Fresh start
docker-compose up -d --build
```

### Clean Docker System

```bash
# Remove all unused Docker resources
docker system prune -a --volumes

# Warning: This removes ALL unused Docker data, not just ZeiCoin
```

## Performance Optimization

### Allocate More Resources

In Docker Desktop settings:
1. Go to Settings → Resources
2. Increase CPU (recommend 4+ cores)
3. Increase Memory (recommend 6+ GB)
4. Click "Apply & Restart"

### Speed Up Build Times

```bash
# Use BuildKit for faster builds
DOCKER_BUILDKIT=1 docker-compose build

# Cache the Zig download
# Edit Dockerfile to use multi-stage builds
```

### Reduce Log Verbosity

Edit `docker-compose.yml`:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

## Expected Resource Usage

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| seed-node | 50-80% of 1 core | 500 MB | 100 MB |
| node-1 | 10-20% of 1 core | 300 MB | 100 MB |
| node-2 | 10-20% of 1 core | 300 MB | 100 MB |
| **Total** | ~1.5 cores | ~1.5 GB | ~500 MB |

## Security Notes

This Docker setup is for **testing only**. Do not use in production:

- Default wallet password (`miner123`) is insecure
- All ports exposed to localhost
- No TLS/SSL encryption
- Simplified authentication
- Test network only

## Next Steps

- Experiment with different consensus modes
- Test chain reorganization scenarios
- Build custom testing scripts
- Monitor network with external tools
- Develop against the REST API (if enabled)

## Support

For issues specific to Docker setup:
1. Check logs: `docker-compose logs`
2. Verify prerequisites are met
3. Review troubleshooting section above
4. Open issue at: https://github.com/ryo-zen/zeicoin/issues

For general ZeiCoin questions, see [main README](../README.md).
