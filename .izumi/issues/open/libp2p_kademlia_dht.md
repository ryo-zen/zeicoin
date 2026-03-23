---
id: kademlia_dht
key: ZEI-20
title: Implement Kademlia DHT for decentralised peer discovery
type: Story
status: Backlog
priority: Low
assignee: null
labels:
- libp2p
- networking
- p2p
- mainnet
sprint: null
story_points: 0
due_date: null
parent_id: libp2p_implementation
rank: 1773125883061.0
comments: []
created_at: 2026-03-10T00:00:00+00:00
updated_at: 2026-03-17T00:39:25.714122877+00:00
---
## Summary

Add Kademlia DHT (`/kad/1.0.0`) as a decentralised peer discovery layer on top of the existing libp2p stack. Kademlia allows nodes to find peers without relying on a fixed bootstrap list — nodes join the routing table organically and the network self-heals as peers come and go. This is only needed at network scale; the current `/zeicoin/peers/1.0.0` peer exchange is sufficient for testnet.

## Acceptance Criteria

- [ ] All prerequisites confirmed working (see Notes)
- [ ] `libp2p/dht/kademlia.zig` implements the Kademlia routing table (XOR distance, k-buckets, k=20)
- [ ] `FIND_NODE` RPC implemented: given a target peer ID, return the k closest known peers
- [ ] `FIND_NODE` client: query the closest known peers iteratively until the target or closest set converges
- [ ] DHT bootstrap: on startup, perform a self-lookup (`FIND_NODE(self_peer_id)`) to populate the routing table
- [ ] DHT integrated as an additional peer source in the address book alongside `/zeicoin/peers/1.0.0` and bootstrap config
- [ ] Stream/resource limits in place so DHT traffic cannot starve ZeiCoin protocol traffic
- [ ] `zig build test-libp2p` passes including new DHT unit tests
- [ ] Docker harness demonstrates peer discovery without static `ZEICOIN_BOOTSTRAP` config

## Notes

**Prerequisites** — do not start until all of these are confirmed:
- Persistent PeerId / identity keys (already done: `.libp2p_identity_<port>.key`)
- Working identify protocol with correct advertised addresses (done)
- Stable address book with scoring, backoff, and dedup (done)
- Dial backoff, peer dedup, and self-connection rejection (done)
- `zen_server` integration of the isolated libp2p path (ZEI-11 — not yet done)
- Stream/resource limits so DHT traffic cannot starve ZeiCoin traffic (not yet done)
- Bootstrap nodes online long enough to seed routing tables

**Kademlia is a discovery source only** — it must not influence consensus, block validation, or mempool decisions. Peer addresses found via DHT go into the address book and are subject to the same scoring and dial logic as any other source.

**Spec:** `reference/libp2p-specs/kad-dht/README.md` (if present) or the upstream libp2p Kademlia spec.

**Implementation order:**
1. Routing table (`k-bucket` structure, XOR distance, `FIND_NODE` handler)
2. Iterative lookup client
3. Bootstrap self-lookup on startup
4. Wire into address book as a discovery source
5. Docker harness validation without static bootstrap

**Key files to create:**
- `libp2p/dht/kademlia.zig` — routing table and RPC handlers
- `libp2p/dht/routing_table.zig` — k-bucket management

**Key files to modify:**
- `src/apps/libp2p_testnode.zig` — start DHT on startup, feed discoveries to address book
- `src/core/network/peer_manager.zig` — consume DHT-discovered peers (post ZEI-11)
