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

Implement libp2p Kademlia DHT (`/kad/1.0.0`) as a spec-respecting decentralised peer discovery layer on top of the existing libp2p stack. Kademlia allows nodes to find peers without relying on a fixed bootstrap list — nodes join the routing table organically and the network self-heals as peers come and go. This is only needed at network scale; the current `/zeicoin/peers/1.0.0` peer exchange is sufficient for testnet, but once `ZEI-20` starts it should respect the real libp2p Kademlia wire protocol and operational rules instead of shipping a partial lookalike under the same protocol ID.

## Acceptance Criteria

- [ ] All prerequisites confirmed working (see Notes)
- [ ] `libp2p/dht/kademlia.zig` implements a 256-bit XOR-distance routing table with k-buckets and `k = 20`
- [ ] Kademlia RPCs use the spec wire format: unsigned-varint length prefix plus protobuf messages on `/kad/1.0.0`
- [ ] Stream-per-RPC request/response behavior matches the spec, including reset/close semantics on errors
- [ ] `FIND_NODE` server implemented: given a target peer ID, return the k closest known peers
- [ ] `FIND_NODE` client implemented: query the closest known peers iteratively with bounded `alpha` concurrency until the target or closest set converges
- [ ] DHT bootstrap implemented per spec intent: startup self-lookup plus periodic routing-table refresh / random-walk maintenance
- [ ] Server/client DHT mode behavior is implemented explicitly; only server-mode peers are admitted to the routing table and advertise `/kad/1.0.0`
- [ ] DHT integrated as an additional peer source in the address book alongside `/zeicoin/peers/1.0.0` and bootstrap config
- [ ] Stream/resource limits in place so DHT traffic cannot starve ZeiCoin protocol traffic
- [ ] Scope decision is explicit for provider/value records:
  - either `PUT_VALUE` / `GET_VALUE` / `ADD_PROVIDER` / `GET_PROVIDERS` plus record storage/refresh/expiry are implemented
  - or they are split into follow-up tickets and `ZEI-20` is renamed/re-scoped away from claiming full libp2p Kademlia support
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

**Spec:** `reference/libp2p-specs/kad-dht/README.md`. Respect the actual libp2p Kademlia spec when using `/kad/1.0.0`; do not ship a narrower `FIND_NODE`-only protocol under the canonical protocol ID without explicitly re-scoping the ticket and protocol name.

**Important scope note:** the current acceptance criteria intentionally call out provider/value records because the real spec includes more than peer routing. If ZeiCoin only wants Kademlia for peer discovery, split the full DHT scope into follow-up tickets and rename this ticket to make the narrower scope explicit.

**Implementation order:**
1. Routing table (`k-bucket` structure, XOR distance, server/client-mode admission rules)
2. Protobuf + unsigned-varint Kademlia RPC codec on `/kad/1.0.0`
3. `PING` / `FIND_NODE` handler and iterative lookup client with bounded concurrency
4. Bootstrap self-lookup plus periodic refresh / random walk
5. Wire into address book as a discovery source
6. Provider/value record implementation or explicit follow-up split
7. Docker harness validation without static bootstrap

**Key files to create:**
- `libp2p/dht/kademlia.zig` — routing table and RPC handlers
- `libp2p/dht/routing_table.zig` — k-bucket management
- `libp2p/dht/message.zig` — protobuf-backed Kademlia message codec
- `libp2p/dht/query.zig` — iterative lookup engine / bootstrap refresh logic

**Key files to modify:**
- `src/apps/libp2p_testnode.zig` — start DHT on startup, feed discoveries to address book
- `src/core/network/peer_manager.zig` — consume DHT-discovered peers (post ZEI-11)
