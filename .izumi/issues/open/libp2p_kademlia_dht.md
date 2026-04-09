---
id: kademlia_dht
key: ZEI-20
title: Implement full libp2p Kademlia DHT /kad/1.0.0 support
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
updated_at: 2026-04-09T11:14:22+10:00
---
## Summary

Implement full libp2p Kademlia DHT support on `/kad/1.0.0`, including peer routing, value records, provider records, bootstrap maintenance, and the server/client-mode behavior required by the spec. ZeiCoin's immediate need is decentralised peer discovery, but this ticket is intentionally scoped as full-spec work so the project does not ship a narrower protocol under the canonical Kad protocol ID and have to rework it later.

## Acceptance Criteria

- [ ] All prerequisites confirmed working (see Notes)
- [ ] `libp2p/dht/kademlia.zig` implements a full Kad service boundary over the existing libp2p host stack
- [ ] `libp2p/dht/routing_table.zig` implements a 256-bit XOR-distance routing table with k-buckets and `k = 20`
- [ ] Kademlia RPCs use the spec wire format: unsigned-varint length prefix plus protobuf messages on `/kad/1.0.0`
- [ ] Stream-per-RPC request/response behavior matches the spec, including reset/close semantics on errors
- [ ] `FIND_NODE` server implemented: given a target peer ID, return the k closest known peers
- [ ] `FIND_NODE` client implemented: query the closest known peers iteratively with bounded `alpha` concurrency until the target or closest set converges
- [ ] DHT bootstrap implemented per spec intent: startup self-lookup plus periodic routing-table refresh / random-walk maintenance
- [ ] Server/client DHT mode behavior is implemented explicitly; only server-mode peers are admitted to the routing table and advertise `/kad/1.0.0`
- [ ] `PUT_VALUE` / `GET_VALUE` implemented with local record storage, validation, selection, refresh, and expiry behavior
- [ ] `ADD_PROVIDER` / `GET_PROVIDERS` implemented with provider storage, republish, and expiry behavior
- [ ] DHT integrated as an additional peer source in the address book alongside `/zeicoin/peers/1.0.0` and bootstrap config
- [ ] Stream/resource limits in place so DHT traffic cannot starve ZeiCoin protocol traffic
- [ ] `zig build test-libp2p` passes including new DHT unit tests
- [ ] Docker harness demonstrates peer discovery without static `ZEICOIN_BOOTSTRAP` config
- [ ] External interoperability smoke test passes against at least one real libp2p Kad implementation

## Notes

**Prerequisites** — do not start the core `/kad/1.0.0` implementation subtasks until all of these are confirmed:
- Persistent PeerId / identity keys (already done: `.libp2p_identity_<port>.key`)
- Peerbook foundation supports repeated multiaddrs per peer (`ZEI-91`)
- DNS/IPv6 address-family support is in place for discovery and identify (`ZEI-92`)
- Identify decoding safely skips unknown protobuf fields (`ZEI-93`)
- Dial backoff, peer dedup, and self-connection rejection (done)
- `zen_server` integration of the isolated libp2p path (done via `ZEI-11` / `ZEI-33`)
- Stream/resource limits so DHT traffic cannot starve ZeiCoin traffic (`ZEI-89`)
- Bootstrap nodes online long enough to seed routing tables

**Kademlia is a network-discovery/storage subsystem only** — it must not influence consensus, block validation, or mempool decisions. Peer addresses found via DHT go into the address book and are subject to the same scoring and dial logic as any other source.

**Spec:** `reference/libp2p-specs/kad-dht/README.md`. This ticket is now explicitly committed to the full libp2p Kad spec surface on `/kad/1.0.0`; partial ZeiCoin-only peer routing is out of scope for `ZEI-20`.

**Implementation note:** ZeiCoin should still land this incrementally. Wire compatibility, routing, query behavior, record/provider handling, and validation may be delivered in phases, but the overall ticket should only be considered done once the full spec-shaped surface is implemented and exercised.

**Implementation order:**
1. Reshape the address book into a Kad-ready peerbook (`ZEI-91`)
2. Add DNS/IPv6 multiaddr support to peer discovery and identify (`ZEI-92`)
3. Harden identify protobuf decoding for interop (`ZEI-93`)
4. Routing table (`k-bucket` structure, XOR distance, server/client-mode admission rules) (`ZEI-81`)
5. Protobuf + unsigned-varint Kademlia RPC codec on `/kad/1.0.0` (`ZEI-82`)
6. `PING` / `FIND_NODE` handler and iterative lookup client with bounded concurrency (`ZEI-83`)
7. Bootstrap self-lookup plus periodic refresh / random walk (`ZEI-84`)
8. `PUT_VALUE` / `GET_VALUE` and record validation/storage lifecycle (`ZEI-86`)
9. Wire into address book as a discovery source (`ZEI-85`)
10. Resource-limiting and fairness hardening (`ZEI-89`)
11. Docker harness validation without static bootstrap (`ZEI-87`)
12. External interoperability validation (`ZEI-90`)

**Key files to create:**
- `libp2p/dht/kademlia.zig` — routing table and RPC handlers
- `libp2p/dht/routing_table.zig` — k-bucket management
- `libp2p/dht/message.zig` — protobuf-backed Kademlia message codec
- `libp2p/dht/query.zig` — iterative lookup engine / bootstrap refresh logic
- `libp2p/dht/store.zig` — local value/provider record storage and expiry

**Key files to modify:**
- `libp2p/host/host.zig` — register Kad handlers and enforce protocol-level limits
- `src/apps/libp2p_testnode.zig` — start DHT on startup, feed discoveries to address book
- `src/core/network/peer_manager.zig` — consume DHT-discovered peers
