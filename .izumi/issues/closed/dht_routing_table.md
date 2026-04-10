---
id: dht_routing_table
key: ZEI-81
title: Implement Kademlia routing table with k-buckets and XOR distance
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775701383196.0
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T02:36:54.801929042+00:00
closed_at: 2026-04-09T02:36:54.801927352+00:00
---

## Summary

Implement the core Kademlia routing table in `libp2p/dht/routing_table.zig`. This is the foundational data structure for the DHT — distance is `XOR(sha256(key1), sha256(key2))` per spec, with k-buckets (k=20) that track known peers by proximity to the local node's key.

## Acceptance Criteria

- [x] Distance function: `XOR(sha256(key1), sha256(key2))` — keys are sha256-hashed before XOR
- [x] k-bucket structure with k=20, buckets for prefix lengths L in [0..255]
- [x] Maintain k peers with shared key prefix of length L for every L
- [x] Insertion follows Kademlia rules: least-recently-seen eviction, ping-and-replace for full buckets
- [x] Server/client mode admission: only server-mode peers are added to the routing table (both client and server nodes enforce this)
- [x] Routing-table entries retain enough peer metadata to serialize valid Kad `Peer` responses (peer ID, multiaddrs, connection state / mode classification inputs)
- [x] `closestPeers(target, count)` returns the `count` closest peers by XOR distance
- [x] Unit tests covering insertion, eviction, sha256+XOR distance, and closest-peer queries

## Notes

- Create `libp2p/dht/routing_table.zig`
- PeerId is already available from the libp2p host layer
- Distance spec: "the distance between two keys is `XOR(sha256(key1), sha256(key2))`" — do NOT skip the sha256 step
- This is step 1 in the implementation order from ZEI-20
- The routing table should be reusable by `FIND_NODE`, `GET_VALUE`, and `GET_PROVIDERS` lookups, not just peer discovery
- Spec reference: `reference/libp2p-specs/kad-dht/README.md`
- Validation: `zig build test-libp2p`
