---
id: dht_routing_table
key: ZEI-81
title: Implement Kademlia routing table with k-buckets and XOR distance
type: Subtask
status: Backlog
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
rank: null
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T00:00:00+00:00
---

## Summary

Implement the core Kademlia routing table in `libp2p/dht/routing_table.zig`. This is the foundational data structure for the DHT — distance is `XOR(sha256(key1), sha256(key2))` per spec, with k-buckets (k=20) that track known peers by proximity to the local node's key.

## Acceptance Criteria

- [ ] Distance function: `XOR(sha256(key1), sha256(key2))` — keys are sha256-hashed before XOR
- [ ] k-bucket structure with k=20, buckets for prefix lengths L in [0..255]
- [ ] Maintain k peers with shared key prefix of length L for every L
- [ ] Insertion follows Kademlia rules: least-recently-seen eviction, ping-and-replace for full buckets
- [ ] Server/client mode admission: only server-mode peers are added to the routing table (both client and server nodes enforce this)
- [ ] `closestPeers(target, count)` returns the `count` closest peers by XOR distance
- [ ] Unit tests covering insertion, eviction, sha256+XOR distance, and closest-peer queries

## Notes

- Create `libp2p/dht/routing_table.zig`
- PeerId is already available from the libp2p host layer
- Distance spec: "the distance between two keys is `XOR(sha256(key1), sha256(key2))`" — do NOT skip the sha256 step
- This is step 1 in the implementation order from ZEI-20
- Spec reference: `reference/libp2p-specs/kad-dht/README.md`
