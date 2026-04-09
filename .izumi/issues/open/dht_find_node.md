---
id: dht_find_node
key: ZEI-83
title: Implement FIND_NODE handler and iterative lookup client
type: Subtask
status: InProgress
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
updated_at: 2026-04-09T13:33:54+10:00
---

## Summary

Implement FIND_NODE server handler and iterative lookup client in `libp2p/dht/query.zig`. The server returns the k closest known peers for a given target. The client performs iterative queries with bounded alpha concurrency until the closest set converges.

## Acceptance Criteria

- [ ] FIND_NODE request: `key` set to binary PeerId of target node
- [ ] FIND_NODE response: `closerPeers` set to k closest Peers from routing table
- [ ] Iterative lookup client with α=10 concurrent inflight requests (spec default)
- [ ] Seed initial candidates (`Pn`) with k closest peers from local routing table
- [ ] Termination: lookup ends when initiator has queried and gotten responses from the k closest nodes it has seen, or all known nodes exhausted
- [ ] Track queried set (`Pq`) and candidate set (`Pn`) sorted by distance ascending
- [ ] On response: add returned peers to `Pn` (excluding already-queried), discard errors/timeouts
- [ ] Store multiaddrs from encountered Peer records in peerbook
- [ ] Responses update the routing table with newly discovered peers
- [ ] Query engine is reusable by later `GET_VALUE` and `GET_PROVIDERS` lookups instead of being hard-coded to `FIND_NODE` only
- [ ] Unit tests for server handler, iterative convergence, and early termination

## Notes

- Create `libp2p/dht/query.zig`
- Depends on ZEI-81 (routing table) and ZEI-82 (codec)
- This is step 3 in the implementation order from ZEI-20
- Spec reference: peer routing algorithm in `reference/libp2p-specs/kad-dht/README.md`
- "Implementations may diverge from this base algorithm as long as they adhere to the wire format and make progress towards the target key"
- Current implementation boundary: `ZEI-83` owns `libp2p/dht/query.zig`, the inbound `/kad/1.0.0` request loop, `FIND_NODE` request/response handling, iterative lookup with bounded `alpha`, and Kad-learned peerbook/routing-table updates; bootstrap refresh stays with `ZEI-84`
