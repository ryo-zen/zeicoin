---
id: dht_resource_limits_and_fairness
key: ZEI-89
title: Add Kademlia resource limits and protocol fairness controls
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
- reliability
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775696646333.0
comments: []
created_at: 2026-04-09T11:01:53+10:00
updated_at: 2026-04-09T08:11:34.132282877+00:00
closed_at: 2026-04-09T08:11:34.132282388+00:00
---

## Summary

Protect ZeiCoin's libp2p stack from Kad abuse and starvation. Full `/kad/1.0.0` support adds new inbound and outbound RPC traffic, so the implementation needs explicit limits and fairness controls to prevent DHT work from monopolising streams, memory, or scheduling needed by the ZeiCoin protocol.

## Acceptance Criteria

- [x] Per-peer and global limits exist for concurrent Kad RPC streams
- [x] Request size and response size limits exist for Kad protobuf messages
- [x] Lookup concurrency and maintenance jobs are bounded so Kad traffic cannot starve `/zeicoin/1.0.0`
- [x] Timeout and cancellation behavior is explicit for inbound handlers and outbound queries
- [x] Misbehaving or malformed Kad peers are handled by reset/close/quarantine behavior consistent with the host stack
- [x] Unit or integration tests cover at least one starvation/abuse scenario and one oversized or malformed message scenario

## Notes

- This should modify `libp2p/host/host.zig` and/or the Kad service layer rather than relying on informal caller discipline
- The Kad spec defines wire behavior, but ZeiCoin still needs local protection so the DHT cannot degrade sync or mempool traffic
- Keep the limits configurable enough for Docker and interoperability testing
- Local implementation now enforces configurable inbound Kad stream budgets in `libp2p/dht/query.zig` with both per-peer and global counters, closes over-budget streams, and penalizes malformed/abusive inbound peers through the shared address-book failure path when a remote address is known.
- Validation: `zig build test-libp2p` (`93 passed; 1 skipped; 0 failed`), including the new limit-enforcement and malformed-stream Kad tests.
