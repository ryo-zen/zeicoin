---
id: dht_provider_value_records
key: ZEI-86
title: Implement Kademlia value and provider record support
type: Subtask
status: Done
priority: Low
assignee: null
labels:
- libp2p
- dht
- networking
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775709881653.0
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T07:46:50.545865660+00:00
closed_at: 2026-04-09T07:46:50.545865402+00:00
---

## Summary

Implement the full Kad record layer for `/kad/1.0.0`: `PUT_VALUE`, `GET_VALUE`, `ADD_PROVIDER`, and `GET_PROVIDERS`, backed by local storage plus the refresh, expiry, and validation behavior needed for spec-respecting operation.

## Acceptance Criteria

- [x] Local record store implemented for Kad values and provider records
- [x] `PUT_VALUE` validates and stores records before acknowledgement
- [x] `GET_VALUE` returns the best local record when present plus `closerPeers` from the routing table
- [x] Record validation/select logic is explicit so conflicting values can be rejected or ordered deterministically
- [x] Republish / refresh behavior implemented for locally originated records
- [x] Expiry / garbage-collection behavior implemented for stale values and stale provider records
- [x] `ADD_PROVIDER` validates the provided key and only records provider peers matching the RPC sender rules required by the spec
- [x] `GET_PROVIDERS` returns known provider peers plus `closerPeers`
- [x] Unit tests cover record store behavior, request handlers, expiry, and refresh
- [x] Storage behavior is documented clearly enough to support future persistence decisions

## Notes

- This is step 6 in the implementation order from ZEI-20
- Depends on ZEI-82 (codec) and should reuse the query engine shaped in ZEI-83
- The spec includes entry validation, correction, provider republish, and provider expiry; do not reduce this ticket to handler stubs only
- Local implementation now adds `libp2p/dht/store.zig` as an in-memory Kad record/provider store with explicit deterministic value selection, expiry, and due-for-republish tracking; `libp2p/dht/query.zig` now serves `PUT_VALUE`, `GET_VALUE`, `ADD_PROVIDER`, and `GET_PROVIDERS` on top of that store.
- The current value-selection policy is intentionally simple and explicit until namespaced validators exist: conflicting values are ordered with `std.mem.order` on raw record bytes, and lower-sorting values are rejected as older.
- Validation currently covers `zig build check`, `zig build test`, DHT-only libp2p tests, and the Kad Docker smoke; the full `zig build test-libp2p` still trips the known flaky Yamux keepalive test late in the run after the new Kad tests have already passed.
