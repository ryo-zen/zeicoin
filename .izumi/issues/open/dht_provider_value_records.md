---
id: dht_provider_value_records
key: ZEI-86
title: Implement Kademlia value and provider record support
type: Subtask
status: Backlog
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
rank: null
comments: []
created_at: 2026-04-09T00:00:00+00:00
updated_at: 2026-04-09T11:01:53+10:00
---

## Summary

Implement the full Kad record layer for `/kad/1.0.0`: `PUT_VALUE`, `GET_VALUE`, `ADD_PROVIDER`, and `GET_PROVIDERS`, backed by local storage plus the refresh, expiry, and validation behavior needed for spec-respecting operation.

## Acceptance Criteria

- [ ] Local record store implemented for Kad values and provider records
- [ ] `PUT_VALUE` validates and stores records before acknowledgement
- [ ] `GET_VALUE` returns the best local record when present plus `closerPeers` from the routing table
- [ ] Record validation/select logic is explicit so conflicting values can be rejected or ordered deterministically
- [ ] Republish / refresh behavior implemented for locally originated records
- [ ] Expiry / garbage-collection behavior implemented for stale values and stale provider records
- [ ] `ADD_PROVIDER` validates the provided key and only records provider peers matching the RPC sender rules required by the spec
- [ ] `GET_PROVIDERS` returns known provider peers plus `closerPeers`
- [ ] Unit tests cover record store behavior, request handlers, expiry, and refresh
- [ ] Storage behavior is documented clearly enough to support future persistence decisions

## Notes

- This is step 6 in the implementation order from ZEI-20
- Depends on ZEI-82 (codec) and should reuse the query engine shaped in ZEI-83
- The spec includes entry validation, correction, provider republish, and provider expiry; do not reduce this ticket to handler stubs only
