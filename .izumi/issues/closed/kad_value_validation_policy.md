---
id: kad_value_validation_policy
key: ZEI-96
title: Define Kad value validation and selection policy
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- design
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775711759957.0
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T08:21:41.684670595+00:00
closed_at: 2026-04-09T08:21:41.684669717+00:00
---

## Summary

Replace the current placeholder Kad value-selection rule with an explicit long-term policy. Right now conflicting values are ordered with `std.mem.order` on raw record bytes so the store is deterministic, but that is only a temporary stand-in until the project decides what namespaced validators or record semantics it actually wants.

## Acceptance Criteria

- [x] The supported Kad value namespaces and validation rules are documented
- [x] Conflicting-value selection is defined explicitly for each supported namespace
- [x] The implementation rejects malformed or unsupported records clearly
- [x] Tests cover at least one conflict-resolution case beyond raw byte ordering

## Notes

- Current placeholder logic lives in `libp2p/dht/store.zig`
- This should stay scoped to network infrastructure and not leak consensus policy into Kad
- ZeiCoin now follows the go-libp2p shape of namespaced value validation instead of treating Kad values as generic blobs with raw-byte ordering.
- Current supported namespace: `/zei/...`
- `/zei/...` validation rule: keys must be namespaced, values must use the explicit format `seq:<u64>:<payload>`, and malformed values are rejected.
- `/zei/...` selection rule: the record with the higher parsed sequence wins; identical values refresh in place; different payloads at the same sequence are rejected as conflicting rather than ordered arbitrarily.
- Unsupported namespaces are rejected clearly instead of being accepted with placeholder byte-order semantics.
- Validation: `zig build test-libp2p` (`94 passed; 1 skipped; 0 failed`).
