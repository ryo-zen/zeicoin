---
id: kad_value_validation_policy
key: ZEI-96
title: Define Kad value validation and selection policy
type: Task
status: Backlog
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
rank: null
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T15:05:00+10:00
---

## Summary

Replace the current placeholder Kad value-selection rule with an explicit long-term policy. Right now conflicting values are ordered with `std.mem.order` on raw record bytes so the store is deterministic, but that is only a temporary stand-in until the project decides what namespaced validators or record semantics it actually wants.

## Acceptance Criteria

- [ ] The supported Kad value namespaces and validation rules are documented
- [ ] Conflicting-value selection is defined explicitly for each supported namespace
- [ ] The implementation rejects malformed or unsupported records clearly
- [ ] Tests cover at least one conflict-resolution case beyond raw byte ordering

## Notes

- Current placeholder logic lives in `libp2p/dht/store.zig`
- This should stay scoped to network infrastructure and not leak consensus policy into Kad
