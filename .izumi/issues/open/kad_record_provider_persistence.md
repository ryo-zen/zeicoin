---
id: kad_record_provider_persistence
key: ZEI-97
title: Decide persistence strategy for Kad value and provider records
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- dht
- networking
- storage
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

Decide whether Kad value records and provider records should remain in-memory only or survive process restarts. The current `libp2p/dht/store.zig` implementation is intentionally in-memory so the wire behavior could land quickly, but that leaves restart behavior, GC semantics, and operational expectations undefined.

## Acceptance Criteria

- [ ] The project explicitly chooses in-memory-only or persistent Kad record storage
- [ ] Restart behavior is documented for both value and provider records
- [ ] If persistence is chosen, the storage boundary and schema are defined
- [ ] Expiry and republish behavior remain clear after the decision

## Notes

- Relevant file: `libp2p/dht/store.zig`
- This should document future expectations even if the immediate answer is “stay ephemeral for now”
