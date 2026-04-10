---
id: kad_record_provider_persistence
key: ZEI-97
title: Decide persistence strategy for Kad value and provider records
type: Task
status: Done
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
rank: 1775711759957.0
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T08:15:43.389413599+00:00
closed_at: 2026-04-09T08:15:43.389412577+00:00
---

## Summary

Decide whether Kad value records and provider records should remain in-memory only or survive process restarts. The current `libp2p/dht/store.zig` implementation is intentionally in-memory so the wire behavior could land quickly, but that leaves restart behavior, GC semantics, and operational expectations undefined.

## Acceptance Criteria

- [x] The project explicitly chooses in-memory-only or persistent Kad record storage
- [x] Restart behavior is documented for both value and provider records
- [x] If persistence is chosen, the storage boundary and schema are defined
- [x] Expiry and republish behavior remain clear after the decision

## Notes

- Relevant file: `libp2p/dht/store.zig`
- This should document future expectations even if the immediate answer is “stay ephemeral for now”
- Decision: keep Kad value records and provider records in-memory only for now. This is treated as ephemeral network cache / rendezvous state rather than durable node state.
- Restart behavior: a process restart drops all cached remote Kad values and provider records, and also drops any locally-originated Kad records/providers that were only present in memory. After restart, the node rebuilds Kad state through fresh network activity and future local republishes rather than replaying a persisted Kad store.
- Persistence boundary: not applicable under the current decision. No on-disk schema is introduced for Kad records/providers in this ticket.
- Expiry / republish semantics remain those implemented in `libp2p/dht/store.zig`: value expiry `48h`, provider validity `48h`, republish interval `22h`, with republish tracking applying only to locally-originated entries.
