---
id: reshape_address_book_into_peerbook
key: ZEI-91
title: Reshape address book into a Kad-ready peerbook
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- dht
- networking
- architecture
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775697307708.0
comments: []
created_at: 2026-04-09T11:14:22+10:00
updated_at: 2026-04-09T01:47:36.983610248+00:00
closed_at: 2026-04-09T01:46:35.986988984+00:00
---

## Summary

Reshape `libp2p/peer/address_book.zig` from a flat address list into a real peerbook keyed by peer identity. Full `/kad/1.0.0` work needs to retain multiple multiaddrs per peer plus enough metadata to merge addresses learned from identify, peer exchange, and Kad `Message.Peer` records without redesigning the storage model mid-implementation.

## Acceptance Criteria

- [x] Peer identity becomes the primary storage key when a PeerId is known
- [x] A single peer entry can store repeated canonical multiaddrs rather than only one flat address
- [x] Address metadata preserves source information for identify, peer exchange, bootstrap config, and Kad peer records
- [x] Existing dial scoring, backoff, last-seen, and self-observation behavior is preserved or cleanly migrated to the new shape
- [x] Peerbook API exposes a clear path for “learn peer with one or more multiaddrs” so Kad handlers do not have to special-case storage
- [x] Snapshot or debug views remain usable for tests and operator inspection
- [x] `zig build test-libp2p` passes with updated peerbook tests covering multiaddr aggregation and deduplication

## Notes

- Primary file: `libp2p/peer/address_book.zig`
- This should land before `ZEI-81` and before any `FIND_NODE` work in `ZEI-83`
- The goal is to avoid baking single-address assumptions into routing, query, and record/provider layers
