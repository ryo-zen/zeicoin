---
id: dht_bootstrap_refresh
key: ZEI-84
title: Implement DHT bootstrap self-lookup and periodic refresh
type: Subtask
status: Backlog
priority: Medium
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

Implement the DHT bootstrap procedure and periodic routing table maintenance. On startup and periodically, the node performs lookups to keep the routing table filled and healthy.

## Acceptance Criteria

- [ ] Runs once on startup, then periodically (default: 10 minutes)
- [ ] On every run: generate a random PeerId for every **non-empty** k-bucket, look it up via FIND_NODE iterative lookup
- [ ] Include a self-lookup (own PeerId) to improve awareness of nearby nodes
- [ ] Peers encountered during lookups are inserted into routing table as per normal rules
- [ ] Each run is subject to QueryTimeout (default: 10 seconds) — abort run on timeout
- [ ] Refresh interval configurable
- [ ] Bootstrap process is usable by the full Kad node before value/provider traffic starts
- [ ] Unit tests for bootstrap sequence, refresh scheduling, and timeout abort

## Notes

- This is step 4 in the implementation order from ZEI-20
- Depends on ZEI-83 (FIND_NODE)
- Spec: "generate a random peer ID for every non-empty routing table's k-bucket" — not all 256 buckets, only non-empty ones
- Spec reference: bootstrap process section in `reference/libp2p-specs/kad-dht/README.md`
