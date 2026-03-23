---
id: libp2p_connection_pool
key: ZEI-59
title: "Add connection pool to prevent duplicate dials to the same peer"
type: Task
status: Backlog
priority: Medium
assignee: null
labels: [libp2p, networking]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-24T00:00:00+00:00
updated_at: 2026-03-24T00:00:00+00:00
---

## Summary

Each outbound dial creates an isolated connection with no deduplication. If two parts of the node dial the same peer concurrently, two full Noise+Yamux sessions are established. The Go reference deduplicates via the host's internal connection manager.

## Acceptance Criteria

- [ ] `host/conn_pool.zig`: `ConnPool` keyed by `PeerId` returning existing `*Session` if connected
- [ ] Thread-safe: concurrent dials to same peer coalesce to one connection
- [ ] Eviction: remove entry when session is closed or errors
- [ ] `host.newStream()` checks pool before dialing

## Notes

Can be a simple `AutoHashMap(PeerId, *Session)` with a mutex initially. Depends on ZEI-56 (Host). The address book in `libp2p_testnode.zig` handles peer addresses separately — this is the active-connection layer only.
