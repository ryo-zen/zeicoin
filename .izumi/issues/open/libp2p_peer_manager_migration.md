---
id: libp2p_peer_manager_migration
key: ZEI-40
title: Replace peer_manager TCP stack with libp2p connection management
type: Subtask
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- peer-manager
sprint: null
story_points: 8
due_date: null
parent_id: libp2p_zen_server_integration
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Rewrite `peer_manager.zig` to manage connections through the libp2p stack (TCP → Noise → Yamux) rather than raw TCP. The address book, scoring, dial backoff, and peer lifecycle logic from `libp2p_testnode.zig` should be merged in or replace the existing implementation.

## Acceptance Criteria

- [ ] `PeerManager` dials peers using `libp2p.dial()` (Noise + Yamux)
- [ ] `PeerManager` accepts inbound connections via the libp2p listener
- [ ] All connections are encrypted (no plaintext TCP peers remain)
- [ ] Dial backoff and peer scoring logic is preserved or improved
- [ ] `zen_server` starts up and syncs blocks successfully over the new stack

## Notes

Depends on ZEI-39 (protocol adapter) and ZEI-35/ZEI-36 (bootstrap config). This is the largest single change in the integration. Consider keeping the old path behind a compile flag during transition.
