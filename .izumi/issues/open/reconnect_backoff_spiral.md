---
id: reconnect_backoff_spiral
key: ZEI-17
title: Fix reconnect backoff spiral caused by AlreadyConnected false failures
type: Bug
status: Backlog
priority: Low
assignee: null
labels:
- networking
- p2p
- reliability
sprint: null
story_points: null
due_date: null
parent_id: libp2p_implementation
rank: null
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-11T00:00:00+00:00
---

## Summary

Three related bugs can cause bootstrap reconnection to spiral into a 5-minute backoff under unlucky timing. The root cause of the Feb 2026 Sydney connectivity incident was a separate missing inter-bootstrap peering config (since fixed), but these bugs remain latent and could cause slow recovery if a bootstrap connection drops again.

## Acceptance Criteria

- [ ] `AlreadyConnected` in `peer.zig:516-521` sets `connection_succeeded = true` instead of incrementing the failure counter
- [ ] Reconnect trigger in `peer.zig:497` uses `getConnectedCount()` (counts only `.connected` state) instead of `getPeerStats().connected` (which includes `.connecting` and `.handshaking`)
- [ ] Max backoff in `peer.zig:479` reduced from 300s to 60s

## Notes

**Bug 1** (`peer.zig:549-556`): `AlreadyConnected` falls into the `catch` block and executes `continue`, skipping the `connection_succeeded = true` assignment at line 558. This means `connection_succeeded` stays false and `reconnect_consecutive_failures` is incremented after the loop. Confirmed unresolved in current code.

**Fix:**
```zig
if (err == error.AlreadyConnected) {
    connection_succeeded = true;  // already attempting — not a failure
    break;
}
```

**Bug 2** (`peer_manager.zig:870-871`): `.connecting` and `.handshaking` peers are counted as "connected" for maintenance purposes. While a peer is stuck in `.connecting` (TCP hang up to 120s), maintenance sees `connected > 0` and skips reconnection. `getConnectedCount()` at line 834 already exists and counts only `.connected`.

**Bug 3**: `calculateBackoff()` at `peer.zig:513` still has `max_backoff: u32 = 300` (5 minutes). Reduce to 60s.

Files: `src/core/network/peer.zig`, `src/core/network/peer_manager.zig`
