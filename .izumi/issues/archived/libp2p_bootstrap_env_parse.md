---
id: libp2p_bootstrap_env_parse
key: ZEI-35
title: Parse multiaddr format from ZEICOIN_BOOTSTRAP env var
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- configuration
sprint: null
story_points: 2
due_date: null
parent_id: libp2p_bootstrap_multiaddr
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Update the bootstrap env var parsing logic to accept multiaddr strings instead of bare `ip:port`. The parser should extract the TCP address and PeerId component for identity-bound dialing.

## Acceptance Criteria

- [ ] `ZEICOIN_BOOTSTRAP=/ip4/x.x.x.x/tcp/10801/p2p/<peer-id>` parses correctly
- [ ] `/dns4/zei.network/tcp/10801` (no PeerId) is accepted and dialed without identity pinning
- [ ] Old `ip:port` format returns a clear error with a migration message
- [ ] Unit test covers valid multiaddr, missing PeerId, and invalid input

## Notes

Parse using the `multiaddr.zig` API already in `libp2p/multiaddr/`. Config loading lives in `src/core/util/config.zig`.
