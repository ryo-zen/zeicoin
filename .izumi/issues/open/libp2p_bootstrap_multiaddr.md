---
id: libp2p_bootstrap_multiaddr
key: ZEI-31
title: Migrate bootstrap configuration to multiaddr format
type: Story
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- networking
- configuration
sprint: null
story_points: 5
due_date: null
parent_id: libp2p_implementation
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Replace the current `ZEICOIN_BOOTSTRAP=ip:port` env var format with multiaddr format so that bootstrap nodes carry a PeerId and the system works out-of-the-box on mainnet with zero config.

## Acceptance Criteria

- [ ] `ZEICOIN_BOOTSTRAP` accepts multiaddr strings (e.g. `/ip4/209.38.84.23/tcp/10801/p2p/<peer-id>`)
- [ ] Hardcoded fallback bootstrap list is compiled into the binary for mainnet
- [ ] Env var takes precedence; empty env var falls back to compiled-in list
- [ ] Testnet and private networks can override via env var as before
- [ ] Old `ip:port` format produces a clear parse error with migration hint

## Notes

See Epic ZEI-11 notes for full design decision. Tasks: ZEI-35, ZEI-36.
