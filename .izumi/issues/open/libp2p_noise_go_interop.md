---
id: libp2p_noise_go_interop
key: ZEI-94
title: Fix libp2p Noise interoperability with go-libp2p
type: Task
status: Backlog
priority: High
assignee: null
labels:
- libp2p
- noise
- networking
- interop
sprint: null
story_points: null
due_date: null
parent_id: libp2p_kademlia_dht
rank: null
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T15:05:00+10:00
---

## Summary

Fix the remaining Noise handshake mismatch between ZeiCoin and a real go-libp2p host. The new Go interop harness now proves the blocker happens before `/kad/1.0.0`: ZeiCoin aborts bootstrap against the Go host with `AuthenticationFailed`, so external Kad validation cannot proceed until the security transport is wire-compatible.

## Acceptance Criteria

- [ ] ZeiCoin can complete a Noise handshake with a real go-libp2p host over TCP
- [ ] The root cause of the current `AuthenticationFailed` mismatch is documented clearly
- [ ] The Go interop harness reaches application protocol negotiation after the fix
- [ ] `zig build test-libp2p` remains green after the compatibility fix

## Notes

- Relevant files: `libp2p/security/noise.zig`, `tools/go_kad_interop/`, `docker/scripts/test_kad_go_interop.sh`
- One spec correction already landed locally during this investigation: the Noise protocol name is no longer hashed unconditionally when it fits in 32 bytes
- This is a prerequisite for meaningful progress on `ZEI-90`
