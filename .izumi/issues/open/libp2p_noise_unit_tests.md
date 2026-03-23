---
id: libp2p_noise_unit_tests
key: ZEI-45
title: Add unit tests for Noise XX handshake spec compliance
type: Subtask
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- noise
- testing
sprint: null
story_points: 3
due_date: null
parent_id: libp2p_integration_testing
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-21T23:00:08+11:00
---

## Summary

Add unit tests for `security/noise.zig` covering the XX handshake, symmetric crypto round-trips, peer identity enforcement, and nonce exhaustion guards.

## Acceptance Criteria

- [x] Test: initiator + responder complete XX handshake in-process (pipe)
- [x] Test: encrypted write on one side is correctly decrypted on the other
- [x] Test: connection from unexpected PeerId is rejected during handshake
- [x] Test: nonce overflow / reuse is caught
- [x] All tests use `std.testing.allocator`

## Notes

Implemented in `libp2p/security/noise.zig`:

- `noise concurrent handshake helpers`
- `symmetricstate encrypt/decrypt roundtrip`
- `noise wrong peer id is rejected during handshake`
- `noise cipher nonce exhaustion is rejected`

Verified as part of `zig build test-libp2p`.
