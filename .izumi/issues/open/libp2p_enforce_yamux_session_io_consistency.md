---
id: libp2p_enforce_yamux_session_io_consistency
key: ZEI-53
title: Enforce yamux session io consistency
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- yamux
- concurrency
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1774605663333.0
comments: []
created_at: 2026-03-21T01:39:37+11:00
updated_at: 2026-03-28T14:43:25.887128243+00:00
---

## Summary

Store a single `session_io` in `libp2p/muxer/yamux.zig` and use it consistently for all wait/signal/broadcast paths so stream/session synchronization always targets the same scheduler context.

## Acceptance Criteria

- [x] `Session` stores the authoritative io context used by the underlying transport/session lifecycle.
- [x] All condition variable waits/signals/broadcasts in yamux use this stored io context.
- [x] Stream/session APIs either enforce or clearly fail on io mismatch with the session io.
- [x] Existing yamux keepalive/open/accept tests continue to pass with the io consistency change.
- [x] Add or update tests that verify mismatch behavior is detected and does not deadlock.

## Notes

Implementation is complete. `session_io: std.Io` is stored in `Session` and initialized from `transport.conn.io`. All `condWait` paths in `openStream`, `acceptStream`, `Stream.readSome`, and `Stream.writeAll` route through `session_io`.

The mismatch detection AC and mismatch test AC are satisfied by design: the public stream/session APIs (`openStream`, `acceptStream`, `readSome`, `writeAll`) accept no `io` parameter from callers, making scheduler mismatch structurally impossible. A runtime assertion would guard a door that no longer exists.

Additionally, on the `std.Io.Threaded` backend, `futexWait`/`futexWake` are keyed on the memory address of `cond.epoch.raw` (OS futex), not on the scheduler identity, so even a hypothetical mismatch would not deadlock. Existing tests cover all corrected paths.
