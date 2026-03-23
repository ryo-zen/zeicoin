---
id: enforce_yamux_session_io_consistency
key: ZEI-53
title: "Enforce yamux session io consistency"
type: Task
status: Done
priority: Medium
assignee: null
labels: ["libp2p", "yamux", "concurrency"]
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-21T01:39:37+11:00
updated_at: 2026-03-21T01:39:37+11:00
---

## Summary

Store a single `session_io` in `libp2p/muxer/yamux.zig` and use it consistently for all wait/signal/broadcast paths so stream/session synchronization always targets the same scheduler context.

## Acceptance Criteria

- [ ] `Session` stores the authoritative io context used by the underlying transport/session lifecycle.
- [ ] All condition variable waits/signals/broadcasts in yamux use this stored io context.
- [ ] Stream/session APIs either enforce or clearly fail on io mismatch with the session io.
- [ ] Existing yamux keepalive/open/accept tests continue to pass with the io consistency change.
- [ ] Add or update tests that verify mismatch behavior is detected and does not deadlock.

## Notes

Current code fixed signal/broadcast call sites to use `self.transport.conn.io`, but wait paths still accept caller-provided `io` (`openStream`, `acceptStream`, `Stream.readSome`, `Stream.writeAll`). This can reintroduce scheduler mismatch if a different io is passed by callers.

Suggested implementation:
- add `session_io: std.Io` to `Session`
- initialize from transport/constructor io source
- route `condWait` through `session_io`
- add debug/runtime assertion or error return for mismatched caller io in stream/session public methods
