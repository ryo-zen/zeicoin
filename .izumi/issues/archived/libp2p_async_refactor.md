---
id: libp2p_async_refactor
key: ZEI-10
title: Refactor libp2p stack to use std.Io async primitives (io.concurrent, io.Group, io.Queue)
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- networking
- async
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1773129708377.0
comments: []
created_at: 2026-03-08T00:00:00+00:00
updated_at: 2026-03-10T08:06:38.142639040+00:00
---

## Summary

The libp2p stack uses raw `std.Thread.spawn`, hand-rolled `SpinLock`, and direct vtable calls for I/O. This plan wires in `io.concurrent()`, `io.Group`, `io.Queue(T)`, and the `net.Stream` reader/writer abstraction, making the stack fully leverage Zig 0.16's execution-model-agnostic async design. The Yamux refactor (Phase 3) simultaneously closes remaining yamux spec gaps.

## Acceptance Criteria

- [x] **Phase 1**: `TcpConnection` uses `net.Stream.Reader`/`Writer` instead of direct `io.vtable.netRead`/`netWrite` calls
- [x] **Phase 2**: Accept loop replaced with `io.concurrent()` + `io.Group`; `Thread.spawn` removed
- [x] **Phase 3**: Yamux `Session` has explicit `SessionState`/`StreamState` enum, per-stream flow control, WINDOW_UPDATE, ping/pong, go-away, and bounded ACK backlog
- [x] **Phase 4**: `AddressBook` `SpinLock` replaced with `std.Thread.Mutex` (kernel-backed, no busy-wait)
- [x] **Phase 4b**: Reachable address advertisement promoted from real self-observations (identify `observedAddr` + self-echoed peer-exchange entries)
- [x] **Phase 5**: `build.zig` option `-Devented=true` selects `std.Io.Evented` (io_uring) backend
- [x] `zig build test-libp2p` passes after each phase

## Notes

- Prerequisite: `libp2p_implementation` (ZEI-11) transport layer stable
- Phase ordering: 1 → 2 → 4 → 4b → 3 → 5 (Phase 3 is highest risk, do last)
- Phase 3 yamux rules: odd stream IDs for initiator, even for responder; session control on stream 0 only; 256 KiB per-stream initial windows; inbound accept backlog capped at 64; outbound ACK backlog capped at 256
- Key files: `libp2p/transport/tcp.zig`, `libp2p/muxer/yamux.zig`, `src/apps/libp2p_testnode.zig`, `build.zig`
