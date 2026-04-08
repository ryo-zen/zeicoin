---
id: libp2p_build_zig_reenable
key: ZEI-44
title: Re-enable libp2p testnode and bench build targets in build.zig
type: Subtask
status: Done
priority: High
assignee: null
labels:
- libp2p
- build
sprint: null
story_points: 1
due_date: null
parent_id: libp2p_integration_testing
rank: 1774094705520.0
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-26T11:54:18.646296062+00:00
---

## Summary

`run-libp2p-testnode` and `run-libp2p-bench` are commented out in `build.zig` with a stale TODO saying "when libp2p source files are present" — but the source files exist. Uncommenting these is a prerequisite for running integration tests and benchmarks locally.

## Acceptance Criteria

- [x] `zig build run-libp2p-testnode` builds and runs cleanly
- [x] `zig build run-libp2p-bench` builds and runs cleanly
- [x] Both targets are verified against current Zig 0.16 API (no stale imports)
- [x] Stale TODO comments removed

## Notes

Verified on 2026-03-21 with:

- `timeout 8s zig build run-libp2p-testnode -- /ip4/127.0.0.1/tcp/10811`
- `zig build -Doptimize=ReleaseFast run-libp2p-bench -- --stack tcp-noise-yamux --direction upload --duration-secs 1 --iterations 1`

This unblocked ZEI-42 (test suite) and the current Docker discovery harness work.
