---
id: libp2p_soak_churn_stress_harness
key: ZEI-50
title: Build libp2p soak and churn stress harness for reliability
type: Task
status: Done
priority: Medium
assignee: null
labels:
- libp2p
- testing
- reliability
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 35000.0
comments: []
created_at: 2026-03-19T00:00:00+00:00
updated_at: 2026-03-27T00:00:00+00:00
---

## Summary

Add a dedicated stress harness that goes beyond throughput benchmarking by running long-duration soak and stream churn scenarios for the Zig libp2p stack (`tcp`, `noise`, `yamux`) to catch memory leaks, race conditions, and lifecycle regressions.

## Acceptance Criteria

- [x] Add a runnable stress harness target (`zig build run-libp2p-stress`) with configurable duration, stream count, payload size, and churn rate
- [x] Implement a soak scenario that keeps sessions and streams active for extended runtime while validating no stalls or unexpected disconnects
- [x] Implement a churn scenario that repeatedly opens/closes/resets streams under load and validates protocol correctness and progress
- [x] Record and print reliability metrics: total streams opened/closed, failures by category, and final pass/fail status
- [x] Ensure stress runs detect leak regressions via GPA with `detectLeaks()` wrapping each scenario and each session_churn cycle
- [x] CI-safe profile (~1s total, default): `zig build run-libp2p-stress`; local soak profile (120s): `zig build run-libp2p-stress -- --soak`

## Test Results (2026-03-27, ReleaseFast)

### `zig build test-libp2p -Doptimize=ReleaseFast`
All 12 yamux unit tests: **PASS**

### `zig build run-libp2p-stress -Doptimize=ReleaseFast`
CI profile (duration=5s, sessions=8, streams=1000, payload=4096B, workers=4)

| Scenario | Opened | Closed | Errors | Sent | Recv | Rate |
|---|---|---|---|---|---|---|
| session_churn | 8 | 8 | 0 | 0.0MB | 0.0MB | 77 streams/s |
| stream_churn | 1000 | 1000 | 0 | 3.9MB | 3.9MB | 17354 streams/s |
| concurrent_chaos | 1000 | 1000 | 0 | 14.2MB | 14.2MB | 11105 streams/s |

Overall: **PASS**. No leaks detected (GPA clean on all scenarios).

## Notes

- In-process harness (`libp2p/libp2p_stress.zig`) replaced the Docker-only soak approach for unit-level reliability testing
- Docker soak (`./scripts/test_libp2p_docker.sh soak`) remains for multi-node TCP integration testing
- Sessions use `keepalive_interval_ms=100` in the harness to avoid blocking teardown on the default 15s keepalive sleep
