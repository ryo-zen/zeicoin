---
id: libp2p_soak_churn_stress_harness
key: ZEI-50
title: Build libp2p soak and churn stress harness for reliability
type: Task
status: InProgress
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
rank: null
comments: []
created_at: 2026-03-19T00:00:00+00:00
updated_at: 2026-03-21T23:00:08+11:00
---

## Summary

Add a dedicated stress harness that goes beyond throughput benchmarking by running long-duration soak and stream churn scenarios for the Zig libp2p stack (`tcp`, `noise`, `yamux`) to catch memory leaks, race conditions, and lifecycle regressions.

## Acceptance Criteria

- [ ] Add a runnable stress harness target (for example `zig build run-libp2p-stress`) with configurable duration, stream count, payload size, and churn rate
- [x] Implement a soak scenario that keeps sessions and streams active for extended runtime (for example 30-120 minutes) while validating no stalls or unexpected disconnects
- [x] Implement a churn scenario that repeatedly opens/closes/resets streams under load and validates protocol correctness and progress
- [x] Record and print reliability metrics: total streams opened/closed, failures by category, reconnect/retry counts, and final pass/fail status
- [ ] Ensure stress runs detect leak regressions via allocator checks in test mode or explicit memory accounting in harness mode
- [ ] Add usage docs with at least one recommended CI-safe profile and one longer local profile

## Notes

Current progress (2026-03-21):

- local soak/churn mode was added to `./scripts/test_libp2p_docker.sh`
- periodic summaries record per-node peer counts, handshakes, discovery count, and failure buckets
- per-node logs plus `summary.log` are written under `tmp/libp2p-docker-soak-*`
- a 30-minute run completed with `PASS`

Remaining work:

- move the harness into tracked paths / a first-class target
- add explicit leak accounting or test-mode allocator enforcement
- document CI-safe and longer local profiles
