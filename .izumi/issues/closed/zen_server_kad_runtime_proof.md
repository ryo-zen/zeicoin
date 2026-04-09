---
id: zen_server_kad_runtime_proof
key: ZEI-98
title: Validate Kad behavior in the full zen_server runtime
type: Task
status: Done
priority: Low
assignee: null
labels:
- libp2p
- dht
- networking
- testing
sprint: null
story_points: null
due_date: null
parent_id: kademlia_dht
rank: 1775711759957.0
comments: []
created_at: 2026-04-09T15:05:00+10:00
updated_at: 2026-04-09T07:46:50.560295373+00:00
closed_at: 2026-04-09T07:46:50.560294330+00:00
---

## Summary

Prove that the Kad discovery path behaves correctly in the actual `zen_server` runtime, not just in the isolated `libp2p_testnode` harness. The dedicated Kad smoke is already valuable, but it does not yet show that the full node lifecycle, configuration, and service wiring behave the same way under real runtime conditions.

## Acceptance Criteria

- [x] Test plan identifies the runtime topology and validation command(s)
- [x] `zen_server` nodes can expose and use the Kad discovery path in a controlled test
- [x] Discovery and refresh behavior are observed in runtime logs or metrics
- [x] Any gaps between `libp2p_testnode` and `zen_server` behavior are documented explicitly

## Notes

- This is lower priority than fixing external interop because the current dedicated smoke already proves the isolated Kad subsystem
- Relevant areas: runtime startup wiring under `src/core/network/`, Docker/runtime harness scripts
