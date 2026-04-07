---
id: extract_peer_manager_message_handlers
key: ZEI-80
title: Extract per-message handlers from peer_manager handleMessage()
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
  - refactor
  - readability
sprint: null
story_points: 3
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-04-07T00:00:00+00:00
updated_at: 2026-04-07T00:00:00+00:00
---

## Summary

`peer_manager.zig:handleMessage()` is ~200 lines with a giant switch statement where each message-type arm contains 10-40 lines of inline logic. Extract each arm into a dedicated handler function to improve readability and testability.

## Acceptance Criteria

- [ ] Each message type arm in the switch is delegated to a named handler function (e.g. `handleBlockMessage()`, `handleTransactionMessage()`, `handlePeerListMessage()`)
- [ ] The top-level `handleMessage()` switch is reduced to a dispatch table of one-line calls
- [ ] No behavioral changes - all existing message handling logic preserved
- [ ] `zig build check` and `zig build test` pass
- [ ] Shell tests under `tests/` pass

## Notes

- Identified during the SoC audit on 2026-04-07 but deferred as a standalone PR due to scope and risk
- Related audit also flagged: response queue boilerplate (10 near-identical lock/unlock methods at lines 259-284), duplicate shutdown logic between `cleanupTimedOut` and `stop`, and block cache (`received_blocks`) living in peer_manager rather than sync layer
- These related items can be addressed in follow-up work but are not required for this ticket
- Relevant file: `src/core/network/peer_manager.zig`
