---
id: verify_peer_chain_work_locally
key: ZEI-67
title: Verify peer chain work from block headers instead of trusting self-report
type: Bug
status: Done
priority: High
assignee: null
labels:
  - consensus
  - security
  - reorg
  - mainnet-blocking
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-03-30T06:48:09+00:00
---

## Summary

`fork_detector.shouldReorganize` calls `requestChainWork` which asks the peer "how much cumulative work does your chain have?" and trusts the response. A malicious peer can report inflated work to trick the node into reorging to a weaker chain. Since the node already fetches the peer's actual blocks during `executeBulkReorg`, the work should be computed locally from those block headers.

## Acceptance Criteria

- [x] Cumulative chain work for the peer's fork is computed locally from the fetched block headers, not from the peer's self-reported value
- [x] `requestChainWork` RPC is either removed or demoted to a hint that must be verified
- [x] The reorg decision (`shouldReorganize`) uses locally-verified work
- [x] `zig build test` passes with no regressions

## Notes

- Landed in the reorg replay/state-root fix series culminating in `8d044f0`.
- `startSync()` now fetches the competing branch before making the reorg decision, `fork_detector.shouldReorganize()` sums `header.getWork()` from those fetched blocks locally, and `executeBulkReorg()` reuses the same prefetched slice.
- `GetChainWork` remains available as a protocol message, but the reorg decision path no longer trusts peer self-report.
- Related: `ZEI-52` covers reorg depth limits and consensus mode; this ticket covered the work-comparison trust model.
- Key files: `src/core/sync/fork_detector.zig`, `src/core/sync/manager.zig`
