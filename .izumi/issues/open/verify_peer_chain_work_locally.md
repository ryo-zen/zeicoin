---
id: verify_peer_chain_work_locally
key: ZEI-67
title: Verify peer chain work from block headers instead of trusting self-report
type: Bug
status: Backlog
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
updated_at: 2026-03-30T00:00:00+00:00
---

## Summary

`fork_detector.shouldReorganize` calls `requestChainWork` which asks the peer "how much cumulative work does your chain have?" and trusts the response. A malicious peer can report inflated work to trick the node into reorging to a weaker chain. Since the node already fetches the peer's actual blocks during `executeBulkReorg`, the work should be computed locally from those block headers.

## Acceptance Criteria

- [ ] Cumulative chain work for the peer's fork is computed locally from the fetched block headers, not from the peer's self-reported value
- [ ] `requestChainWork` RPC is either removed or demoted to a hint that must be verified
- [ ] The reorg decision (`shouldReorganize`) uses locally-verified work
- [ ] `zig build test` passes with no regressions

## Notes

- The fix can be as simple as: fetch blocks first (already done in `executeBulkReorg`), compute work from headers, then decide whether to reorg
- This reorders the current flow slightly — currently decide-then-fetch, should be fetch-then-decide
- Alternatively: fetch only headers first (lighter), compute work, then fetch full blocks if reorg is warranted
- Related: ZEI-52 covers reorg depth limits and consensus mode; this ticket covers the work comparison trust model
- Key files: `src/core/sync/fork_detector.zig:152-190`, `src/core/sync/manager.zig:1061`
