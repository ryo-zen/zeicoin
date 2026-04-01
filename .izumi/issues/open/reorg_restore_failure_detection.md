---
id: reorg_restore_failure_detection
key: ZEI-66
title: Surface chain corruption when reorg restore fails
type: Bug
status: Todo
priority: Medium
assignee: null
labels:
- consensus
- reorg
- observability
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774927672826.0
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-03-31T09:19:15.006661284+00:00
closed_at: null
---

## Summary

The restore path is much stronger now than when this ticket was opened: `restoreOriginalChain` attempts an atomic snapshot restore, falls back to replaying the original canonical segment, and verifies the restored state root. The remaining gap is that `ReorgExecutor` still cannot explicitly signal to its caller that restore itself failed or that the node should stop normal operation and resync. In the revert/apply failure branches it logs a CRITICAL restore failure but still returns an ordinary failed reorg result, and the caller still reduces that to a generic `error.ReorgFailed`.

## Acceptance Criteria

- [ ] `ReorgResult` includes a `chain_corrupted: bool` field (or equivalent typed failure signal) that is set when restore fails or post-restore verification cannot prove canonical state was recovered
- [ ] The caller (`ChainProcessor.executeBulkReorg`) checks for corruption and triggers a full resync/quarantine path instead of returning only generic `error.ReorgFailed`
- [x] A `log.err` with "CRITICAL" severity is emitted so operators can detect restore failure in monitoring
- [ ] A focused regression test covers restore-failure surfacing and proves the caller enters the resync/quarantine path
- [ ] `zig build test` passes with no regressions

## Notes

- Restore robustness improved during the snapshot/reorg hardening series:
  - atomic snapshot restore is attempted first
  - replay fallback restores the original canonical segment if the snapshot path cannot be prepared
  - restored state is verified against the expected state root
- Remaining scope is observability/recovery orchestration, not basic restore capability.
- Current caller behavior is still too lossy:
  - `ReorgExecutor` can log a CRITICAL restore failure but return an ordinary failed reorg result
  - `ChainProcessor.executeBulkReorg` still collapses that to generic `error.ReorgFailed`
- Ideal recovery: set a `needs_resync` or equivalent fail-closed flag and restart sync from a known good checkpoint or bounded recovery anchor.
- Key files:
  - `src/core/chain/reorg_executor.zig`
  - `src/core/chain/processor.zig`
  - `src/core/sync/manager.zig`
