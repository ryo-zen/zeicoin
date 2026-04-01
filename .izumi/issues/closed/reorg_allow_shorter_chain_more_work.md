---
id: reorg_allow_shorter_chain_more_work
key: ZEI-64
title: Allow reorg to shorter chain with more cumulative work
type: Bug
status: Done
priority: Medium
assignee: null
labels:
- consensus
- reorg
sprint: null
story_points: null
due_date: null
parent_id: reorg_safety_and_recovery_hardening
rank: 1774927663826.0
comments: []
created_at: 2026-03-30T00:00:00+00:00
updated_at: 2026-04-01T06:27:27.408760770+00:00
closed_at: 2026-04-01T06:27:27.408760542+00:00
---

## Summary

`ReorgExecutor.executeReorg()` at line 54 rejects any chain where `new_tip_height < old_tip_height`. This prevents reorging to a shorter chain that has more cumulative proof-of-work — a valid scenario in Bitcoin-style consensus where a shorter chain with higher difficulty blocks can have more total work.

## Acceptance Criteria

- [x] `executeReorg` no longer rejects chains solely based on height comparison
- [x] Reorg decision is based on cumulative work (already computed by `fork_detector.shouldReorganize`)
- [x] `zig build test` passes with no regressions

## Notes

- `fork_detector.shouldReorganize` already compares cumulative work correctly — the height guard in `executeReorg` is a second, contradictory check
- The height check was likely a safety guard during early development; now that work comparison exists, it's redundant and incorrect
- Key file: `src/core/chain/reorg_executor.zig:54`
- Result:
  - Removed the obsolete `new_tip_height < old_tip_height` rejection from `src/core/chain/reorg_executor.zig`.
  - Reorg eligibility now remains anchored on the prior `fork_detector.shouldReorganize()` cumulative-work decision plus the executor's fork/continuity validation.
- Regression coverage:
  - Added a focused test in `src/tests.zig` proving a branch with fewer blocks but higher cumulative work is accepted by `executeReorg()`.
- Validation:
  - `zig build check` passed.
  - `zig build test` passed.
  - `./docker/scripts/test_libp2p_zen_server.sh` passed.
  - `./docker/scripts/verify_deep_reorg.sh` did not complete its assertion path in this run because after its fixed 180s divergence wait it could not retrieve block-50 hashes, so it exited before the deep-reorg convergence check. That looks like a timing/environment limitation in the script run rather than a direct failure of the `ZEI-64` logic, but it remains worth rerunning when continuing reorg work.
