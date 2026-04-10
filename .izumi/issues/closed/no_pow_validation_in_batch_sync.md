---
id: no_pow_validation_in_batch_sync
key: ZEI-102
title: Enforce PoW validation on every block received during batch sync
type: Bug
status: Done
priority: High
assignee: null
labels:
- consensus
- validation
- sync
- security
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1775735617832.0
comments: []
created_at: 2026-04-09T11:50:00+00:00
updated_at: 2026-04-09T11:56:38.249478382+00:00
closed_at: null
---

## Summary

`validateBlockBeforeApply` in the batch sync path only checks basic block structure and hash chain continuity. It never calls `validator.validateBlock` or `validateBlockPoW`. A peer can serve blocks with completely fabricated proof-of-work during batch sync and they will be accepted. This lets a malicious or buggy peer poison the local chain with blocks that would never pass the full validator used during normal block acceptance.

## Acceptance Criteria

- [x] `validateBlockBeforeApply` (or its callsite) calls `validator.validateBlock` including PoW before accepting any synced block
- [x] A block with a header that does not meet the required difficulty is rejected during sync with a clear log line
- [x] The full validator path and the sync path exercise the same PoW check function — no duplicated logic
- [x] Performance impact is understood: RandomX validation is expensive; if amortisation or caching is needed that should be noted explicitly
- [x] `zig build test` passes

## Notes

- Relevant files: `src/core/sync/manager.zig` (`validateBlockBeforeApply`, line ~1191), `src/core/chain/validator.zig` (`validateBlock`, `validateBlockPoW`)
- Current gap: `validateBlockBeforeApply` returns `true` after checking only structure and `previous_hash` continuity; PoW is never checked
- The full `validator.validateBlock` path is used when a locally-mined or peer-broadcast block is accepted via the normal `ChainManager` path — sync should use the same gate
- RandomX PoW validation spawns a subprocess; consider whether the sync context has access to the same `mining_context` the validator uses, and wire it accordingly
- This issue was surfaced during the ZEI-100 audit of the ZEI-81–99 DHT sprint
