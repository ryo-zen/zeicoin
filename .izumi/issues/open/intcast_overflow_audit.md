---
id: intcast_overflow_audit
key: ZEI-7
title: Audit and fix unsafe @intCast usages in consensus and network paths
type: Task
status: Backlog
priority: High
assignee: null
labels:
- security
- consensus
- audit
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-03-10T00:00:00+00:00
---

## Summary

The codebase has ~115 `@intCast` usages across 33 files. In Zig, `@intCast` panics in debug builds and produces undefined behaviour in release builds if the value does not fit the target type. Several usages operate on attacker-controlled data (block heights, network message fields) and are potential exploits or consensus-breaking bugs.

## Acceptance Criteria

- [ ] High-risk arithmetic-before-cast patterns fixed in `src/core/chain/validator.zig:690-691` and `src/core/chain/operations.zig:129,145,153` with checked subtraction guards
- [ ] Medium-risk `usize → u32` casts in `src/core/sync/protocol/batch_sync.zig` replaced with `std.math.cast(u32, i) orelse return error.BlockIndexOverflow`
- [ ] All remaining `@intCast` on network-derived values audited and either guarded or documented as safe
- [ ] `zig build test` passes with no regressions

## Notes

**Fix pattern for arithmetic-before-cast:**
```zig
// Before (unsafe):
const old_height: u32 = @intCast(height - lookback_blocks);

// After (safe):
if (height < lookback_blocks) return error.InsufficientChainHistory;
const old_height: u32 = @intCast(height - lookback_blocks);
```

**Priority order:**

| File | Risk |
|------|------|
| `src/core/chain/validator.zig` | High — consensus, external data |
| `src/core/chain/operations.zig` | High — consensus, height arithmetic |
| `src/core/sync/protocol/batch_sync.zig` | Medium — network data |
| `src/core/chain/block_index.zig` | Medium — internal counts |
| `src/core/crypto/bech32.zig` (18 uses) | Low — format-bounded |
| `src/core/crypto/bip39.zig` (13 uses) | Low — wordlist indices |

Reference safe implementation: `src/core/rpc/server.zig:451-463` — `validateU64FromJson` and `validateU32FromUsize` helpers.
