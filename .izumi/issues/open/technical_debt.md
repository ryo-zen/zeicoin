---
id: technical_debt
key: ZEI-19
title: Consolidate duplicate validation logic and establish consistent error handling conventions
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- code-quality
- technical-debt
- refactoring
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

Two categories of technical debt accumulate risk in the consensus and network paths: duplicated validation logic across mempool, block application, and sync replay; and inconsistent error handling patterns that make it hard to audit whether critical failures are silently swallowed.

## Acceptance Criteria

- [ ] Single canonical `validateTransaction` function used by all validation paths (mempool entry, block application, sync/reorg replay), with explicit flags for the few cases where behaviour legitimately differs (e.g., `force_processing`)
- [ ] Error handling convention documented and applied to consensus, block application, and mempool paths: clear rule for when to propagate (`try`) vs. log-and-continue vs. `catch unreachable`
- [ ] Audit of critical paths for silent error swallows (`catch |err| { log; return; }` on consensus operations) — each silent catch reviewed and either converted to propagation or documented with rationale

## Notes

**Duplicate validation locations:**
- Mempool entry validation
- Block application validation (`processBlockTransactions`)
- Sync/reorg replay validation (`force_processing = true` path)

Each path has slightly different behaviour, increasing the risk that a fix in one path is not applied to the others.

**Mixed error handling patterns currently in use:**
- `try` with propagation
- `catch |err| { log; return; }` (silent swallow)
- `catch unreachable`
- `catch continue` in loops

See `CLAUDE.md` logging guidelines for the existing convention between CLI (`std.debug.print`) and server (`std.log.scoped`) output — the error handling convention should build on this.
