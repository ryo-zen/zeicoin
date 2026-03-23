---
id: env_file_issues
key: ZEI-6
title: Fix password.zig TEST_MODE bypass and review systemd deployment docs
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- config
- testing
- docs
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

Two minor items remain open after the env config cleanup. The main dotenv loading, inline comment stripping, and binary enablement issues have all been resolved.

## Acceptance Criteria

- [ ] `getPasswordForWallet()` in `src/core/util/password.zig` checks `types.TEST_MODE` and skips the interactive prompt (returning a default password) when TEST_MODE is true
- [ ] Systemd deployment docs in `systemd/` reviewed and updated to reflect current binary names and env file structure

## Notes

- **Workaround**: Set `ZEICOIN_WALLET_PASSWORD` in the environment to bypass the prompt in Docker/CI — this already works correctly and is not blocking
- Fix location: `src/core/util/password.zig:139` — `getPasswordForWallet()`
- Related: `src/core/types/types.zig` — `TEST_MODE` constant
