---
id: investigate_misleading_zig_build_test_failure_footer
key: ZEI-74
title: Investigate misleading zig build test failure footer on successful runs
type: Task
status: Done
priority: Low
assignee: null
labels:
- testing
- build
- developer-experience
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1775027637729.0
comments: []
created_at: 2026-04-01T07:13:36Z
updated_at: 2026-04-02T07:45:10.817580178+00:00
closed_at: 2026-04-02T07:45:10.817579379+00:00
---

## Summary

Investigate why `zig build test` prints a trailing `failed command: .../test --listen=-` line even when the overall command appears to succeed with exit code `0`. This is likely a test harness or Zig-nightly output quirk, but it makes passing runs look broken and wastes debugging time.

## Acceptance Criteria

- [ ] Reproduce the misleading footer and confirm the real process exit status
- [ ] Determine whether the message comes from ZeiCoin's build/test setup or from Zig itself
- [ ] Either fix the misleading output or document clearly why it is expected and how to interpret it
- [ ] `zig build test` output no longer looks like a failure on successful runs, or the repo docs/status notes clearly explain the behavior

## Notes

- Recent successful local runs for `ZEI-64` still ended with a trailing `failed command: ./.zig-cache/.../test --listen=-` line.
- The useful first check is `echo $?` immediately after `zig build test`.
- This is developer-experience cleanup, not a current rollout blocker.
