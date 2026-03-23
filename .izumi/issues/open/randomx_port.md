---
id: randomx_port
key: ZEI-16
title: Replace randomx_helper.c with native Zig CLI wrapper
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- mining
- randomx
- build
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-01-27T00:00:00+00:00
updated_at: 2026-03-10T00:00:00+00:00
---

## Summary

Replace the C helper binary (`randomx/randomx_helper.c`) with a native Zig CLI tool (`src/randomx/main.zig`) backed by a thin Zig wrapper (`src/randomx/wrapper.zig`) over the existing `librandomx.a` static library. The active implementation still uses the C helper; this is a future replacement that eliminates the C source dependency while keeping the compiled library.

## Acceptance Criteria

- [ ] `src/randomx/wrapper.zig` wraps `librandomx.a` with Zig allocator semantics and Zig error types
- [ ] `src/randomx/main.zig` replicates the `randomx_helper.c` CLI (parse args, hex input, light/fast mode, hash + difficulty check, print `HASH:MEETS`)
- [ ] `build.zig` registers `randomx_cli` and `randomx_wrapper` targets linking against `randomx/randomx_install/lib/librandomx.a`
- [ ] Test in `src/randomx/tests.zig` validates Zig output matches the original C helper output byte-for-byte
- [ ] `zig build test` includes the RandomX test

## Notes

- Keep the upstream `librandomx.a` static library — do not rewrite SIMD-heavy C core
- Performance is unchanged: the wrapper adds only nanoseconds of Zig call overhead
- Active production path: `randomx/randomx_helper.c` + `src/core/crypto/randomx.zig`
- `src/randomx/wrapper.zig` and `src/randomx/main.zig` do not currently exist in the active build

**Future work (post this ticket):** Pure-Zig SIMD port via `@Vector` types; `librandomx.so` dynamic loading; configurable `RANDOMX_FLAG_JIT`/`RANDOMX_FLAG_LARGE_PAGES` flags.
