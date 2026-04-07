---
id: reduce_unused_javascript_and_main_thread_work_on_homepage
key: ZEI-78
title: Reduce unused JavaScript and main-thread work on the homepage
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
  - website
  - performance
  - javascript
  - lighthouse
  - bundling
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-04-07T02:00:00Z
updated_at: 2026-04-07T02:00:00Z
closed_at: null
---

## Summary

Chrome Lighthouse reported roughly 54.5 KiB of unused JavaScript in the large first-party chunk `.../chunks/C1YNY2I3.js`, along with a long main-thread task attributed to that bundle. The homepage should be reviewed for code splitting, hydration scope, and any non-critical scripts that can be deferred or removed from the initial load.

## Acceptance Criteria

- [ ] Identify what code is bundled into the large homepage chunk and which parts are not needed for the initial render
- [ ] Defer, lazy-load, or remove non-critical client-side code where it does not hurt UX
- [ ] Rebuild and verify that the initial homepage bundle size and execution cost are reduced
- [ ] Re-run Lighthouse and confirm improvement in both "Reduce unused JavaScript" and long main-thread task diagnostics

## Notes

- Lighthouse findings called out:
  - `.../chunks/C1YNY2I3.js` transfer size about 121.7 KiB with estimated savings of 54.5 KiB
  - Long task around 63 ms attributed to the same chunk
- Ignore the minify warning for `chrome-extension://cimiefiiaegbelhefglklhhakcgmhkai/...`; that is a browser extension, not a site asset.
