---
id: remove_render_blocking_requests_from_website_critical_path
key: ZEI-76
title: Remove render-blocking requests from the website critical path
type: Task
status: InProgress
priority: High
assignee: null
labels:
- website
- frontend
- performance
- lighthouse
- lcp
- fonts
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1775520419939.0
comments: []
created_at: 2026-04-07T02:00:00Z
updated_at: 2026-04-07T00:09:15.803019444+00:00
closed_at: null
---

## Summary

Chrome Lighthouse reports an estimated 1,220 ms savings from render-blocking requests on `https://zeicoin.com`. The main offenders are the Google Fonts stylesheet (`/css2?family=...`) and the first-party CSS asset (`/assets/0.Cl-LDoYr.css`), both of which currently sit on the initial render path and can delay LCP.

## Acceptance Criteria

- [ ] Audit the current font-loading strategy and remove the external Google Fonts stylesheet from the blocking path by self-hosting, using a stronger fallback stack, or otherwise deferring it safely
- [ ] Review the above-the-fold CSS strategy and either inline the critical subset or defer non-critical styling without causing a broken first paint
- [ ] Confirm the page still renders with acceptable typography and without severe FOIT/FOUT regressions on Chrome
- [ ] Re-run Lighthouse in Chrome and verify the render-blocking request warning is materially reduced or eliminated for the homepage

## Notes

- Lighthouse flagged:
  - `https://fonts.googleapis.com/css2?family=...` at roughly 920 ms
  - `https://zeicoin.com/assets/0.Cl-LDoYr.css`
- This ticket is about first paint and LCP only, not general visual redesign.
