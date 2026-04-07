---
id: improve_homepage_image_delivery_and_layout_stability
key: ZEI-79
title: Improve homepage image delivery and layout stability
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
  - website
  - performance
  - images
  - lighthouse
  - cls
  - lcp
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

Beyond the blocking and caching issues, Lighthouse also flagged image delivery opportunities, layout shift culprits, and LCP breakdown concerns on the homepage. The visual loading path should be tightened so key imagery is delivered efficiently and the initial layout stays stable as assets load.

## Acceptance Criteria

- [ ] Audit homepage images for oversized payloads, incorrect formats, or missing responsive variants
- [ ] Ensure above-the-fold images have explicit dimensions or aspect-ratio handling to prevent layout shift
- [ ] Preload or prioritize the true LCP image only if profiling shows it is beneficial
- [ ] Re-run Lighthouse and confirm improvement in image delivery, layout shift, and LCP diagnostics

## Notes

- Lighthouse did not provide a single failing URL in the summary, so this ticket starts with a targeted audit in Chrome DevTools Performance/Lighthouse traces.
- Keep this ticket focused on measurable loading behavior, not copy or design changes.
