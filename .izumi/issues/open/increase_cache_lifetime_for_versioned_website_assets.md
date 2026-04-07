---
id: increase_cache_lifetime_for_versioned_website_assets
key: ZEI-77
title: Increase cache lifetime for versioned website assets
type: Task
status: Backlog
priority: High
assignee: null
labels:
  - website
  - performance
  - caching
  - lighthouse
  - deployment
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

Lighthouse reports that many first-party static assets on `zeicoin.com` are served with a cache TTL of only 4 hours, including hashed JS chunks, CSS, and icon images. Because these assets are fingerprinted, they should likely be shipped with a much longer immutable cache policy to speed up repeat visits.

## Acceptance Criteria

- [ ] Audit the production caching headers for hashed JS, CSS, and static image assets served by the website
- [ ] Update deployment or server configuration so fingerprinted assets are served with a long-lived immutable cache policy
- [ ] Ensure HTML and any non-versioned assets keep an appropriate shorter cache policy so content updates still propagate safely
- [ ] Re-run Lighthouse and confirm the "Use efficient cache lifetimes" finding is substantially reduced for first-party assets

## Notes

- Lighthouse examples included:
  - JS chunks such as `.../chunks/C1YNY2I3.js`
  - CSS asset `.../assets/0.Cl-LDoYr.css`
  - icon assets under `/icons/*.png`
- The expected fix is probably in hosting or CDN headers rather than application code, but verify the current deployment pipeline before changing anything.
