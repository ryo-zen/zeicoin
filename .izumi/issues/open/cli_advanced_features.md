---
id: cli_advanced_features
key: ZEI-3
title: Add advanced CLI features (offline mode, daemon override, tx-notify, doctor)
type: Story
status: Backlog
priority: Low
assignee: null
labels:
- cli
- ux
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

Several useful CLI features are missing that would improve cold-wallet workflows, multi-node setups, automation, and new operator onboarding.

## Acceptance Criteria

- [ ] `--offline` flag on `send` creates a signed but unbroadcast transaction saved to a file
- [ ] `broadcast <file>` command submits a previously created offline transaction
- [ ] `--daemon-address ip:port` flag overrides `ZEICOIN_SERVER` per-command
- [ ] `--tx-notify <script>` executes a script/webhook when the wallet receives a transaction
- [ ] `doctor` command checks `.env` validity, server reachability, wallet readability, port availability, and bootstrap node response — outputs pass/fail checklist

## Notes

- `--offline` is the most complex item — requires splitting transaction creation, signing, and broadcast into separate steps
- `doctor` is a quick win and high value for onboarding new node operators; implement first
- `--tx-notify` requires a background polling or subscription mechanism
