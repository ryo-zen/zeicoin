---
id: add_graphana_to_project
key: ZEI-80
title: Set up Grafana on project
type: Task
status: Backlog
priority: Medium
assignee: null
labels: []
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1775651785888.0
comments: []
created_at: 2026-04-08T12:36:25.888795268+00:00
updated_at: 2026-04-08T12:37:08.026080580+00:00
closed_at: null
---

## Summary

Set up Grafana Cloud (free tier) on the bootstrap server (209.38.84.23) to replace the removed `zeicoin_error_monitor` service. Grafana Cloud provides log aggregation, system metrics, and alerting without consuming RAM on the 2GB server.

## Acceptance Criteria

- [ ] Create Grafana Cloud account and configure free tier
- [ ] Install Grafana Alloy agent on bootstrap server
- [ ] Configure Alloy to ship journalctl logs from zeicoin services (mining, transaction-api, indexer)
- [ ] Set up alert rules for error-level log messages
- [ ] Add basic dashboard for system metrics (CPU, memory, disk)
- [ ] Add dashboard for ZeiCoin-specific metrics (block height, mining status, peer count)

## Notes

- Free tier includes 50GB logs/month, more than enough for a single node
- Alloy agent is lightweight, suitable for the 2GB server
- Previous error monitor (`src/apps/error_monitor.zig`) was removed due to 100% CPU usage from pipe I/O issues in Zig 0.16
- Server already has PostgreSQL/TimescaleDB with analytics tables that could also feed Grafana
