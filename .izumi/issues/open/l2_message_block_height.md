---
id: l2_message_block_height
key: ZEI-8
title: Fix L2 message block_height always stored as 0
type: Bug
status: Backlog
priority: Low
assignee: null
labels:
- l2
- indexer
- data-quality
sprint: null
story_points: null
due_date: null
parent_id: null
rank: null
comments: []
created_at: 2026-02-18T00:00:00+00:00
updated_at: 2026-03-10T00:00:00+00:00
---

## Summary

L2 messages are confirmed with `block_height: 0` because the wallet confirms the message at transaction submit time, before the transaction has been mined. All confirmed L2 messages in the `l2_messages` table have `block_height = 0`. The `status` and `tx_hash` fields are correct.

## Acceptance Criteria

- [ ] After a transaction is mined, the corresponding `l2_messages.block_height` is updated to the actual block height
- [ ] New L2 messages confirmed after this fix have a non-zero `block_height`

## Notes

**Recommended fix (Option A — indexer update):** In `src/apps/indexer.zig`, after indexing a transaction, run:

```sql
UPDATE l2_messages SET block_height = $block_height
WHERE tx_hash = $tx_hash AND block_height = 0;
```

The indexer already has both `block_height` and `tx_hash` at the point it processes each transaction — this is the cleanest approach.

This is a data quality gap only. It does not affect message delivery, status, or tx_hash linkage.
