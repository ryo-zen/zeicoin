---
id: l2_messages_get_endpoint
key: ZEI-9
title: Implement GET endpoint for L2 message inbox retrieval
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- l2
- api
- wallet
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

There is no GET endpoint to fetch L2 messages for an address. The wallet messages inbox cannot display received or sent messages without it. Current `transaction_api.zig` only implements POST (create) and confirm/pending update routes.

## Acceptance Criteria

- [ ] `GET /api/l2/messages?address={address}` returns paginated confirmed messages for an address
- [ ] Response includes `temp_id`, `sender`, `recipient`, `message`, `category`, `tx_hash`, `block_height`, `status`, `created_at`
- [ ] `limit` and `offset` query params supported (defaults: 50 and 0)
- [ ] Optional `direction=sent|received` filter supported
- [ ] Handler added in `src/apps/transaction_api.zig` alongside the existing POST handler

## Notes

**SQL:**
```sql
SELECT temp_id, sender_address, recipient_address, message, category,
       tx_hash, block_height, status, created_at
FROM l2_messages
WHERE (sender_address = $1 OR recipient_address = $1)
  AND status = 'confirmed'
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
```

**Wallet side** (once endpoint exists):
- `src/routes/messages/+page.svelte` — fetch and display messages
- Add `getMessages` Tauri command in `src-tauri/src/api.rs` following the same pattern as `get_transactions`
