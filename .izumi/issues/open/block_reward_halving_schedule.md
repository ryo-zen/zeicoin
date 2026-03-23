---
id: block_reward_halving_schedule
key: ZEI-22
title: Implement block reward emission schedule and halving logic for 24M supply cap
type: Task
status: Backlog
priority: High
assignee: null
labels: [mainnet, consensus]
sprint: null
story_points: null
due_date: null
parent_id: mainnet_readiness
rank: null
comments: []
created_at: 2026-03-14T00:00:00+00:00
updated_at: 2026-03-14T00:00:00+00:00
---

## Summary

ZeiCoin has a fixed supply of 24,000,000 ZEI. The block reward emission curve and halving interval need to be designed and implemented before MainNet. Without this, the supply cap cannot be enforced by consensus.

## Acceptance Criteria

- [ ] Decide initial block reward amount and halving interval (block height based)
- [ ] Implement `getBlockReward(height)` function in `types.zig` or equivalent
- [ ] Coinbase transaction validation rejects blocks with oversized rewards
- [ ] Supply never exceeds 24,000,000 ZEI across all halvings
- [ ] Unit tests covering reward at genesis, first halving, last reward, post-cap

## Notes

Current coinbase maturity is set but no reward schedule exists. This is consensus-critical — once MainNet launches, the schedule cannot change without a hard fork. Files likely affected: `src/core/types/types.zig`, `src/core/chain/validator.zig`, `src/core/miner/manager.zig`.
