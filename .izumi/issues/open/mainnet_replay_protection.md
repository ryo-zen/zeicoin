---
id: mainnet_replay_protection
key: ZEI-23
title: Add chain ID replay protection to prevent testnet transactions replaying on MainNet
type: Task
status: Backlog
priority: High
assignee: null
labels: [mainnet, security, consensus]
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

Without replay protection, a valid signed transaction on TestNet can be rebroadcast and included on MainNet (and vice versa). A chain ID must be included in the transaction signing hash so signatures are bound to a specific network.

## Acceptance Criteria

- [ ] Chain ID constant defined for TestNet and MainNet in `types.zig`
- [ ] Chain ID included in `hashForSigning()` for all transaction types
- [ ] Validator rejects transactions signed for a different chain ID
- [ ] Existing TestNet transactions remain valid on TestNet after the change
- [ ] Ocelot Wallet updated to include chain ID when signing

## Notes

Typically implemented by adding chain ID to the transaction hash preimage before Ed25519 signing. Must be deployed to TestNet well before MainNet so wallets and tooling have time to update. Affects `src/core/types/types.zig`, `src/core/mempool/validator.zig`, and the wallet signing path.
