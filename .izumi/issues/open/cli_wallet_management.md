---
id: cli_wallet_management
key: ZEI-4
title: Add wallet management commands (password change, key import/export, rescan, HD address list)
type: Story
status: Backlog
priority: Low
assignee: null
labels:
- cli
- wallet
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

Several wallet management commands are missing. Users cannot change wallet passwords, import/export keys, rescan from a given height, or list HD-derived addresses.

## Acceptance Criteria

- [ ] `wallet change-password <name>` re-encrypts the wallet file with a new password
- [ ] `wallet export-keys <name>` exports the raw private key with a prominent security warning and confirmation prompt
- [ ] `wallet import-keys <name>` creates a wallet from an imported private key
- [ ] `rescan [--height=N]` forces a wallet rescan from a given height
- [ ] `refresh` syncs wallet balances with the latest chain state
- [ ] `address list <wallet>` shows all derived addresses with individual balances
- [ ] `address new <wallet>` generates and displays the next HD address in the derivation path

## Notes

- `wallet export-keys` must prompt for confirmation and show a security warning before displaying private key material
- `rescan` needs a last-scanned-height field stored per wallet; currently wallets do not track this
- `address list` requires iterating BIP32-derived addresses and querying balance for each — may be slow without a transaction index
