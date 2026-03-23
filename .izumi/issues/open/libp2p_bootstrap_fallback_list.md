---
id: libp2p_bootstrap_fallback_list
key: ZEI-36
title: Add hardcoded fallback bootstrap multiaddr list to binary
type: Subtask
status: Backlog
priority: Medium
assignee: null
labels:
- libp2p
- configuration
- mainnet
sprint: null
story_points: 2
due_date: null
parent_id: libp2p_bootstrap_multiaddr
rank: null
comments: []
created_at: 2026-03-17T00:00:00+00:00
updated_at: 2026-03-17T00:00:00+00:00
---

## Summary

Compile a hardcoded list of well-known bootstrap node multiaddrs into the binary so mainnet nodes work out-of-the-box with zero config. The env var always takes precedence; this list is the last resort.

## Acceptance Criteria

- [ ] Hardcoded list is defined in `types.zig` or a dedicated `bootstrap.zig`
- [ ] List is selected based on `CURRENT_NETWORK` (testnet vs mainnet)
- [ ] Env var override suppresses the fallback list entirely
- [ ] At least one valid testnet bootstrap node is in the testnet list

## Notes

Analogous to Bitcoin's `chainparams.cpp` DNS seeds. Keep the list small (2-4 nodes per network).
