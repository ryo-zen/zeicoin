---
id: generic_crypto_signature
key: ZEI-2
title: Design generic signature interface for cryptographic agility
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- crypto
- architecture
sprint: null
story_points: null
due_date: null
parent_id: post_quantum_migration
rank: 1773125880061.0
comments: []
created_at: 2026-01-19T00:00:00+00:00
updated_at: 2026-03-17T11:10:22.483560055+00:00
---

## Summary

ZeiCoin currently hardcodes Ed25519 throughout the codebase. This task introduces a generic signature interface using Zig tagged unions to support multiple algorithms (Ed25519, ML-DSA-44/65/87) without a hard fork, enabling post-quantum readiness from MainNet genesis.

## Acceptance Criteria

- [ ] `SignatureScheme` enum and `Signature` tagged union defined in `src/core/crypto/key.zig`
- [ ] Generic `KeyPair` union with `generate()`, `sign()`, `getPublicKey()` methods
- [ ] `verify()` dispatches based on scheme tag
- [ ] `Transaction` updated to use variable-size `sender_public_key` and generic `Signature`
- [ ] HD wallet (`hd.zig`) supports scheme parameter for key derivation
- [ ] Mempool and chain validators updated to handle generic signatures
- [ ] `ZEICOIN_SIGNATURE_SCHEME` env var controls default scheme per network
- [ ] Existing Ed25519 wallets remain backward compatible
- [ ] Unit tests cover all schemes and serialization round-trips

## Notes

- Implementation plan is 6 phases across ~8–12 days; see `docs/issues/open/generic_crypto_signature.md` for full detail
- Recommended strategy: clean slate — implement before MainNet so ML-DSA-44 is the default from genesis
- Memory consideration: tagged union takes size of largest variant (ML-DSA-87 = 4,627 bytes); use separate tx versions to avoid waste
- Related: `docs/issues/open/post_quantum_cryto_attempt2.md` is the more concrete ML-DSA integration plan
- Files affected: `types/types.zig`, `crypto/key.zig`, `crypto/hd.zig`, `mempool/validator.zig`, `chain/genesis.zig`
