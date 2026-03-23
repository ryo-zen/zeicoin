---
id: post_quantum_cryto_attempt2
key: ZEI-15
title: Implement ML-DSA-44 transaction signing with staged backward-compatible rollout
type: Task
status: Backlog
priority: Medium
assignee: null
labels:
- crypto
- pqc
- mainnet
sprint: null
story_points: null
due_date: null
parent_id: post_quantum_migration
rank: null
comments: []
created_at: 2026-03-03T00:00:00+00:00
updated_at: 2026-03-10T00:00:00+00:00
---

## Summary

Implement ML-DSA-44 post-quantum signatures in ZeiCoin using a staged, backward-compatible approach. The big-bang replacement of fixed-size `PublicKey`/`Signature` types failed in Attempt 1. This plan decouples crypto migration from serialization migration using versioned transaction types and feature flags.

## Acceptance Criteria

- [ ] **Phase 0**: Feature flags `ZEICOIN_SIGNATURE_DEFAULT=ed25519|mldsa44` and `ZEICOIN_ACCEPT_TX_V2=true|false` added (defaults: `ed25519`, `false`)
- [ ] **Phase 1**: `src/core/crypto/key.zig` adds ML-DSA-44 wrappers (`generateNewMLDSA44`, `signMLDSA44`, `verifyMLDSA44`) and `SignatureAlgorithm` enum; existing Ed25519 paths unchanged
- [ ] **Phase 2**: `TransactionV2` struct added with versioned variable-length `sender_public_key` and `signature`; serialization round-trips correctly; v1 unchanged
- [ ] **Phase 3**: Wallet supports ML-DSA-44 derivation on account branch `m/44'/882'/1'/0/index`; CLI `--algo mldsa44` flag supported
- [ ] **Phase 4**: RPC `submitTransaction` accepts v2 payload; mempool and chain validators dispatch by transaction version
- [ ] `zig build check` and `zig build test` pass with existing Ed25519 tests unchanged

## Notes

**Lessons from Attempt 1:**
- Do not replace `PublicKey`/`Signature` fixed-size types globally — causes widespread breakage
- Do not use global search/replace — high risk of corrupting unrelated call sites
- Decouple crypto migration from serialization migration
- ML-DSA API: `std.crypto.sign.mldsa.MLDSA44.KeyPair.generate(io)`, `kp.sign(msg, null)`, `sig.verify(msg, kp.public_key)`

**Validation rules:**
- `mldsa44` public key length must be exactly 1312
- `mldsa44` signature length must be exactly 2420
- `TransactionV2.hashForSigning()` must include `sig_algorithm` and key bytes, exclude signature bytes
- Domain separation context: `"ZeiCoin-TX-v2"`

**Rollout:** Release A (compiled in, v2 disabled) → Release B (v2 on testnet) → Release C (mldsa44 default on testnet) → MainNet decision point
