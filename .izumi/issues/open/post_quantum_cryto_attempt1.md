---
id: post_quantum_cryto_attempt1
key: ZEI-14
title: Research post-quantum cryptography options and migration strategy for ZeiCoin
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- crypto
- research
- pqc
- mainnet
sprint: null
story_points: null
due_date: null
parent_id: post_quantum_migration
rank: null
comments: []
created_at: 2026-01-19T00:00:00+00:00
updated_at: 2026-03-11T00:00:00+00:00
---

## Summary

ZeiCoin currently uses Ed25519 for transaction signatures. This research document analyzes the quantum threat timeline, available PQC options in Zig, and the recommended migration path using ML-DSA-44 (FIPS 204) from the Zig standard library.

## Acceptance Criteria

- [x] ML-DSA-44 integration plan documented and ready for review — actionable plan is ZEI-15 (`post_quantum_cryto_attempt2`)
- [ ] Decision formally recorded on MainNet launch strategy: ML-DSA-44 from genesis vs. hybrid vs. Ed25519 with later hard fork (recommendation: ML-DSA-44 from genesis — see Notes)

## Notes

**Key findings:**
- Zig 0.16 has native ML-DSA support at `std.crypto.sign.mldsa.MLDSA44` (confirmed working on current nightly)
- ML-DSA-44 signature size: 2,420 bytes (vs. 64 bytes for Ed25519 — 37.8x larger)
- Block size already updated to 16 MB soft / 32 MB hard to accommodate PQC transactions
- Recommended algorithm: ML-DSA-44 (FIPS-204, NIST Category 2, 128-bit security matching Ed25519)
- Not recommended: SPHINCS+ (too large), Falcon (not FIPS), XMSS/LMS (stateful)

**Recommended timeline:**
- Since MainNet has not launched, ZeiCoin can launch with ML-DSA-44 from genesis — no migration complexity

**Quantum threat timeline:** CRQCs unlikely before 2030-2035. Not urgent, but planning now avoids a hard fork later.

See `docs/issues/open/post_quantum_cryto_attempt1.md` for full analysis including size comparison tables, storage impact, and migration strategy options.
