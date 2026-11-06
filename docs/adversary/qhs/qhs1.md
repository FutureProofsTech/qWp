# FAD: qwp_crypto::qhs (QHS-1)

## Identity

- Function ID: `qhs_keygen`, `QhsPrivateKey::sign`, `QhsPublicKey::verify`, `message_digits`, `wots_sign`, `wots_verify`, `merkle_root`, `auth_path`
- Module: `qwp-crypto/qhs`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: attacked; proof review and formal/fuzz evidence pending

## Contract

- Purpose: stateful WOTS + Merkle signature over in-tree BLAKE3.
- Inputs: 32-byte seed, message bytes, 64-byte keys, 2408-byte signature.
- Outputs: key pair, signature, verification result.
- Secrets handled: seed, WOTS chain values, Merkle leaf state.
- Trust boundary: untrusted signatures/public keys; secret seed.
- Preconditions: unique leaf per signature; seed from a CSPRNG.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key fails.
- Invariants: 67 chains × 15 steps; 256 leaves; leaf index <256; checksum over 2404 bytes; no heap/unsafe.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, leaf-index manipulation, auth-path manipulation, key exhaustion, rollback.
- Assets targeted: one-time leaf, WOTS chain values, Merkle root, state counter.
- Attack tree: `docs/attack-trees.md` §1–§2 and `docs/05-qhs1.md` §9.
- Abuse cases:
  - A1: tamper WOTS chain value.
  - A2: tamper auth path.
  - A3: change leaf index.
  - A4: wrong message.
  - A5: wrong public key.
  - A6: key exhaustion.
  - A7: leaf reuse via counter rollback.
  - A8: checksum corruption.
  - A9: cross-domain hash confusion.
  - A10: timing/fault/DoS.

## Evidence

- Direct unit tests: `qwp-crypto/src/qhs.rs`.
- Negative/abuse tests: `qwp-attacks::attack_qhs1`.
- Property tests: pending.
- Fuzz target: pending.
- Formal harness: Kani parser proofs pass; WOTS/Merkle proofs pending.
- Timing harness: pending.
- Benchmarks: pending.
- Break-log entries: none for QHS-1.
- Gap IDs: GAP-SIGN-0019, GAP-QHS-0020, GAP-QHS-0021, GAP-QHS-0022.

## Closure

- Abuse cases covered: A1–A6, A8 in tests; A7 operational; A9/A10 pending.
- Error paths tested: yes for parser/exhaustion; pending fuzz.
- Bounds proven: Kani parser proofs pass; WOTS/Merkle bounds pending.
- Red-team sign-off: pending.
- Date: 2026-11-06
