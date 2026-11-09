# FAD: qwp_crypto::qhs2 (QHS-2)

## Identity

- Function ID: `qhs2_keygen`, `qhs2_keygen_from_leaves`, `qhs2_leaf`, `qhs2_leaves`, `Qhs2PrivateKey::sign`, `Qhs2PrivateKey::sign_with_leaves`, `Qhs2PublicKey::verify`, `message_digits`, `wots_sign`, `wots_verify`, `merkle_root`, `auth_path_from_leaves`, `qwp_platform::qhs2_leaves_parallel`, CLI QHS-2 cache read/write
- Module: `qwp-crypto/qhs2`, `qwp-platform`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the production path. Combined 1-hour soak passed.

## Contract

- Purpose: stateful base-64 WOTS + Merkle signature over in-tree BLAKE3.
- Inputs: 32-byte seed, message bytes, 64-byte keys, 1,704-byte signature.
- Outputs: key pair, signature, verification result.
- Secrets handled: seed, WOTS chain values, Merkle leaf state.
- Trust boundary: untrusted signatures/public keys; secret seed.
- Preconditions: unique leaf per signature; seed from a CSPRNG.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key fails.
- Invariants: 45 chains × 63 steps; 43 message digits + 2 checksum digits; 256 leaves; leaf index <256; checksum over 1,700 bytes; no heap/unsafe.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, leaf-index manipulation, auth-path manipulation, key exhaustion, rollback, cross-version confusion, cache poisoning.
- Assets targeted: one-time leaf, WOTS chain values, Merkle root, state counter.
- Attack tree: `docs/attack-trees.md` §8 and `docs/07-qhs2.md` §9.
- Abuse cases:
  - A1: tamper WOTS chain value.
  - A2: tamper auth path.
  - A3: change leaf index.
  - A4: wrong message.
  - A5: wrong public key.
  - A6: key exhaustion.
  - A7: leaf reuse via counter rollback.
  - A8: checksum corruption.
  - A9: QHS-1/QHS-2 cross-domain confusion.
  - A10: cache poisoning.
  - A11: timing/fault/DoS.

## Evidence

- Direct unit tests: `qwp-crypto/src/qhs2.rs` (KAT, round-trip, tamper, wrong key/message, exhaustion, cached-vs-sequential equivalence).
- Negative/abuse tests: `qwp-attacks::attack_qhs2`; tamper matrix covers version, algorithm, leaf index, WOTS, auth path, checksum, all-zero, all-0xff.
- Property/equivalence tests: parallel leaves equal sequential leaves; cached signing equals sequential signing.
- Fuzz target: in-house parser/verifier fuzz covers QHS-1/2/3/3.1; combined 1-hour soak 333,637,807 iterations, 0 panics.
- Formal harness: Kani parser proofs pass (QHS-2 public key, private key, leaf index).
- Timing harness: keygen ≈27–28 ms, sign ≈0.46–0.61 ms, verify ≈0.41 ms; Welch \|t\| < 4.5.
- Benchmarks: `qhs2_timing`, `qwp-bench`.
- Break-log entries: BL-0015.
- Gap IDs: GAP-QHS-0024 — closed; combined 1h soak passed.

## Closure

- Abuse cases covered: A1–A6, A8 in tests; A9 by versioned formats/contexts and cross-version CLI tests; A7 by CLI lock + atomic counter; A10 by versioned cache validation; A11 by timing harness and operational fault/DoS rules.
- Error paths tested: parser, exhaustion, cache corruption/truncation/foreign cache, fuzz.
- Bounds proven: Kani parser proofs; checked arithmetic; fuzz/Miri.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-06
