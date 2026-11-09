# FAD: qwp_crypto::qhs3 (QHS-3)

## Identity

- Function ID: `qhs3_keygen`, `qhs3_keygen_from_leaves`, `qhs3_leaf`, `Qhs3PrivateKey::sign`, `Qhs3PrivateKey::sign_with_leaves`, `Qhs3PublicKey::verify`, `message_digits`, `wots_sign`, `wots_verify`, `range_root_from_seed`, `range_root_from_leaves`, `auth_path_from_seed`, `auth_path_from_leaves`, `qwp_platform::qhs3_leaves_parallel`, CLI QHS-3 cache read/write
- Module: `qwp-crypto/qhs3`, `qwp-platform`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the production path. Combined 1-hour soak passed.

## Contract

- Purpose: stateful base-64 WOTS + height-12 Merkle signature over in-tree BLAKE3.
- Inputs: 32-byte seed, message bytes, 64-byte keys, 1,832-byte signature, 4,096-leaf slice.
- Outputs: key pair, signature, verification result.
- Secrets handled: seed, WOTS chain values, Merkle leaf state.
- Trust boundary: untrusted signatures/public keys; secret seed.
- Preconditions: unique leaf per signature; seed from a CSPRNG; leaf slice has exactly 4,096 entries.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key fails.
- Invariants: 45 chains × 63 steps; 43 message digits + 2 checksum digits; 4,096 leaves; leaf index <4096; checksum over 1,828 bytes; no heap/unsafe in the crypto core.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, leaf-index manipulation, auth-path manipulation, key exhaustion, rollback, cross-version confusion, cache poisoning, oversized cache.
- Assets targeted: one-time leaf, WOTS chain values, Merkle root, state counter.
- Attack tree: `docs/attack-trees.md` §9 and `docs/10-qhs3.md` §9.
- Abuse cases:
  - A1: tamper WOTS chain value.
  - A2: tamper auth path.
  - A3: change leaf index.
  - A4: wrong message.
  - A5: wrong public key.
  - A6: key exhaustion.
  - A7: leaf reuse via counter rollback.
  - A8: checksum corruption.
  - A9: QHS-1/QHS-2/QHS-3/QHS-3.1 cross-domain confusion.
  - A10: cache poisoning / oversized cache.
  - A11: timing/fault/DoS.

## Evidence

- Direct unit tests: `qwp-crypto/src/qhs3.rs` (KAT, round-trip, tamper, wrong key/message, exhaustion, cached-vs-sequential equivalence, slice-based keygen).
- Negative/abuse tests: `qwp-attacks::attack_qhs3`; tamper matrix covers version, algorithm, leaf index, WOTS, auth path, checksum, all-zero, all-0xff.
- Property/equivalence tests: parallel leaves equal sequential leaves; cached signing equals uncached signing.
- Fuzz target: in-house parser/verifier fuzz covers QHS-1/2/3/3.1; combined 1-hour soak 333,637,807 iterations, 0 panics.
- Formal harness: Kani parser proofs pass (QHS-3 public key, private key, leaf index).
- Timing harness: keygen ≈0.40–0.44 s, sign ≈1.60–1.70 ms, verify ≈0.39 ms; Welch \|t\| < 4.5.
- Benchmarks: `qhs3_timing`, `qwp-bench`.
- Break-log entries: BL-0016.
- Gap IDs: GAP-QHS-0025 — closed; combined 1h soak passed.

## Closure

- Abuse cases covered: A1–A6, A8 in tests; A9 by versioned formats/contexts and cross-version CLI tests; A7 by CLI lock + atomic counter; A10 by versioned cache validation and bounded reads; A11 by timing harness and operational fault/DoS rules.
- Error paths tested: parser, exhaustion, cache corruption/truncation/foreign/oversized cache, fuzz.
- Bounds proven: Kani parser proofs; checked arithmetic; fuzz/Miri.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-06
