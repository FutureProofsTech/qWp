# FAD: qwp_crypto::qhs (QHS-1)

## Identity

- Function ID: `qhs_keygen`, `qhs_keygen_from_leaves`, `qhs_leaf`, `qhs_leaves`, `QhsPrivateKey::sign`, `QhsPrivateKey::sign_with_leaves`, `QhsPublicKey::verify`, `message_digits`, `wots_sign`, `wots_verify`, `merkle_root`, `auth_path_from_leaves`, `qwp_platform::qhs_leaves_parallel`, CLI cache read/write
- Module: `qwp-crypto/qhs`, `qwp-platform`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the production path. 1-hour soak passed; 72-hour soak waived by owner decision (2026-11-06).

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

- Direct unit tests: `qwp-crypto/src/qhs.rs` (KAT, round-trip, tamper, wrong key/message, exhaustion, cached-vs-sequential equivalence).
- Negative/abuse tests: `qwp-attacks::attack_qhs1`; tamper matrix covers version, algorithm, leaf index, WOTS, auth path, checksum, all-zero, all-0xff.
- Property/equivalence tests: parallel leaves equal sequential leaves; cached signing equals sequential signing.
- Fuzz target: in-house fuzz covers random-seed keygen, random-message sign/verify, parser/verifier, and QHS-3.1 tree signing; 13,270,061 iterations / 60s, 0 panics; QHS-1 1-hour soak 793,945,578 iterations; final combined 1-hour soak 360,181,413 iterations, 0 panics; 72-hour soak waived by owner (no pass claimed).
- Formal harness: Kani parser proofs pass (public key, private key, leaf index). WOTS/Merkle security is the written reduction in `docs/05-qhs1.md`, not a machine-checked proof.
- Timing harness: keygen ≈10–13 ms, sign ≈0.21–0.33 ms, verify ≈0.14 ms; keygen/sign Welch \|t\| < 4.5.
- Benchmarks: `qwp-timing`, `qwp-bench`.
- Break-log entries: BL-0011, BL-0012, BL-0013, BL-0014.
- Gap IDs: GAP-SIGN-0019, GAP-QHS-0020, GAP-QHS-0021, GAP-QHS-0022, GAP-QHS-0023 — all closed.

## Closure

- Abuse cases covered: A1–A6, A8 in tests; A9 by distinct-context test + KAT; A7 by CLI lock + atomic counter + keyed state guard; A10 by timing harness and operational fault/DoS rules.
- Error paths tested: parser, exhaustion, cache corruption/truncation/foreign cache, fuzz.
- Bounds proven: Kani parser proofs; checked arithmetic; fuzz/Miri.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-06
