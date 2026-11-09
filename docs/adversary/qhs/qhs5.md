# FAD: qwp_crypto::qhs5 (QHS-5)

## Identity

- Function ID: `qhs5_keygen`, `qhs5_keygen_from_leaves`, `qhs5_leaf`, `qhs5_leaves`, `Qhs5PrivateKey::sign`, `Qhs5PrivateKey::sign_with_leaves`, `Qhs5PublicKey::verify`, `qwp_platform::qhs5_leaves_parallel`, CLI `qhs5-*`
- Module: `qwp-crypto/qhs5`, `qwp-hash` 512-bit mode, `qwp-platform`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the local production path. 1-hour soak passed: 48,430,620 iterations, 0 panics (`docs/evidence/qhs5-fuzz-soak-1h.txt`).

## Contract

- Purpose: stateful 512-bit-hash WOTS + Merkle signature over in-tree BLAKE3.
- Inputs: 64-byte seed, message bytes, 72-byte keys, 6,216-byte signature.
- Outputs: key pair, signature, verification result.
- Secrets handled: 64-byte seed, WOTS chain values.
- Trust boundary: untrusted signatures/public keys; secret seed and key counter.
- Preconditions: seed from a CSPRNG; header `[6,6,8,0]` for keys; leaf index
  `< 256`; single-writer key use.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key
  fails; each signature consumes one leaf and persists the counter before the
  signature is released.
- Invariants: WOTS 89 chains × 63 steps; 86+3 base-64 digits; height-8 tree;
  checksum over 6,212 bytes; 64-byte nodes; no heap/unsafe in the crypto core.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, header/path
  manipulation, cross-version confusion, parser/checksum corruption, cache
  corruption, key/state rollback, timing/fault/DoS.
- Assets targeted: WOTS chain values, Merkle root, leaf uniqueness, key counter,
  cache integrity, public key.
- Attack tree: `docs/attack-trees.md` §14 and `docs/16-qhs5.md` §12.
- Abuse cases:
  - A1: tamper a WOTS chain value.
  - A2: tamper an auth-path node.
  - A3: change the leaf index or signature header.
  - A4: wrong message.
  - A5: wrong public key.
  - A6: reuse a leaf by resetting the key counter.
  - A7: corrupt/foreign leaf cache.
  - A8: checksum/header corruption.
  - A9: cross-version confusion with QHS-1/2/3/4/4.2.
  - A10: timing/fault/DoS.

## Evidence

- Direct unit tests: `crates/qwp-crypto/src/qhs5.rs` (KAT, round-trip,
  deterministic, tamper, wrong key/message, header/parser, counter, 512-bit
  digit encoding, cache/leaf helpers).
- Negative/abuse tests: `qwp-attacks::attack_qhs5`; suite 12/12.
- Property tests: signature size, key size, domain-context distinctness,
  message-digit reconstruction/checksum, leaf/cache determinism.
- Fuzz target: random QHS-5 public/private/signature parsing, random verifier
  inputs, valid signature checks, and random-message signing.
- Formal harness: Kani parser proofs pass
  (`qhs5_public_key_parse_never_panics`,
  `qhs5_private_key_parse_never_panics`,
  `qhs5_signature_from_slice_checks_length`).
- Timing harness: parallel keygen ≈0.09 s (≈7.0×), cached sign ≈1.5 ms,
  uncached sign ≈0.62 s, verify ≈1.2 ms; Welch `|t| < 4.5`.
- CLI tests: keygen/sign/verify end-to-end; cache size/header/fingerprint/MAC;
  state guard size/header/MAC; counter increments; rollback refused; corrupt
  cache recomputed; cross-version rejection; exhausted key refused.
- Coverage: 99.74% lines in `qhs5.rs`; 100% functions.
- Mutation: 129 mutants, 94 caught, 32 unviable, 3 missed (1 best-effort
  `Drop`; 2 equivalent); `docs/evidence/qhs5-mutation.txt`.
- Break-log entries: BL-0026, BL-0027.
- Gap IDs: GAP-QHS-0031 — closed; 1-hour soak passed (48,430,620 iterations, 0 panics).

## Closure

- Abuse cases covered: A1–A10 in tests/attack/Kani/CLI.
- Error paths tested: parser, header/checksum, wrong length, wrong key/message,
  tamper matrix, rollback, cache corruption, fuzz.
- Bounds proven: Kani parser/length proofs; checked arithmetic; fuzz.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-09
