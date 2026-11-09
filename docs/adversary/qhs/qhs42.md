# FAD: qwp_crypto::qhs42 (QHS-4.2)

## Identity

- Function ID: `qhs42_keygen`, `Qhs42PrivateKey::sign`, `Qhs42PublicKey::verify`, `qhs42_signing_plan`, `qhs42_leaf`, `qhs42_fors_leaf`, tree builders, `qhs42_sign_with_trees`, `qwp_platform::qhs42_sign_parallel`, CLI `qhs42-*`
- Module: `qwp-crypto/qhs42`, `qwp-platform`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the local production path. 1-hour soak passed: 56,556,913 iterations, 0 panics (`docs/evidence/qhs42-fuzz-soak-1h.txt`).

## Contract

- Purpose: compact stateless base-256 WOTS + FORS + seven-layer hypertree
  signature over in-tree BLAKE3.
- Inputs: 32-byte seed, message bytes, 68-byte keys, 14,344-byte signature.
- Outputs: key pair, signature, verification result.
- Secrets handled: `SK.seed`, WOTS chain values, FORS leaf secrets.
- Trust boundary: untrusted signatures/public keys; secret seed.
- Preconditions: seed from a CSPRNG; exact `[5,5,56,0]` headers; `q ≤ 2^20`.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key
  fails; signing does not mutate the key.
- Invariants: WOTS 34 chains × 255 steps; 32+2 base-256 digits; 7 layers ×
  height 8; FORS 17 trees × height 8; checksum over 14,340 bytes; no
  heap/unsafe in the crypto core.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, randomizer/path
  manipulation, auth-path manipulation, cross-version confusion,
  parser/checksum corruption, timing/fault/DoS.
- Assets targeted: FORS leaves, bottom WOTS key, upper WOTS keys, hypertree
  roots, public key root, stateless key file.
- Attack tree: `docs/attack-trees.md` §13 and `docs/15-qhs42.md` §11.
- Abuse cases:
  - A1: tamper a FORS secret or auth path.
  - A2: tamper a WOTS chain value.
  - A3: tamper a hypertree auth path.
  - A4: change the randomizer/tree index.
  - A5: wrong message.
  - A6: wrong public key.
  - A7: reuse a bottom leaf with different FORS digests.
  - A8: checksum/header corruption.
  - A9: QHS-4/4.1/4.2 cross-version confusion.
  - A10: stateless key mutation or unexpected cache/state files.
  - A11: timing/fault/DoS.

## Evidence

- Direct unit tests: `crates/qwp-crypto/src/qhs42.rs` (KAT, round-trip,
  deterministic signatures, tamper, wrong key/message, header/parser,
  stateless key bytes, layer-by-layer internal derivation).
- Negative/abuse tests: `qwp-attacks::attack_qhs42`; suite 11/11.
- Property tests: signature size, key size, domain-context distinctness,
  message-digit shape/checksum, public leaf helpers.
- Fuzz target: in-house fuzz covers random QHS-4.2 public/private/signature
  parsing, random verifier inputs, valid signature checks, and random-message
  signing on longer runs. 60-second run: 853,000 iterations, 0 panics;
  1-hour soak: 56,556,913 iterations, 0 panics.
- Formal harness: Kani parser proofs pass (`qhs42_public_key_parse_never_panics`,
  `qhs42_private_key_parse_never_panics`,
  `qhs42_signature_from_slice_checks_length`); 18/18 workspace total.
- Timing harness: keygen ≈0.30 s, sequential sign ≈2.08 s, parallel sign
  ≈0.27 s, verify ≈4.0 ms; Welch `|t| < 4.5`.
- Coverage: 99.33% lines in `qhs42.rs`.
- Mutation: 187 mutants, 130 caught, 48 unviable, 9 missed (8 release-only
  `sign_with_trees` assembly paths covered by release/platform equivalence; 1
  best-effort `Drop`); `docs/evidence/qhs42-mutation.txt`.
- CLI tests: keygen/sign/verify end-to-end; private key bytes/mtime unchanged;
  no `.cache`, `.treecache`, or `.state` files; read-only private key signing
  succeeds; QHS-4 verifier rejects the 14,344-byte signature.
- Break-log entries: BL-0024, BL-0025.
- Gap IDs: GAP-QHS-0030 — closed; 1-hour soak passed (56,556,913 iterations, 0 panics).

## Closure

- Abuse cases covered: A1–A11 in tests/attack/Kani/CLI.
- Error paths tested: parser, header/checksum, wrong length, wrong key/message,
  tamper matrix, fuzz.
- Bounds proven: Kani parser/length proofs; checked arithmetic; fuzz.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-09
