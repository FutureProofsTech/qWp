# FAD: qwp_crypto::qhs4 (QHS-4)

## Identity

- Function ID: `qhs4_keygen`, `Qhs4PrivateKey::sign`, `Qhs4PublicKey::verify`, `message_digits`, `wots_sign`, `wots_verify`, `tree_root_and_auth`, `fors_root_and_auth`, `fors_public_key`, `fors_verify`, `climb_path`, CLI `qhs4-*`
- Module: `qwp-crypto/qhs4`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the local production path. Final 1-hour soak recorded in `docs/evidence/`.

## Contract

- Purpose: stateless base-64 WOTS + FORS + eight-layer hypertree signature over in-tree BLAKE3.
- Inputs: 32-byte seed, message bytes, 68-byte keys, 18,216-byte signature.
- Outputs: key pair, signature, verification result.
- Secrets handled: `SK.seed`, WOTS chain values, FORS leaf secrets.
- Trust boundary: untrusted signatures/public keys; secret seed.
- Preconditions: seed from a CSPRNG; keys and signatures use the exact QHS-4 headers; `q ≤ 2^20` for the stated 128-bit bound.
- Postconditions: valid signature verifies; tamper/wrong message/wrong key fails; signing does not mutate the key.
- Invariants: 45 chains × 63 steps; 43+2 base-64 digits; 8 layers × height 8; 16 FORS trees × height 8; header `[4,4,64,0]`; checksum over 18,212 bytes; no heap/unsafe in the crypto core.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, randomizer/tree-index manipulation, auth-path manipulation, cross-version confusion, parser/checksum corruption, timing/fault/DoS.
- Assets targeted: FORS leaves, bottom WOTS key, upper WOTS keys, hypertree roots, public key root, stateless key file.
- Attack tree: `docs/attack-trees.md` §11 and `docs/13-qhs4.md` §11.
- Abuse cases:
  - A1: tamper a FORS secret or auth path.
  - A2: tamper a WOTS chain value.
  - A3: tamper a hypertree auth path.
  - A4: change the randomizer/tree index.
  - A5: wrong message.
  - A6: wrong public key.
  - A7: reuse a bottom leaf with different FORS digests.
  - A8: checksum/header corruption.
  - A9: QHS-1/2/3/3.1/QHS-4 cross-domain confusion.
  - A10: stateless key mutation or unexpected cache/state files.
  - A11: timing/fault/DoS.

## Evidence

- Direct unit tests: `qwp-crypto/src/qhs4.rs` (KAT, round-trip, deterministic signatures, tamper, wrong key/message, header/parser, stateless key bytes).
- Negative/abuse tests: `qwp-attacks::attack_qhs4`; tamper matrix covers header, randomizer, FORS, hypertree, auth path, checksum, all-zero, all-0xff.
- Property tests: signature size, key size, domain-context distinctness, message-digit shape/checksum.
- Fuzz target: in-house fuzz covers random QHS-4 public/private/signature parsing, random verifier inputs, valid signature checks, and random-message signing on longer runs.
- Formal harness: Kani parser proofs pass (`qhs4_public_key_parse_never_panics`, `qhs4_private_key_parse_never_panics`, `qhs4_signature_from_slice_checks_length`).
- Timing harness: keygen ≈0.19 s, sign ≈1.51 s, verify ≈3.0 ms; Welch `|t| < 4.5`.
- Benchmarks: `qhs4_timing`.
- Mutation: 137 mutants, 93 caught, 38 unviable, 6 documented equivalents; no non-equivalent viable survivor (`docs/evidence/qhs4-mutation.txt`).
- CLI tests: keygen/sign/verify end-to-end; private key bytes and mtime unchanged; no `.cache`, `.treecache`, or `.state` files; read-only private key signing succeeds.
- Break-log entries: BL-0019, BL-0020, BL-0021.
- Gap IDs: GAP-QHS-0028 — closed; 1-hour soak evidence recorded.

## Closure

- Abuse cases covered: A1–A9, A11 in tests/attack/Kani; A10 by CLI statelessness tests.
- Error paths tested: parser, header/checksum, wrong length, wrong key/message, tamper matrix, fuzz.
- Bounds proven: Kani parser/length proofs; checked arithmetic; fuzz.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-09
