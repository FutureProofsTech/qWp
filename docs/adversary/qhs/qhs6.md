# FAD: qwp_crypto::qhs6 and qwp_classical::ed25519 (QHS-6)

## Identity

- Function ID: `qhs6_keygen`, `qhs6_keygen_from_leaves`, `Qhs6PrivateKey::sign`, `Qhs6PrivateKey::sign_with_leaves`, `Qhs6PublicKey::verify`, CLI `qhs6-*`; `Ed25519PrivateKey::sign`, `Ed25519PublicKey::verify`, `qwp_classical::sha512`
- Module: `qwp-crypto/qhs6`, `qwp-classical`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the local production path. 1-hour soak passed: 36,957,000 iterations, 0 panics (`docs/evidence/qhs6-fuzz-soak-1h.txt`).

## Contract

- Purpose: hybrid QHS-5 + Ed25519 signature over a key-and-message transcript.
- Inputs: QHS-5 seed (64), Ed25519 seed (32), message, 108-byte keys,
  6,284-byte signature.
- Outputs: hybrid key pair, hybrid signature, verification result.
- Secrets handled: QHS-5 seed, Ed25519 seed, Ed25519 scalar nonce.
- Trust boundary: untrusted signatures/public keys; secret seeds and QHS-5
  counter.
- Preconditions: seeds from a CSPRNG; QHS-6 headers; QHS-5 leaf `< 256`;
  single-writer key use.
- Postconditions: both components verify; tamper/wrong message/wrong key fails;
  each signature consumes one QHS-5 leaf and persists the counter first.
- Invariants: transcript binds both public keys and the message; QHS-5 89×63
  WOTS; Ed25519 RFC 8032; `S < L`; canonical point decoding; small-order
  rejection; no heap/unsafe in the crypto core.

## Attacker model

- Capabilities: chosen message, component mixing, signature tampering, wrong
  key, header/path manipulation, cross-version confusion, parser/checksum
  corruption, Ed25519 non-canonical `S`/invalid point/small-order point, cache
  corruption, key/state rollback, timing/fault/DoS.
- Assets targeted: QHS-5 leaf uniqueness, QHS-5 root, Ed25519 scalar/public key,
  transcript binding, key counter, cache integrity.
- Attack tree: `docs/attack-trees.md` §15 and `docs/17-qhs6.md` §12.
- Abuse cases:
  - A1: mix a QHS-5 signature and an Ed25519 signature from different messages
    or keys.
  - A2: tamper the QHS-5 component.
  - A3: tamper the Ed25519 component.
  - A4: wrong message/key.
  - A5: reuse a QHS-5 leaf by resetting the counter.
  - A6: corrupt/foreign cache or roll back the state guard.
  - A7: non-canonical Ed25519 `S`, invalid point, or small-order point.
  - A8: cross-version confusion with QHS-5 or Ed25519-only data.
  - A9: timing/fault/DoS.

## Evidence

- RFC 8032 vectors 1 and 2: public key and signature byte equality.
- SHA-512 empty/`abc`/streaming vectors.
- Field/scalar/point invariants, basepoint order, canonical encodings.
- QHS-6 KAT/round-trip/tamper/transcript-binding/exhaustion tests.
- Negative/abuse tests: `qwp-attacks::attack_qhs6`; suite 13/13.
- Kani: `qhs6_private_key_parse_never_panics`,
  `qhs6_signature_from_slice_checks_length`,
  `ed25519_signature_from_slice_checks_length`. The QHS-6 public-key parser
  decodes Ed25519 and is covered by RFC vectors/fuzz rather than Kani (CBMC
  memory).
- Coverage: qhs6.rs 99.25% lines; qwp-classical 99.66% lines; 100% functions.
- Timing: QHS-6 parallel keygen ≈0.09 s, cached sign ≈2.0 ms, verify ≈1.5 ms;
  Ed25519 keygen ≈0.125 ms, sign ≈0.257 ms, verify ≈0.258 ms; Welch `|t| < 4.5`.
- CLI tests: keygen/sign/verify; cache/state sizes, headers, fingerprints,
  MACs; counter increments; rollback refused; cache corruption recovery;
  cross-version rejection; exhausted key refused.
- Break-log entries: BL-0028, BL-0029.
- Gap IDs: GAP-QHS-0032 — closed; 1-hour soak passed (36,957,000 iterations, 0 panics).

## Closure

- Abuse cases covered: A1–A9 in tests/attack/Kani/CLI.
- Error paths tested: parser, headers, transcript mixing, tamper, wrong
  key/message, Ed25519 canonical/small-order, rollback, cache corruption, fuzz.
- Bounds proven: Kani parser/length proofs; checked arithmetic; fuzz.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-09
