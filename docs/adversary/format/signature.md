# FAD: qwp_crypto::Signature

## Identity

- Function ID: `qwp_crypto::Signature::{from_bytes,to_bytes,as_bytes,is_zero}`
- Module: `qwp-crypto/format`
- Visibility: public
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived unit/attack; signature semantics not implemented

## Contract

- Purpose: fixed 160-byte signature container.
- Inputs: `[u8; 160]`.
- Outputs: `Signature`, `[u8; 160]`, byte reference, zero check.
- Secrets handled: no (signature is public).
- Trust boundary: untrusted signature bytes.
- Preconditions: none.
- Postconditions: exact round-trip; size 160.
- Invariants: no interpretation until the custom signature spec is frozen.

## Attacker model

- Capabilities: arbitrary signature bytes, all-zero, all-0xff.
- Assets targeted: parser, malleability, cross-protocol confusion.
- Attack tree: `docs/attack-trees.md` §1.
- Abuse cases:
  - A1: all-zero signature.
  - A2: all-0xff signature.
  - A3: arbitrary round-trip.
  - A4: semantic acceptance without verification (not implemented; must fail closed).

## Evidence

- Direct unit tests: `qwp-crypto/src/format.rs`.
- Negative/abuse tests: `qwp-attacks::attack_key_formats`.
- Property tests: pending.
- Fuzz target: pending.
- Formal harness: pending.
- Timing harness: comparison not implemented.
- Benchmarks: pending.
- Break-log entries: none.
- Gap IDs: GAP-FMT-0007, GAP-CRYPTO-0001.

## Closure

- Abuse cases covered: container only; semantic cases open.
- Error paths tested: no error paths in container.
- Bounds proven: size assertion.
- Red-team sign-off: pending signature semantics.
- Date: 2026-11-06
