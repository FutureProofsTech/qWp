# FAD: qwp_crypto::Signature

## Identity

- Function ID: `qwp_crypto::Signature::{from_bytes,to_bytes,as_bytes,is_zero}`
- Module: `qwp-crypto/format`
- Visibility: public
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived unit/attack as a legacy research container. Not used for production; production signatures use QHS-1 (`qhs/qhs1.md`).

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
- Property/equivalence tests: exact round-trip.
- Fuzz target: parser fuzz exercises the container.
- Formal harness: not applicable; no semantics are attached.
- Timing harness: comparison not implemented (container only).
- Benchmarks: not applicable to the legacy container.
- Break-log entries: BL-0001 (original construction rejected).
- Gap IDs: GAP-FMT-0007, GAP-CRYPTO-0001 — closed; legacy v0 retained as research.

## Closure

- Abuse cases covered: container only. A4 semantic acceptance is not implemented; no production sign/verify path uses this container.
- Error paths tested: no error paths in the container.
- Bounds proven: size assertion.
- Red-team sign-off: accepted as research-only; QHS-1 is the production signature.
- Date: 2026-11-06
