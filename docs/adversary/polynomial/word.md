# FAD: qwp_core::Polynomial (parse/write/coefficient)

## Identity

- Function ID: `qwp_core::Polynomial::{from_bytes,to_bytes,coefficient,set_coefficient}`
- Module: `qwp-core/polynomial`
- Visibility: public
- Owner (engineer): Math/Rust lead
- Owner (attacker): Red team
- Status: survived unit/attack and Kani proof; fuzz pending (GAP-CRYPTO-0014)

## Contract

- Purpose: exact 516-byte polynomial encoding and bounded coefficient access.
- Inputs: `[u8; 516]`, degree `i32`, coefficient `i32`.
- Outputs: `Polynomial`, `[u8; 516]`, `Result<i32, CryptoError>`.
- Secrets handled: no (public key material).
- Trust boundary: untrusted bytes enter here.
- Preconditions: none.
- Postconditions: round-trip is exact; degree access is bounded.
- Invariants: size is exactly 516 bytes; degrees `-64..=64`.

## Attacker model

- Capabilities: chosen bytes, boundary degrees, `i32::MIN/MAX`.
- Assets targeted: public-key parser, coefficient bounds.
- Attack tree: `docs/attack-trees.md` §4.
- Abuse cases:
  - A1: degree 65 or -65.
  - A2: `i32::MIN` / `i32::MAX` coefficients.
  - A3: all-zero polynomial.
  - A4: arbitrary 516-byte input round-trip.

## Evidence

- Direct unit tests: `qwp-core/src/polynomial.rs`.
- Negative/abuse tests: `qwp-attacks::attack_polynomial_round_trip`.
- Property tests: pending.
- Fuzz target: pending.
- Formal harness: `qwp-verify` `polynomial_round_trip_is_exact`.
- Timing harness: not secret-dependent.
- Benchmarks: `qwp-bench` polynomial case.
- Break-log entries: none.
- Gap IDs: GAP-FMT-0003, GAP-CRYPTO-0014.

## Closure

- Abuse cases covered: yes.
- Error paths tested: yes.
- Bounds proven: Kani proof passes.
- Red-team sign-off: pending fuzz.
- Date: 2026-11-06
