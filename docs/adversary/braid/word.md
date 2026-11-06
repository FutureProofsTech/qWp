# FAD: qwp_core::Braid (word parse/write/validate/clear)

## Identity

- Function ID: `qwp_core::Braid::{from_bytes,to_bytes,validate,clear}`
- Module: `qwp-core/braid`
- Visibility: public
- Owner (engineer): Rust core lead
- Owner (attacker): Red team
- Status: survived unit/attack; formal proof pending (GAP-CRYPTO-0014)

## Contract

- Purpose: parse, validate, serialize, and best-effort clear a 40-byte braid word.
- Inputs: `[u8; 40]` for parsing; generator slices for construction.
- Outputs: `Result<Braid, CryptoError>`; `[u8; 40]` for serialization.
- Secrets handled: a braid can be a private key.
- Trust boundary: untrusted bytes enter here.
- Preconditions: none.
- Postconditions: active generators are `±1..=±7`; padding is zero; length ≤ 32.
- Invariants: size is exactly 40 bytes; no heap; no panic.

## Attacker model

- Capabilities: chosen input, malformed bytes, boundary values.
- Assets targeted: parser state, key material, length field.
- Attack tree: `docs/attack-trees.md` §2 and §4.
- Abuse cases:
  - A1: length > 32.
  - A2: zero generator.
  - A3: generator outside `-7..=7`.
  - A4: non-zero padding.
  - A5: all-zero / empty braid.
  - A6: maximum length 32.
  - A7: endianness of the length field.
  - A8: clear leaves stale data (best-effort limitation).

## Evidence

- Direct unit tests: `qwp-core/src/braid.rs` tests.
- Negative/abuse tests: `qwp-attacks::attack_braid_parser`.
- Property tests: pending.
- Fuzz target: pending.
- Formal harness: `qwp-verify` `braid_from_bytes_never_panics`, `braid_round_trip_is_stable`.
- Timing harness: not secret-dependent for parsing; pending.
- Benchmarks: `qwp-bench` braid cases.
- Break-log entries: BL-0009.
- Gap IDs: GAP-FMT-0003, GAP-CRYPTO-0014.

## Closure

- Abuse cases covered: A1–A7 yes; A8 documented limitation.
- Error paths tested: yes.
- Bounds proven: Kani harness written, proof run pending.
- Red-team sign-off: pending formal/fuzz.
- Date: 2026-11-06
