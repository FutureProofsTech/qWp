# FAD: qwp_platform::HostEntropy

## Identity

- Function ID: `qwp_platform::HostEntropy::{open,fill}`
- Module: `qwp-platform`
- Visibility: public
- Owner (engineer): Platform lead
- Owner (attacker): Red team
- Status: survived unit/attack; portability and failure tests pending

## Contract

- Purpose: safe Unix entropy from `/dev/urandom`.
- Inputs: mutable byte slice.
- Outputs: `Result<(), CryptoError>`.
- Secrets handled: yes (entropy output).
- Trust boundary: OS entropy source.
- Preconditions: Unix host.
- Postconditions: requested bytes filled or `EntropyFailure`.
- Invariants: no unsafe, no FFI, no external crate.

## Attacker model

- Capabilities: zero-length request, large request, missing `/dev/urandom`, read failure.
- Assets targeted: key generation seed, RNG failure handling.
- Attack tree: `docs/attack-trees.md` §5.
- Abuse cases:
  - A1: zero-length fill.
  - A2: normal 32-byte fill.
  - A3: `/dev/urandom` unavailable.
  - A4: short read.
  - A5: non-Unix platform.
  - A6: entropy content quality (health tests pending).

## Evidence

- Direct unit tests: `qwp-platform/src/lib.rs`.
- Negative/abuse tests: `qwp-attacks::attack_entropy`.
- Property tests: pending.
- Fuzz target: not applicable to OS entropy.
- Formal harness: not applicable.
- Timing harness: pending.
- Benchmarks: pending.
- Break-log entries: none.
- Gap IDs: GAP-KEY-0008, GAP-CRYPTO-0014.

## Closure

- Abuse cases covered: A1–A5; A6 health tests pending.
- Error paths tested: open/fill failure paths partly.
- Bounds proven: no fixed buffer.
- Red-team sign-off: pending health tests.
- Date: 2026-11-06
