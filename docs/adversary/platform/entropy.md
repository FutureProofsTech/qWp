# FAD: qwp_platform::HostEntropy

## Identity

- Function ID: `qwp_platform::HostEntropy::{open,fill}`
- Module: `qwp-platform`
- Visibility: public
- Owner (engineer): Platform lead
- Owner (attacker): Red team
- Status: survived; OS CSPRNG adapter with fail-closed errors. No user-space health tests by design.

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
  - A6: entropy content quality.

## Evidence

- Direct unit tests: `qwp-platform/src/lib.rs` (zero-length, normal fill with non-zero output assertion, debug formatting, parallel-leaf equivalence).
- Negative/abuse tests: `qwp-attacks::attack_entropy`.
- Property tests: not applicable to the OS source.
- Fuzz target: not applicable to OS entropy.
- Formal harness: not applicable.
- Timing harness: not secret-dependent beyond requested length.
- Benchmarks: not meaningful for a kernel CSPRNG read.
- Break-log entries: none.
- Gap IDs: GAP-KEY-0008, GAP-CRYPTO-0014 — closed.

## Closure

- Abuse cases covered: A1–A5 tested/handled; A6 is delegated to the kernel CSPRNG. User-space statistical health tests are not applied because they do not add entropy and can cause false failures for a kernel CSPRNG.
- Error paths tested: open failure maps to `EntropyFailure`; `read_exact` handles short reads; non-Unix returns `UnsupportedPlatform`.
- Bounds proven: slice length is enforced by `read_exact`; no fixed buffer.
- Red-team sign-off: accepted with the OS CSPRNG trust assumption.
- Date: 2026-11-06
