# FAD: qwp_hash::blake3 (hash32/derive_key32/Hasher)

## Identity

- Function ID: `qwp_hash::{hash32,derive_key32,Hasher}`
- Module: `qwp-hash/blake3`
- Visibility: public
- Owner (engineer): Crypto/Rust lead
- Owner (attacker): Red team
- Status: survived KATs, known vectors, streaming/keyed/derive-key tests, and indirect fuzz through the verifier; cryptographic hardness is an explicit assumption (GAP-CRYPTO-0014 closed)

## Contract

- Purpose: in-tree BLAKE3 hash, keyed mode, derive-key mode, streaming.
- Inputs: arbitrary byte slices, 32-byte key, context.
- Outputs: `Hash32` (32 bytes).
- Secrets handled: keyed mode may process secrets.
- Trust boundary: hash input is untrusted; hash output is public.
- Preconditions: none.
- Postconditions: deterministic 32-byte output; streaming equals one-shot.
- Invariants: no heap, no unsafe, no panic, chunk/tree bounds fixed.

## Attacker model

- Capabilities: chosen input, length boundaries, keyed/derive-key misuse.
- Assets targeted: hash collision/preimage, length-extension, parser state.
- Attack tree: `docs/attack-trees.md` §4.
- Abuse cases:
  - A1: empty input.
  - A2: 1, 63, 64, 65 bytes.
  - A3: 1023, 1024, 1025 bytes.
  - A4: 2048, 4096, 10000 bytes.
  - A5: streaming with odd chunk sizes.
  - A6: keyed mode.
  - A7: derive-key mode.
  - A8: very long input / stack depth.
  - A9: zero-length update.

## Evidence

- Direct unit tests: `qwp-hash/src/blake3.rs` (empty, abc, long, streaming, keyed, derive-key).
- Negative/abuse tests: `qwp-attacks::attack_hash_vectors` (known vectors and boundary lengths).
- Property/equivalence tests: streaming equals one-shot at tested chunk boundaries.
- Fuzz target: hash is exercised indirectly by the parser/verifier fuzz (13,270,061 iterations / 60s, 0 panics); no dedicated BLAKE3 fuzz target.
- Formal harness: none for the compression function; safe Rust and fixed-size arrays, no unsafe. Cryptographic hardness is not machine-proved.
- Timing harness: no secret-dependent branches by design; BLAKE3 is data-independent.
- Benchmarks: `qwp-bench` 1024-byte case.
- Break-log entries: BL-0008.
- Gap IDs: GAP-CRYPTO-0014 — closed with KAT/attack/fuzz evidence; hardness remains an assumption.

## Closure

- Abuse cases covered: A1–A9 by KATs/attack vectors; A8 is bounded by fixed-size arrays and safe Rust, not a machine proof.
- Error paths tested: no error paths (infallible).
- Bounds proven: Rust type/array bounds + fuzz; no Kani compression proof.
- Red-team sign-off: accepted with the explicit BLAKE3 hardness assumption.
- Date: 2026-11-06
