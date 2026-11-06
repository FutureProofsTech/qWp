# FAD: qwp_hash::blake3 (hash32/derive_key32/Hasher)

## Identity

- Function ID: `qwp_hash::{hash32,derive_key32,Hasher}`
- Module: `qwp-hash/blake3`
- Visibility: public
- Owner (engineer): Crypto/Rust lead
- Owner (attacker): Red team
- Status: survived KATs; fuzz/Kani pending (GAP-CRYPTO-0014)

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
- Negative/abuse tests: `qwp-attacks::attack_hash_vectors`.
- Property tests: pending.
- Fuzz target: pending.
- Formal harness: pending (Kani for bounds).
- Timing harness: pending (hash is data-independent by design).
- Benchmarks: `qwp-bench` 1024-byte case.
- Break-log entries: BL-0008.
- Gap IDs: GAP-CRYPTO-0014.

## Closure

- Abuse cases covered: A1–A9 mostly; A8 stack proof pending.
- Error paths tested: no error paths (infallible).
- Bounds proven: pending Kani.
- Red-team sign-off: pending fuzz/Kani.
- Date: 2026-11-06
