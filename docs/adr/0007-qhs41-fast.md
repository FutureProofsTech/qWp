# ADR-0007: QHS-4.1 Parallel Fast-Signing Profile

**Status:** Accepted and implemented — local evidence complete; 1-hour soak passed; `qhs41-rc1`

**Date:** 2026-11-09

**Deciders:** qWp owner, crypto lead, red team

**Related:** `docs/14-qhs41.md`, `docs/13-qhs4.md`, `docs/03-formats.md`

---

## Context

QHS-4 is stateless, but signing is dominated by the eight hypertree subtree
generations and the FORS tree generation. After the 64-bit path is derived, the
tree structures are message-independent: each tree depends only on the private
seed, `PK.seed`, the layer/tree index, and the leaf index. The WOTS signatures
depend on the child roots, but those roots are also known once the trees are
built.

The sequential QHS-4 implementation therefore leaves a large safe optimization
on the table: compute the independent trees in parallel, then assemble the same
signature bytes.

## Decision

QHS-4.1 is a **performance profile of QHS-4**, not a new signature parameter
set:

- Same 68-byte public/private keys.
- Same 18,216-byte signature format and header `[4, 4, 64, 0]`.
- Same QHS-4 proof, domain contexts, and `q ≤ 2^20` security bound.
- Same sequential `Qhs4PrivateKey::sign` as the reference and fallback.
- Add reusable BLAKE3 derive-key contexts (`DeriveKey`) so the context hash is
  not repeated for every chain step.
- Expose the QHS-4 leaf/tree primitives and a `qhs4_sign_with_trees` assembly
  function.
- Add `qwp-platform::qhs4_sign_parallel`, which computes the hypertree and FORS
  leaves with scoped threads, builds the trees, and calls the assembly
  function.
- Add `qhs41-*` CLI commands. `qhs4-verify` and `qhs41-verify` both accept the
  same signature bytes.

## Why this is sound

- The parallel and sequential paths produce **byte-identical signatures**; the
  release tests compare them for a fixed KAT and random messages.
- The tree leaves are public hash commitments; parallel scheduling changes no
  hash input, output, or ordering.
- `DeriveKey` computes the same BLAKE3 derive-key output as `derive_key32`; the
  hash crate has direct equivalence tests.
- No new cryptographic assumption, key format, signature format, or security
  parameter is introduced.
- The sequential `sign` remains available, so a platform without threads can
  ignore the profile entirely.

## Consequences

- New `docs/14-qhs41.md`, ADR-0007, FAD, traceability/gap/break entries, and
  `qhs41-*` CLI tests.
- New timing harness (`qhs41_timing`), coverage, mutation, fuzz, and a fresh
  1-hour soak.
- Tag `qhs41-rc1`; QHS-4 and all prior tags remain unchanged.
- Expected speedup on the reference host: sequential ≈0.81 s, parallel ≈0.11 s
  (≈7.4×), with the same 18,216-byte signature.
