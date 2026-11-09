# ADR-0006: QHS-4 Stateless Hypertree/FORS Signature

**Status:** Accepted and implemented — local evidence complete; final soak before `qhs4-rc1`

**Date:** 2026-11-09

**Deciders:** qWp owner, crypto lead, red team

**Related:** `docs/13-qhs4.md`, `docs/09-version-family.md`, `docs/03-formats.md`

---

## Context

QHS-1/2/3/3.1 are stateful: the signer must persist a monotonic leaf counter.
QHS-4 is the planned stateless version for use cases where a counter cannot be
maintained safely.

A stateless hash-based signature needs a few-time signature layer and a
hypertree. The design follows the SPHINCS+-style construction, but is implemented
and proved independently in this project.

## Decision

QHS-4 uses:

| Parameter | Value |
|---|---:|
| Hash | BLAKE3, 32-byte output |
| WOTS | 45 chains × 63 steps, 43 + 2 base-64 digits |
| Hypertree layers | 8 |
| Subtree height | 8 |
| Total height | 64 |
| FORS trees | 16 |
| FORS tree height | 8 (256 leaves) |
| Public key | 68 bytes |
| Private key | 68 bytes |
| Signature | 18,216 bytes |

Layout:

```
4 header | 32 randomizer | 4,608 FORS | 13,568 hypertree | 4 checksum
```

The private key stores `SK.seed` and `PK.seed`; there is no counter, no cache,
and no state guard. Signing is stateless.

## Why this is sound

- Every WOTS key signs a **fixed** value:
  - the bottom WOTS key signs the fixed FORS public key for that leaf;
  - upper WOTS keys sign fixed lower-tree roots.
  Reusing a WOTS key therefore repeats the same signature and leaks nothing new.
- Only the FORS key degrades with reuse. FORS uses 16 trees of 256 leaves.
  After `γ` uses of one FORS key, a forgery requires a digest whose 16 indices
  all hit revealed leaves; the probability is at most `(γ/256)^16`.
  For `γ = 1`, this is `2^-128`; for `γ = 2`, `2^-112`.
- A full 64-bit hypertree path collision is required to reuse a bottom leaf.
  For `q` signatures, that probability is at most `q^2 / 2^65`.
  For `q ≤ 2^20`, this is `2^-25`; even then, FORS forgery after reuse is
  `2^-112`, so the combined term is `2^-137`.
- Merkle path forgery reduces to a BLAKE3 collision; the 32-byte output gives a
  128-bit classical collision bound.
- WOTS one-time security is the same reduction as QHS-2 with a 45×63 loss.

The overall target is at least 128-bit classical and 64-bit quantum for
`q ≤ 2^20` signatures per key. QHS-4 is stateless, but its security bound is
finite in the number of signatures; this is documented explicitly.

## Consequences

- New `qhs4-*` CLI commands, formats, domain contexts, and tests.
- No key cache, no counter, no state guard.
- New KAT, attack harness, Kani parser proofs, fuzz coverage, and timing.
- A fresh 1-hour soak is required before the `qhs4-rc1` tag.
- QHS-1/2/3/3.1 remain unchanged and tagged.
- Implementation: `crates/qwp-crypto/src/qhs4.rs`; formats: `docs/03-formats.md` §10.18–10.22; proof/evidence: `docs/13-qhs4.md`.
