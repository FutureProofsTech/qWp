# ADR-0008: QHS-4.2 Compact Stateless Profile

**Status:** Accepted and implemented — local evidence complete; 1-hour soak passed; `qhs42-rc1`

**Date:** 2026-11-09

**Deciders:** qWp owner, crypto lead, red team

**Related:** `docs/15-qhs42.md`, `docs/13-qhs4.md`, `docs/14-qhs41.md`, `docs/03-formats.md`

---

## Context

QHS-4 and QHS-4.1 are stateless and sound for `q ≤ 2^20`, but their signature is
18,216 bytes. The owner wants a **compact** stateless profile with a smaller
signature while keeping the same 128-bit classical / ≥64-bit quantum target and
the same `q ≤ 2^20` limit. No 2^64 variant is planned.

The compact profile cannot be a pure implementation optimization: reducing the
signature requires changing the WOTS/FORS/hypertree parameters and therefore the
security proof and wire format. It is a new version, `QHS-4.2`.

## Decision

QHS-4.2 uses:

| Parameter | Value |
|---|---:|
| Hash | BLAKE3, 32-byte output |
| WOTS base | 256 |
| WOTS chains | 34 (32 message + 2 checksum) |
| WOTS chain length | 255 steps |
| Hypertree layers | 7 |
| Subtree height | 8 |
| Total height | 56 |
| FORS trees | 17 |
| FORS height | 8 (256 leaves/tree) |
| Public key | 68 bytes |
| Private key | 68 bytes |
| Signature | **14,344 bytes** |
| Header | `[5, 5, 56, 0]` |

Signature layout:

```
4 header | 32 randomizer | 4,896 FORS | 9,408 hypertree | 4 checksum
```

- FORS: `17 × (32 + 8×32) = 4,896`.
- Hypertree: `7 × (1,088 WOTS + 256 auth) = 9,408`.
- WOTS signature: `34 × 32 = 1,088` per layer.

## Why this is sound

The construction is the QHS-4 hypertree/FORS design with compact parameters.
At `q = 2^20`:

- **WOTS fixed-message:** loss `34 × 255 = 8,670 ≈ 2^13.08`; preimage security
  ≈`2^242.9`, capped by the 128-bit hash collision bound.
- **FORS one-time:** `17 × 8 = 136` bits.
- **FORS q-fold bottom-leaf targeting:** `2^(20−56−136) = 2^-172`.
- **FORS leaf reuse after a 56-bit path collision:** `2^(39−56−17×7) = 2^-136`.
- **Merkle/FORS collision:** ≈`2^-128` classical, the limiting term.
- **Quantum:** FORS index search ≈`2^68`; collision ≈`2^85`; bottom-leaf
  selection ≈`2^28`; conservative bound ≥64 bits.

The WOTS base-256 digit encoding is exact: the 32-byte message is 32 base-256
digits; the checksum is `Σ(255 − d_i)` over the 32 message digits, encoded in
two base-256 digits (high 8 bits and low 8 bits). The checksum range is
`0..=8160`, which fits 16 bits.

The 56-bit path still gives `q/2^56 = 2^-36` at `q = 2^20`; the FORS q-fold and
leaf-reuse terms remain at least 128 bits. The hash collision bound is
unchanged.

## Consequences

- New `qhs42-*` CLI commands, formats, domain contexts, tests, attacks, Kani,
  fuzz, timing, coverage, mutation, and a fresh 1-hour soak.
- QHS-4 and QHS-4.1 remain unchanged and tagged.
- QHS-4.2 is **not** signature-compatible with QHS-4/4.1: different WOTS
  parameters, FORS tree count, total height, and header.
- The compact profile is slower to sign than QHS-4.1 (more WOTS chain steps),
  but smaller. It can use the QHS-4.1 parallel tree strategy.
- No 2^64 variant is planned or claimed.
