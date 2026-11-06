# qWp Function Inventory and FAD Index

**Status:** Seeded  
**Rule:** Every function (public and private) in `qwp-core`, `qwp-crypto`, and `qwp-hash` must appear here. Small helpers may be grouped under a parent FAD, but must be named explicitly.

| Function | Module | FAD | Attack harness | Status |
|---|---|---|---|---|
| `braid_from_bytes` | `qwp-core` | `braid/from_bytes.md` | `qwp-attacks/parser` | Open |
| `braid_write` | `qwp-core` | `braid/write.md` | `qwp-attacks/parser` | Open |
| `braid_reduce` | `qwp-core` | `braid/reduce.md` | `qwp-attacks/reduce` | Open |
| `braid_metrics` | `qwp-core` | `braid/metrics.md` | `qwp-attacks/reduce` | Open |
| `polynomial_add` | `qwp-core` | `polynomial/add.md` | `qwp-attacks/solver` | Open |
| `polynomial_shift` | `qwp-core` | `polynomial/shift.md` | `qwp-attacks/solver` | Open |
| `tl_transition` | `qwp-core` | `invariant/tl.md` | `qwp-attacks/solver` | Open |
| `solve_invariant` | `qwp-core` | `invariant/solve.md` | `qwp-attacks/solver` | Open |
| `blake3_compress` | `qwp-hash` | `hash/compress.md` | `qwp-attacks/hash` | Open |
| `blake3_derive_key` | `qwp-hash` | `hash/derive_key.md` | `qwp-attacks/hash` | Open |
| `keygen` | `qwp-crypto` | `crypto/keygen.md` | `qwp-attacks/keygen` | Open |
| `sign` | `qwp-crypto` | `crypto/sign.md` | `qwp-attacks/sign` | Open |
| `verify` | `qwp-crypto` | `crypto/verify.md` | `qwp-attacks/verify` | Open |
| `parse_signature` | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Open |

## Status meanings

- **Open** — no FAD/attack harness yet.
- **Attacked** — harness exists and has been run.
- **Survived** — attack suite passes; FAD signed.
- **Broken** — a known break exists; gap required.
- **Closed** — FAD complete, signed, and no open gaps.

A missing row is a release blocker.
