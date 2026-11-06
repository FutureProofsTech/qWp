# qWp Function Inventory and FAD Index

**Status:** Foundation slice  
**Rule:** Every function (public and private) in `qwp-core`, `qwp-crypto`, and `qwp-hash` must appear here. Small helpers may be grouped under a parent FAD, but must be named explicitly.

| Function | Module | FAD | Attack harness | Status |
|---|---|---|---|---|
| `braid_from_bytes` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Attacked (formal pending) |
| `braid_to_bytes` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Attacked |
| `braid_validate` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Attacked |
| `braid_clear` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Attacked (best-effort wipe) |
| `braid_reduce` | `qwp-core` | planned | `qwp-attacks/reduce` | Open (not implemented) |
| `braid_metrics` | `qwp-core` | planned | `qwp-attacks/reduce` | Open (not implemented) |
| `polynomial_from_bytes` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Attacked (formal pending) |
| `polynomial_to_bytes` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Attacked |
| `polynomial_coefficient` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Attacked |
| `polynomial_add` | `qwp-core` | planned | `qwp-attacks/solver` | Open (not implemented) |
| `polynomial_shift` | `qwp-core` | planned | `qwp-attacks/solver` | Open (not implemented) |
| `tl_transition` | `qwp-core` | planned | `qwp-attacks/solver` | Open (not implemented) |
| `solve_invariant` | `qwp-core` | planned | `qwp-attacks/solver` | Open (not implemented) |
| `blake3_compress` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Attacked (KATs; fuzz/Kani pending) |
| `blake3_derive_key` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Attacked (KATs; fuzz/Kani pending) |
| `hash32` / `Hasher` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Attacked (KATs; fuzz/Kani pending) |
| `keygen` | `qwp-crypto` | planned | `qwp-attacks/keygen` | Open (not implemented) |
| `sign` | `qwp-crypto` | planned | `qwp-attacks/sign` | Open (not implemented) |
| `verify` | `qwp-crypto` | planned | `qwp-attacks/verify` | Open (not implemented) |
| `signature_from_bytes` / `to_bytes` | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Attacked (semantics open) |
| `host_entropy_fill` | `qwp-platform` | `platform/entropy.md` | `qwp-attacks/entropy` | Attacked (health tests pending) |
| `qhs_keygen` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Attacked (proof/fuzz pending) |
| `QhsPrivateKey::sign` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Attacked (timing pending) |
| `QhsPublicKey::verify` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Attacked |
| `message_digits` / WOTS / Merkle internals | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Attacked (Kani/fuzz pending) |

## Status meanings

- **Open** — no FAD/attack harness yet; function may not be implemented.
- **Attacked** — harness exists and has been run.
- **Survived** — attack suite passes; FAD signed.
- **Broken** — a known break exists; gap required.
- **Closed** — FAD complete, signed, and no open gaps.

A missing row is a release blocker.
