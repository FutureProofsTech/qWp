# qWp Function Inventory and FAD Index

**Status:** Production path indexed; research items marked explicitly.<br>
**Rule:** Every function (public and private) in `qwp-core`, `qwp-crypto`, and `qwp-hash` must appear here. Small helpers may be grouped under a parent FAD, but must be named explicitly.

| Function | Module | FAD | Attack harness | Status |
|---|---|---|---|---|
| `braid_from_bytes` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Survived — Kani + fuzz |
| `braid_to_bytes` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Survived — unit + Kani |
| `braid_validate` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Survived — unit + Kani + fuzz |
| `braid_clear` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Survived — best-effort wipe documented |
| `Braid::{from_generators,len,is_empty,iter,as_slice}` | `qwp-core` | `braid/word.md` | `qwp-attacks/parser` | Survived — unit + Kani + fuzz |
| `braid_reduce` | `qwp-core` | planned | `qwp-attacks/reduce` | Research backlog (not production) |
| `braid_metrics` | `qwp-core` | planned | `qwp-attacks/reduce` | Research backlog (not production) |
| `polynomial_from_bytes` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Survived — Kani + fuzz |
| `polynomial_to_bytes` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Survived — unit + Kani |
| `polynomial_coefficient` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Survived — unit tests |
| `Polynomial::{degree_span,nonzero_count,get,set_coefficient,as_slice}` | `qwp-core` | `polynomial/word.md` | `qwp-attacks/solver` | Survived — unit + Kani |
| `polynomial_add` | `qwp-core` | planned | `qwp-attacks/solver` | Research backlog (not production) |
| `polynomial_shift` | `qwp-core` | planned | `qwp-attacks/solver` | Research backlog (not production) |
| `tl_transition` | `qwp-core` | planned | `qwp-attacks/solver` | Research backlog (not production) |
| `solve_invariant` | `qwp-core` | planned | `qwp-attacks/solver` | Research backlog (not production) |
| `blake3_compress` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Survived — KATs + attack vectors + indirect fuzz; hardness assumed |
| `blake3_derive_key` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Survived — KATs + QHS usage + indirect fuzz |
| `hash32` / `Hasher` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Survived — KATs + attack vectors + indirect fuzz |
| `Hash32::{as_bytes,get,size}` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Survived — KATs |
| `Hasher::{new,new_keyed,new_derive_key,update,finalize}` | `qwp-hash` | `hash/blake3.md` | `qwp-attacks/hash` | Survived — KATs + streaming equality |
| `keygen` (legacy braid) | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Legacy research v0; use `qhs_keygen` |
| `sign` (legacy braid) | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Legacy research v0; use `QhsPrivateKey::sign` |
| `verify` (legacy braid) | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Legacy research v0; use `QhsPublicKey::verify` |
| `signature_from_bytes` / `to_bytes` | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Legacy research v0; not production |
| `PrivateKey` / `PublicKey` accessors | `qwp-crypto` | `format/signature.md` | `qwp-attacks/parser` | Legacy research v0; not production |
| `host_entropy_fill` | `qwp-platform` | `platform/entropy.md` | `qwp-attacks/entropy` | Survived — OS CSPRNG; failure paths handled |
| `qhs_keygen` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — proof + KAT + fuzz + timing |
| `qhs_keygen_from_leaves` / `qhs_leaf` / `qhs_leaves` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — equivalence + CLI tests |
| `QhsPrivateKey::sign` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — proof + timing + fuzz |
| `QhsPrivateKey::sign_with_leaves` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — equivalence + CLI tests |
| `QhsPrivateKey` accessors (`from_parts`, `from_bytes`, `to_bytes`, `seed`, `next_leaf`, `is_exhausted`) | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — unit + fuzz |
| `QhsPublicKey` accessors (`from_root`, `from_bytes`, `to_bytes`, `root`) | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — unit + fuzz |
| `QhsSignature` accessors (`from_bytes`, `to_bytes`, `leaf_index`) | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — Kani + fuzz |
| `QhsPublicKey::verify` | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — attack suite + fuzz |
| `message_digits` / WOTS / Merkle internals | `qwp-crypto` | `qhs/qhs1.md` | `qwp-attacks/qhs1` | Survived — KAT + Kani parsers + fuzz |
| `qhs_leaves_parallel` | `qwp-platform` | `qhs/qhs1.md` | `qwp-platform` tests | Survived — parallel/sequential equivalence |
| `read_qhs_cache` / `write_qhs_cache` | `qwp-cli` | `qhs/qhs1.md` §7.1 | `qwp-cli` tests | Survived — tamper/foreign/truncation tests |
| `qhs2_keygen` / `qhs2_keygen_from_leaves` / `qhs2_leaf` / `qhs2_leaves` | `qwp-crypto` | `qhs/qhs2.md` | `qwp-attacks/qhs2` | Survived — KAT + attack + timing |
| `Qhs2PrivateKey::sign` / `sign_with_leaves` | `qwp-crypto` | `qhs/qhs2.md` | `qwp-attacks/qhs2` | Survived — proof + timing + cache equivalence |
| `Qhs2PublicKey::verify` | `qwp-crypto` | `qhs/qhs2.md` | `qwp-attacks/qhs2` | Survived — attack suite + fuzz |
| `Qhs2PrivateKey` / `Qhs2PublicKey` / `Qhs2Signature` accessors | `qwp-crypto` | `qhs/qhs2.md` | `qwp-attacks/qhs2` | Survived — unit + Kani + fuzz |
| `qhs2_leaves_parallel` | `qwp-platform` | `qhs/qhs2.md` | `qwp-platform` tests | Survived — parallel/sequential equivalence |
| QHS-2 cache read/write | `qwp-cli` | `qhs/qhs2.md` | `qwp-cli` tests | Survived — header/tamper/foreign/oversized tests |
| `qhs3_keygen` / `qhs3_keygen_from_leaves` / `qhs3_leaf` | `qwp-crypto` | `qhs/qhs3.md` | `qwp-attacks/qhs3` | Survived — KAT + attack + timing |
| `Qhs3PrivateKey::sign` / `sign_with_leaves` | `qwp-crypto` | `qhs/qhs3.md` | `qwp-attacks/qhs3` | Survived — proof + timing + cache equivalence |
| `Qhs3PublicKey::verify` | `qwp-crypto` | `qhs/qhs3.md` | `qwp-attacks/qhs3` | Survived — attack suite + fuzz |
| `Qhs3PrivateKey` / `Qhs3PublicKey` / `Qhs3Signature` accessors | `qwp-crypto` | `qhs/qhs3.md` | `qwp-attacks/qhs3` | Survived — unit + Kani + fuzz |
| `qhs3_leaves_parallel` | `qwp-platform` | `qhs/qhs3.md` | `qwp-platform` tests | Survived — parallel/sequential equivalence |
| QHS-3 cache read/write | `qwp-cli` | `qhs/qhs3.md` | `qwp-cli` tests | Survived — header/tamper/foreign/oversized tests |
| `qhs3_build_tree` / `qhs3_auth_path_from_tree` | `qwp-crypto` | `qhs/qhs31.md` | `qhs3` unit tests | Survived — tree/leaf equivalence |
| `Qhs3PrivateKey::sign_with_auth_path` | `qwp-crypto` | `qhs/qhs31.md` | `qhs3` unit tests | Survived — signature equivalence |
| QHS-3.1 tree cache read/write | `qwp-cli` | `qhs/qhs31.md` | `qwp-cli` tests | Survived — header/tamper/foreign/oversized tests |

## Status meanings

- **Open** — no FAD/attack harness yet; function may not be implemented.
- **Attacked** — harness exists and has been run.
- **Survived** — attack suite passes; FAD signed.
- **Broken** — a known break exists; gap required.
- **Closed** — FAD complete, signed, and no open gaps.

A missing row is a release blocker.
