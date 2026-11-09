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
| Key state guard read/write | `qwp-cli` | `docs/03-formats.md` §10.17 | `qwp-cli` tests | Survived — rollback/missing-guard tests |
| `qhs4_keygen` | `qwp-crypto` | `qhs/qhs4.md` | `qwp-attacks/qhs4` | Survived — KAT + attack + timing |
| `Qhs4PrivateKey::sign` | `qwp-crypto` | `qhs/qhs4.md` | `qwp-attacks/qhs4` | Survived — proof + stateless CLI tests |
| `Qhs4PublicKey::verify` | `qwp-crypto` | `qhs/qhs4.md` | `qwp-attacks/qhs4` | Survived — attack suite + fuzz |
| `Qhs4PrivateKey` / `Qhs4PublicKey` / `Qhs4Signature` accessors | `qwp-crypto` | `qhs/qhs4.md` | `qwp-attacks/qhs4` | Survived — unit + Kani + fuzz |
| QHS-4 WOTS/FORS/hypertree internals (`message_digits`, `wots_sign`, `wots_verify`, `tree_root_and_auth`, `fors_root_and_auth`, `fors_public_key`, `fors_verify`, `climb_path`) | `qwp-crypto` | `qhs/qhs4.md` | `qwp-attacks/qhs4` | Survived — KAT + tamper + fuzz |
| QHS-4 CLI keygen/sign/verify | `qwp-cli` | `qhs/qhs4.md` | `qwp-cli` tests | Survived — key bytes/mtime unchanged; no cache/state |
| `qhs4_timing` | `qwp-bench` | `qhs/qhs4.md` | timing harness | Survived — \|t\| < 4.5 |
| `qhs4_sign_parallel` | `qwp-platform` | `qhs/qhs41.md` | `qwp-platform` tests | Survived — byte-equivalence + timing |
| `qhs4_signing_plan` / `qhs4_leaf` / `qhs4_fors_leaf` / tree builders / `qhs4_sign_with_trees` | `qwp-crypto` | `qhs/qhs41.md` | `qwp-attacks/qhs41` | Survived — equivalence + wrong-plan/tree tests |
| QHS-4.1 CLI `qhs41-*` | `qwp-cli` | `qhs/qhs41.md` | `qwp-cli` tests | Survived — both verifiers; key unchanged; no cache/state |
| `qhs41_timing` | `qwp-bench` | `qhs/qhs41.md` | timing harness | Survived — speedup 7.4×; \|t\| < 4.5 |
| `qhs42_keygen` / `Qhs42PrivateKey::sign` / `Qhs42PublicKey::verify` | `qwp-crypto` | `qhs/qhs42.md` | `qwp-attacks/qhs42` | Survived — KAT + attack + timing |
| `Qhs42PrivateKey` / `Qhs42PublicKey` / `Qhs42Signature` accessors | `qwp-crypto` | `qhs/qhs42.md` | `qwp-attacks/qhs42` | Survived — unit + Kani + fuzz |
| QHS-4.2 WOTS/FORS/hypertree internals | `qwp-crypto` | `qhs/qhs42.md` | `qwp-attacks/qhs42` | Survived — KAT + layer derivation + fuzz |
| `qhs42_sign_parallel` | `qwp-platform` | `qhs/qhs42.md` | `qwp-platform` tests | Survived — byte-equivalence + verify |
| QHS-4.2 CLI `qhs42-*` | `qwp-cli` | `qhs/qhs42.md` | `qwp-cli` tests | Survived — key unchanged; no cache/state |
| `qhs42_timing` | `qwp-bench` | `qhs/qhs42.md` | timing harness | Survived — \|t\| < 4.5 |
| `qhs5_keygen` / `Qhs5PrivateKey::sign` / `Qhs5PublicKey::verify` | `qwp-crypto` | `qhs/qhs5.md` | `qwp-attacks/qhs5` | Survived — KAT + attack + timing |
| `Qhs5PrivateKey` / `Qhs5PublicKey` / `Qhs5Signature` accessors | `qwp-crypto` | `qhs/qhs5.md` | `qwp-attacks/qhs5` | Survived — unit + Kani + fuzz |
| QHS-5 WOTS/Merkle internals and 512-bit hash mode | `qwp-crypto`, `qwp-hash` | `qhs/qhs5.md` | `qwp-attacks/qhs5` | Survived — KAT + digit reconstruction + fuzz |
| `qhs5_leaves_parallel` | `qwp-platform` | `qhs/qhs5.md` | `qwp-platform` tests | Survived — leaf equivalence + verify |
| QHS-5 CLI `qhs5-*`, leaf cache, state guard | `qwp-cli` | `qhs/qhs5.md` | `qwp-cli` tests | Survived — cache/rollback/cross-version tests |
| `qhs5_timing` | `qwp-bench` | `qhs/qhs5.md` | timing harness | Survived — \|t\| < 4.5 |
| `qhs6_keygen` / `Qhs6PrivateKey::sign` / `Qhs6PublicKey::verify` | `qwp-crypto` | `qhs/qhs6.md` | `qwp-attacks/qhs6` | Attacked — RFC/KAT + attack + timing |
| `Ed25519PrivateKey::sign` / `Ed25519PublicKey::verify` / SHA-512 | `qwp-classical` | `qhs/qhs6.md` | RFC 8032 + unit + timing | Attacked — vectors + tamper + timing |
| QHS-6 transcript binding and hybrid parser | `qwp-crypto`, `qwp-cli` | `qhs/qhs6.md` | `qwp-attacks/qhs6`, CLI tests | Attacked — component mixing rejected |
| QHS-6 CLI `qhs6-*`, leaf cache, state guard | `qwp-cli` | `qhs/qhs6.md` | `qwp-cli` tests | Attacked — cache/rollback/cross-version tests |
| `qhs6_timing` | `qwp-bench` | `qhs/qhs6.md` | timing harness | Attacked — \|t\| < 4.5 |

## Status meanings

- **Open** — no FAD/attack harness yet; function may not be implemented.
- **Attacked** — harness exists and has been run.
- **Survived** — attack suite passes; FAD signed.
- **Broken** — a known break exists; gap required.
- **Closed** — FAD complete, signed, and no open gaps.

A missing row is a release blocker.
