# qWp

qWp is a **non-standard, zero-trust, adversarial** topological cryptography project.

It is built under three hard constraints:

1. **100% safe first-party Rust** — every crate uses `#![forbid(unsafe_code)]`.
2. **Zero external crates** — no dependencies; only `core`/`std` from the pinned toolchain.
3. **No hidden gaps** — every function gets an adversary dossier and attack harness; every known gap is tracked until closed.

> **Status: QHS-1/2/3/3.1 release candidates; zero open production gaps.** Signatures are **QHS-1** (2,408 bytes, 256/key), **QHS-2** (1,704 bytes, 256/key), or **QHS-3 / QHS-3.1** (1,832 bytes, 4,096/key), all with 64-byte keys. QHS-1 passed its 1-hour soak; the combined QHS-1/2/3 1-hour soak passed with 360,181,413 iterations and 0 panics. The QHS-1 72-hour soak was waived by owner decision (2026-11-06). QHS-3.1 uses the same QHS-3 signature format. The original topological `P·M·P⁻¹` construction is a confirmed break and is retained only as research. See `docs/05-qhs1.md`, `docs/07-qhs2.md`, `docs/10-qhs3.md`, `docs/12-qhs31.md`, and `docs/gap-register.md`.

## Workspace

| Crate | Role |
|---|---|
| `qwp-core` | Braid and polynomial types, fixed layouts, errors |
| `qwp-crypto` | Private key, public key, signature wrappers; QHS-1/2/3/3.1 |
| `qwp-hash` | In-tree BLAKE3 |
| `qwp-platform` | Safe Unix entropy adapter |
| `qwp-cli` | `qwp` command-line interface |
| `qwp-attacks` | Attacker-side harnesses and audit |
| `qwp-bench` | In-house benchmark harness |
| `qwp-tests` | Integration and KAT tests |
| `qwp-verify` | Kani proof harnesses |

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p qwp-attacks --bin attack-suite
cargo run -p qwp-attacks --bin audit
cargo run -p qwp-cli --bin qwp -- selftest
```

Local CI:

```bash
./scripts/ci.sh
```

## QHS-1 CLI

```bash
cargo run -p qwp-cli --bin qwp -- qhs-keygen public.key private.key
cargo run -p qwp-cli --bin qwp -- qhs-sign private.key message.txt message.sig
cargo run -p qwp-cli --bin qwp -- qhs-verify public.key message.txt message.sig

cargo run -p qwp-cli --bin qwp -- qhs2-keygen public2.key private2.key
cargo run -p qwp-cli --bin qwp -- qhs2-sign private2.key message.txt message2.sig
cargo run -p qwp-cli --bin qwp -- qhs2-verify public2.key message.txt message2.sig

cargo run -p qwp-cli --bin qwp -- qhs3-keygen public3.key private3.key
cargo run -p qwp-cli --bin qwp -- qhs3-sign private3.key message.txt message3.sig
cargo run -p qwp-cli --bin qwp -- qhs3-verify public3.key message.txt message3.sig

cargo run -p qwp-cli --bin qwp -- qhs31-keygen public31.key private31.key
cargo run -p qwp-cli --bin qwp -- qhs31-sign private31.key message.txt message31.sig
cargo run -p qwp-cli --bin qwp -- qhs31-verify public31.key message.txt message31.sig
```

The private key is stateful: each signature consumes one leaf and the CLI atomically updates the key counter with `fsync` + rename before writing the signature. The private key file is created with mode `0600` on Unix. Do not copy, roll back, or use the same key concurrently from multiple processes.

`qhs-keygen` and `qhs2-keygen` write an 8,260-byte cache (mode `0600`); `qhs3-keygen` writes a 131,140-byte leaf cache; `qhs31-keygen` writes a 262,180-byte tree cache. The cache contains only public Merkle data, bound to the key by a versioned fingerprint and keyed MAC. If the cache is missing, corrupt, from another key, or from another QHS version, the CLI recomputes it.

Each key also gets a keyed `<private-key>.state` guard (38 bytes, mode `0600`). If the guard counter is ahead of the key counter, `qhs-sign` refuses to sign and reports a rollback. This catches accidental restoration of an old key backup; it is not a hardware monotonic counter.

On the 16-thread reference host:

| Variant | Signature | Keygen | Cached sign | Verify |
|---|---:|---:|---:|---:|
| QHS-1 | 2,408 B | ≈10–13 ms | ≈0.21–0.33 ms | ≈0.14 ms |
| QHS-2 | 1,704 B | ≈27–28 ms | ≈0.46–0.61 ms | ≈0.41 ms |
| QHS-3 | 1,832 B | ≈0.40–0.44 s | ≈1.60–1.70 ms | ≈0.39 ms |
| QHS-3.1 | 1,832 B | ≈0.40–0.41 s | **≈0.35–0.36 ms** | ≈0.39 ms |

## Doctrine and registers

- `docs/qwp-standard.md` — qWp Standard v1
- `docs/01-math-spec.md` — invariant, bounds, TL solver, signature analysis
- `docs/03-formats.md` — fixed layouts and signature container
- `docs/security-memo.md` — Phase 0 soundness findings
- `docs/05-qhs1.md` — QHS-1 construction and security proof
- `docs/06-qhs1-review.md` — QHS-1 internal proof review and evidence
- `docs/07-qhs2.md` — QHS-2 smaller-signature construction and proof
- `docs/08-qhs2-review.md` — QHS-2 internal proof review and evidence
- `docs/10-qhs3.md` — QHS-3 high-capacity construction and proof
- `docs/11-qhs3-review.md` — QHS-3 internal proof review and evidence
- `docs/12-qhs31.md` — QHS-3.1 tree-cache signing profile
- `docs/09-version-family.md` — QHS version family and use-case matrix
- `docs/adr/0002-qhs1.md` — QHS-1 acceptance
- `docs/adr/0003-qhs2.md` — QHS-2 smaller-signature acceptance
- `docs/adr/0004-qhs3.md` — QHS-3 high-capacity acceptance
- `docs/adr/0005-qhs31-tree-cache.md` — QHS-3.1 tree-cache profile
- `docs/adr/0001-signature-paradigm.md` — superseded signature paradigm decision
- `docs/gap-register.md` — every open gap
- `docs/traceability.md` — requirement traceability
- `docs/break-log.md` — attack attempts and results
- `docs/attack-trees.md` — per-asset attack trees
- `docs/adversary/` — one Function Adversary Dossier per function
- `PLAN.md` — full engineering and security plan
- `STATUS.md` — current implementation and verification status

## Warning

This project is not standard and not externally audited. QHS-1, QHS-2, QHS-3, and QHS-3.1 are closed with internal proofs and evidence, and the production gap register is empty. The combined 1-hour fuzz soak passed with 360,181,413 iterations and 0 panics. The 72-hour soak was waived by owner decision for QHS-1. Do not use qWp for real security without an independent review of your deployment.
