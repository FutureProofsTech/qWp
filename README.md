# qWp

qWp is a **non-standard, zero-trust, adversarial** topological cryptography project.

It is built under three hard constraints:

1. **100% safe first-party Rust** — every crate uses `#![forbid(unsafe_code)]`.
2. **Zero external crates** — no dependencies; only `core`/`std` from the pinned toolchain.
3. **No hidden gaps** — every function gets an adversary dossier and attack harness; every known gap is tracked until closed.

> **Status: QHS-1 production candidate; zero open production gaps.** The core types, fixed layouts, in-tree BLAKE3, safe Unix entropy, attack harnesses, CLI, proof, and verification evidence are in place. Production signatures use **QHS-1** (WOTS + Merkle, 2408-byte signature, 64-byte keys). 1-hour pre-soak passed; release gate: 72-hour fuzz soak. The original topological `P·M·P⁻¹` construction is a confirmed break and is retained only as research. See `docs/05-qhs1.md`, `docs/06-qhs1-review.md`, `docs/gap-register.md`, and `docs/break-log.md`.

## Workspace

| Crate | Role |
|---|---|
| `qwp-core` | Braid and polynomial types, fixed layouts, errors |
| `qwp-crypto` | Private key, public key, signature wrappers |
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
```

The private key is stateful: each signature consumes one leaf and the CLI atomically updates the key counter with `fsync` + rename before writing the signature. The private key file is created with mode `0600` on Unix. Do not copy, roll back, or use the same key concurrently from multiple processes.

`qhs-keygen` also writes `<private-key>.cache` (8,232 bytes, mode `0600`): the 256 public Merkle leaves, bound to the key by a fingerprint and checksum. It contains no secret WOTS values. If the cache is missing, corrupt, or from another key, the CLI recomputes the leaves. On the 16-thread reference host, keygen takes ≈10–13 ms, cached signing ≈0.21–0.33 ms, and verification ≈0.14 ms; keys and signature bytes are unchanged by the cache.

## Doctrine and registers

- `docs/qwp-standard.md` — qWp Standard v1
- `docs/01-math-spec.md` — invariant, bounds, TL solver, signature analysis
- `docs/03-formats.md` — fixed layouts and signature container
- `docs/security-memo.md` — Phase 0 soundness findings
- `docs/05-qhs1.md` — QHS-1 construction and security proof
- `docs/06-qhs1-review.md` — internal proof review and remaining obligations
- `docs/adr/0002-qhs1.md` — QHS-1 acceptance
- `docs/adr/0001-signature-paradigm.md` — superseded signature paradigm decision
- `docs/gap-register.md` — every open gap
- `docs/traceability.md` — requirement traceability
- `docs/break-log.md` — attack attempts and results
- `docs/attack-trees.md` — per-asset attack trees
- `docs/adversary/` — one Function Adversary Dossier per function
- `PLAN.md` — full engineering and security plan
- `STATUS.md` — current implementation and verification status

## Warning

This project is not standard and not externally audited. The QHS-1 construction is closed with an internal proof and evidence, and the production gap register is empty. It remains a release candidate until the 72-hour soak passes. Do not use qWp for real security before that gate and an independent review of your deployment.
