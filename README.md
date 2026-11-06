# qWp

qWp is a **non-standard, zero-trust, adversarial** topological cryptography project.

It is built under three hard constraints:

1. **100% safe first-party Rust** — every crate uses `#![forbid(unsafe_code)]`.
2. **Zero external crates** — no dependencies; only `core`/`std` from the pinned toolchain.
3. **No hidden gaps** — every function gets an adversary dossier and attack harness; every known gap is tracked until closed.

> **Status: foundation slice.** The core types, fixed layouts, in-tree BLAKE3, safe Unix entropy, attack harnesses, and CLI selftest are in place. The custom signature is **not implemented** and the original `P·M·P⁻¹` construction is a confirmed break. See `docs/gap-register.md` and `docs/break-log.md`.

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

## Doctrine and registers

- `docs/qwp-standard.md` — qWp Standard v1
- `docs/01-math-spec.md` — invariant, bounds, TL solver, signature analysis
- `docs/03-formats.md` — fixed layouts and signature container
- `docs/security-memo.md` — Phase 0 soundness findings
- `docs/adr/0001-signature-paradigm.md` — signature paradigm decision
- `docs/gap-register.md` — every open gap
- `docs/traceability.md` — requirement traceability
- `docs/break-log.md` — attack attempts and results
- `docs/attack-trees.md` — per-asset attack trees
- `docs/adversary/` — one Function Adversary Dossier per function
- `PLAN.md` — full engineering and security plan
- `STATUS.md` — current implementation and verification status

## Warning

This project is not standard, not audited, and not production-ready. The critical signature construction is still open. Do not use qWp for real security until the gap register is empty and the internal red team has signed off.
