# qWp

qWp is a **non-standard, zero-trust, adversarial** topological cryptography project.

It is built under three hard constraints:

1. **100% safe first-party Rust** — every crate uses `#![forbid(unsafe_code)]`.
2. **Zero external crates** — no dependencies; only `core`/`std` from the pinned toolchain.
3. **No hidden gaps** — every function gets an adversary dossier and attack harness; every known gap is tracked until closed.

> **Status: QHS-1/2/3/3.1 release candidates; QHS-4 tagged; QHS-4.1 fast profile implemented; QHS-4.2 compact implemented; QHS-5 512-bit implemented; QHS-6 hybrid implemented; QHS-E verifier profile implemented; zero open production gaps.** Signatures are **QHS-1** (2,408 bytes, 256/key), **QHS-2** (1,704 bytes, 256/key), **QHS-3 / QHS-3.1** (1,832 bytes, 4,096/key), **QHS-4** (18,216 bytes, stateless, 68-byte keys), **QHS-4.1** (same QHS-4 keys/signature, parallel fast signing), **QHS-4.2** (14,344 bytes, compact stateless), **QHS-5** (6,216 bytes, 512-bit hash, 256/key), or **QHS-6** (6,284 bytes, QHS-5 + Ed25519 hybrid, 256/key). QHS-1 passed its 1-hour soak; the combined QHS-1/2/3 1-hour soak passed with 360,181,413 iterations and 0 panics. The QHS-1 72-hour soak was waived by owner decision (2026-11-06). QHS-3.1 uses the same QHS-3 signature format. QHS-4 has no counter, cache, or state guard; its 1-hour soak passed with 91,191,782 iterations and 0 panics. QHS-4.1 uses the same signature and proof; its 1-hour soak passed with 94,814,625 iterations and 0 panics. QHS-4.2 is a compact stateless parameter set; its 1-hour soak passed with 56,556,913 iterations and 0 panics. QHS-5 is a stateful 512-bit-hash profile with a leaf cache and key state guard; its 1-hour soak passed with 48,430,620 iterations and 0 panics. QHS-6 is the QHS-5 + Ed25519 hybrid; its 1-hour soak passed with 36,957,000 iterations and 0 panics. QHS-E is the verifier-only QHS-1/2/3/3.1 profile for bootloaders/MCUs; its 1-hour soak passed with 28,798,916 iterations and 0 panics. The original topological `P·M·P⁻¹` construction is a confirmed break and is retained only as research. See `docs/05-qhs1.md`, `docs/07-qhs2.md`, `docs/10-qhs3.md`, `docs/12-qhs31.md`, `docs/13-qhs4.md`, `docs/14-qhs41.md`, `docs/15-qhs42.md`, `docs/16-qhs5.md`, and `docs/gap-register.md`.

## Workspace

| Crate | Role |
|---|---|
| `qwp-core` | Braid and polynomial types, fixed layouts, errors |
| `qwp-crypto` | Private key, public key, signature wrappers; QHS-1/2/3/3.1/4 |
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
cargo test --workspace --release
cargo run -p qwp-attacks --bin attack-suite
cargo run -p qwp-attacks --bin byte-sweep
cargo run -p qwp-attacks --bin audit
cargo run -p qwp-cli --bin qwp -- selftest
```

Local CI:

```bash
./scripts/ci.sh
```

## Verification tooling

The production workspace stays zero-dependency. Optional verification tools run
in standalone workspaces under `fuzz/` and `tools/`:

```bash
./scripts/tooling.sh          # libFuzzer, proptest, loom, dudect, Creusot, AORAI, asm
cargo kani -p qwp-verify      # Kani proofs
cargo +nightly-2026-08-21 miri test -p qwp-classical --lib
cargo +nightly-2026-08-21 miri test -p qwp-e --lib
```

Evidence is recorded in `docs/evidence/qhse-*.txt`; the full matrix, including
tools that cannot be installed (Ferrocene) or that need a model (AORAI), is in
`docs/19-code-standard-audit.md`.

## QHS CLI

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

cargo run -p qwp-cli --bin qwp -- qhs4-keygen public4.key private4.key
cargo run -p qwp-cli --bin qwp -- qhs4-sign private4.key message.txt message4.sig
cargo run -p qwp-cli --bin qwp -- qhs4-verify public4.key message.txt message4.sig

cargo run -p qwp-cli --bin qwp -- qhs41-keygen public41.key private41.key
cargo run -p qwp-cli --bin qwp -- qhs41-sign private41.key message.txt message41.sig
cargo run -p qwp-cli --bin qwp -- qhs41-verify public41.key message.txt message41.sig

cargo run -p qwp-cli --bin qwp -- qhs42-keygen public42.key private42.key
cargo run -p qwp-cli --bin qwp -- qhs42-sign private42.key message.txt message42.sig
cargo run -p qwp-cli --bin qwp -- qhs42-verify public42.key message.txt message42.sig

cargo run -p qwp-cli --bin qwp -- qhs5-keygen public5.key private5.key
cargo run -p qwp-cli --bin qwp -- qhs5-sign private5.key message.txt message5.sig
cargo run -p qwp-cli --bin qwp -- qhs5-verify public5.key message.txt message5.sig

cargo run -p qwp-cli --bin qwp -- qhs6-keygen public6.key private6.key
cargo run -p qwp-cli --bin qwp -- qhs6-sign private6.key message.txt message6.sig
cargo run -p qwp-cli --bin qwp -- qhs6-verify public6.key message.txt message6.sig

cargo run -p qwp-cli --bin qwp -- qhse-verify 1 public1.key message.txt message1.sig
```

The QHS-1/2/3/3.1 private key is stateful: each signature consumes one leaf and the CLI atomically updates the key counter with `fsync` + rename before writing the signature. The private key file is created with mode `0600` on Unix. Do not copy, roll back, or use the same key concurrently from multiple processes.

QHS-4, QHS-4.1, and QHS-4.2 are the stateless exception: `qhs4-sign`, `qhs41-sign`, and `qhs42-sign` read the key and write only the signature. They create no cache, tree cache, or state guard, and do not modify the private key. The key file is still protected by mode `0600`.

QHS-6 is the hybrid. `qhs6-keygen` writes 108-byte keys and a QHS-6 leaf cache/state guard; `qhs6-sign` signs a transcript with both QHS-5 and Ed25519, and `qhs6-verify` requires both.

QHS-E is verifier-only. `qhse-verify <version> <public-key> <message> <signature>` verifies QHS-1/2/3/3.1 with the embedded profile; it has no keygen, signing, cache, or state files.

QHS-5 is stateful. `qhs5-keygen` writes a 16,452-byte public-leaf cache and a 38-byte keyed state guard. `qhs5-sign` persists the incremented key counter and state guard before releasing the signature; a guard counter ahead of the key counter is refused as a rollback. Restoring both the key and guard together is not detectable without a hardware monotonic counter.

`qhs-keygen` and `qhs2-keygen` write an 8,260-byte cache (mode `0600`); `qhs3-keygen` writes a 131,140-byte leaf cache; `qhs31-keygen` writes a 262,180-byte tree cache. The cache contains only public Merkle data, bound to the key by a versioned fingerprint and keyed MAC. If the cache is missing, corrupt, from another key, or from another QHS version, the CLI recomputes it.

Each QHS-1/2/3/3.1 key also gets a keyed `<private-key>.state` guard (38 bytes, mode `0600`). If the guard counter is ahead of the key counter, `qhs-sign` refuses to sign and reports a rollback. This catches accidental restoration of an old key backup; it is not a hardware monotonic counter. QHS-4, QHS-4.1, and QHS-4.2 have no state guard. QHS-5 has its own 64-byte-seed state guard and leaf cache. QHS-6 inherits the QHS-5 cache/state and adds an Ed25519 seed.

On the 16-thread reference host:

| Variant | Signature | Keygen | Sign | Verify |
|---|---:|---:|---:|---:|
| QHS-1 | 2,408 B | ≈10–13 ms | ≈0.21–0.33 ms | ≈0.14 ms |
| QHS-2 | 1,704 B | ≈27–28 ms | ≈0.46–0.61 ms | ≈0.41 ms |
| QHS-3 | 1,832 B | ≈0.40–0.44 s | ≈1.60–1.70 ms | ≈0.39 ms |
| QHS-3.1 | 1,832 B | ≈0.40–0.41 s | **≈0.35–0.36 ms** | ≈0.39 ms |
| QHS-4 | 18,216 B | ≈0.10 s | sequential ≈0.81 s | ≈1.6 ms |
| QHS-4.1 | 18,216 B | ≈0.10 s | **parallel ≈0.11 s** | ≈1.6 ms |
| QHS-4.2 | **14,344 B** | ≈0.30 s | parallel ≈0.27 s | ≈4.0 ms |
| QHS-5 | **6,216 B** | ≈0.09 s parallel | **≈1.5 ms cached** | ≈1.2 ms |
| QHS-6 | **6,284 B** | ≈0.09 s parallel | ≈2.0 ms cached | ≈1.5 ms |
| QHS-E | same as base | n/a | n/a | **0.14–0.39 ms** |

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
- `docs/13-qhs4.md` — QHS-4 stateless hypertree/FORS construction and proof
- `docs/14-qhs41.md` — QHS-4.1 parallel fast-signing profile
- `docs/15-qhs42.md` — QHS-4.2 compact stateless construction and proof
- `docs/16-qhs5.md` — QHS-5 512-bit stateful construction and proof
- `docs/17-qhs6.md` — QHS-6 QHS-5 + Ed25519 hybrid construction and proof
- `docs/18-qhse.md` — QHS-E embedded verifier profile and evidence
- `docs/09-version-family.md` — QHS version family and use-case matrix
- `docs/adr/0002-qhs1.md` — QHS-1 acceptance
- `docs/adr/0003-qhs2.md` — QHS-2 smaller-signature acceptance
- `docs/adr/0004-qhs3.md` — QHS-3 high-capacity acceptance
- `docs/adr/0005-qhs31-tree-cache.md` — QHS-3.1 tree-cache profile
- `docs/adr/0006-qhs4-stateless.md` — QHS-4 stateless hypertree/FORS acceptance
- `docs/adr/0007-qhs41-fast.md` — QHS-4.1 parallel fast-signing profile
- `docs/adr/0008-qhs42-compact.md` — QHS-4.2 compact stateless profile
- `docs/adr/0009-qhs5-512.md` — QHS-5 512-bit stateful profile
- `docs/adr/0010-qhs6-hybrid.md` — QHS-6 classical hybrid
- `docs/adr/0011-qhse-embedded.md` — QHS-E embedded verifier profile
- `docs/adr/0001-signature-paradigm.md` — superseded signature paradigm decision
- `docs/gap-register.md` — every open gap
- `docs/traceability.md` — requirement traceability
- `docs/break-log.md` — attack attempts and results
- `docs/attack-trees.md` — per-asset attack trees
- `docs/adversary/` — one Function Adversary Dossier per function
- `PLAN.md` — full engineering and security plan
- `STATUS.md` — current implementation and verification status

## Warning

This project is not standard and not externally audited. QHS-1, QHS-2, QHS-3, QHS-3.1, QHS-4, QHS-4.1, QHS-4.2, QHS-5, QHS-6, and QHS-E are closed with internal proofs and evidence, and the production gap register is empty. The combined QHS-1/2/3/3.1 1-hour soak passed with 360,181,413 iterations and 0 panics; the QHS-4 1-hour soak passed with 91,191,782 iterations and 0 panics; the QHS-4.1 1-hour soak passed with 94,814,625 iterations and 0 panics; the QHS-4.2 1-hour soak passed with 56,556,913 iterations and 0 panics. The QHS-5 1-hour soak passed with 48,430,620 iterations and 0 panics; the QHS-6 1-hour soak passed with 36,957,000 iterations and 0 panics. The QHS-E 1-hour soak passed with 28,798,916 iterations and 0 panics. The 72-hour soak was waived by owner decision for QHS-1. Do not use qWp for real security without an independent review of your deployment.
