# qWp Code-Standard Audit

**Date:** 2026-11-10

**Scope:** production crypto core, verifier profile, host tooling, evidence
helpers, and the requested tooling matrix.

**Rule:** This audit does not claim compliance by assertion. Each row states the
actual evidence or the gap.

---

## 1. Crate classification

| Crate | Class | `no_std` | `forbid(unsafe_code)` |
|---|---|---:|---:|
| `qwp-core` | production crypto core | Yes | Yes |
| `qwp-hash` | production crypto core | Yes | Yes |
| `qwp-classical` | production crypto core | Yes | Yes |
| `qwp-crypto` | production crypto core | Yes | Yes |
| `qwp-e` | production verifier profile | Yes | Yes |
| `qwp-platform` | host adapter | No (std threads/fs) | Yes |
| `qwp-cli` | host CLI | No (std fs/io) | Yes |
| `qwp-attacks` | host attack harness | No (std) | Yes |
| `qwp-bench` | host benchmark/timing | No (std/time) | Yes |
| `qwp-tests` | host test/fuzz harness | No (std) | Yes |
| `qwp-verify` | Kani proof harness | Yes | Yes |
| `qwp-e-size` | evidence-only staticlib | Yes | Yes |

`no_std` is a property of the production crypto core. Host tools cannot be
`no_std` because they use OS entropy, files, threads, and the test harness.

## 2. Lint matrix

All production crypto crates deny the requested Level 1–5 set. The four
general-purpose crypto crates also deny `arithmetic_side_effects`; `qwp-classical`
does not, because its field and scalar algorithms are defined by explicit
fixed-width `wrapping_*` arithmetic. That lint is an extra hardening choice, not
one of the requested Level 1–5 lints.

- `clippy::all`, `pedantic`, `nursery`, `cargo`
- `alloc_instead_of_core`, `std_instead_of_core`, `std_instead_of_alloc`
- `unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `todo`,
  `unimplemented`, `unreachable`
- `as_conversions`, `cast_lossless`, `cast_possible_truncation`,
  `cast_possible_wrap`, `float_arithmetic`
- `indexing_slicing` (all production crates)
- `missing_inline_in_public_items`, `exhaustive_structs`,
  `exhaustive_enums`
- `arithmetic_side_effects` (qwp-core, qwp-hash, qwp-crypto, qwp-e),
  `panic_in_result_fn`, `unwrap_in_result`
- `allow_attributes_without_reason`, `dbg_macro`, `exit`, `mem_forget`
- `print_stdout`, `print_stderr`, `let_underscore_must_use`
- `missing_debug_implementations`, `missing_docs`, `rustdoc::all`
- `unreachable_pub`, `unused_results`, `let_underscore_drop`
- `non_ascii_idents`, `rust_2018_idioms`, `future_incompatible`
- `trivial_casts`, `trivial_numeric_casts`, `unused_qualifications`
- `unused_lifetimes`, `single_use_lifetimes`, `elided_lifetimes_in_paths`

Results:

| Crate | Security-lint status | Documented exceptions |
|---|---|---|
| `qwp-core` | PASS | cargo metadata only |
| `qwp-hash` | PASS | cargo metadata only |
| `qwp-crypto` | PASS | cargo metadata only |
| `qwp-classical` | PASS | `many_single_char_names`, `unreadable_literal`, `redundant_pub_crate`, cargo metadata — style/documentation only; indexing/cast lints are denied |
| `qwp-e` | PASS | cargo metadata only |
| `qwp-platform` | PASS for host profile | `std_instead_of_core` not denied because std is the host adapter; `print_*`/thread/fs allows with reasons |
| `qwp-cli` | PASS for host profile | std/print/fs allows with reasons; binary has no `missing_inline`/`rustdoc::all` |
| `qwp-attacks` | PASS for host profile | std/print allows with reasons |
| `qwp-bench` | PARTIAL | reduced lint set for a benchmark/timing binary |
| `qwp-tests` | PARTIAL | test/fuzz harness only; `forbid(unsafe_code)` |
| `qwp-verify` | PARTIAL | Kani harness; `unexpected_cfgs` allow |
| `qwp-e-size` | PARTIAL | evidence-only staticlib; `no_std`/`forbid` only |

### Security-lint fixes applied during this audit

- `qwp-e`: removed the `indexing_slicing` and `arithmetic_side_effects`
  exceptions, added the full cast/index/arithmetic deny set, and replaced the
  remaining slice with `.get(..)`.
- `qwp-classical`: removed the `indexing_slicing`, `as_conversions`, cast, and
  `needless_range_loop` exceptions and added explicit denies. Bounded
  `u128`→`u64` casts were replaced by `util::low_u64`; fixed-limb loops were
  rewritten as iterator zips. `arithmetic_side_effects` remains a documented
  exception because the field/scalar code is explicitly wrapping.

### qwp-classical remaining exceptions

The classical crate denies `indexing_slicing`, `as_conversions`, and all cast
lints. It does not enable `arithmetic_side_effects`; fixed-width wrapping is the
algorithm and every operation uses an explicit `wrapping_*` method. Its only
allows are:

- conventional SHA-512/Edwards single-letter names;
- grouped 51-bit limb literals;
- explicit `pub(crate)` in internal modules;
- cargo metadata.

These are style/documentation choices, not unchecked arithmetic or indexing.

### Host tooling

Host tools intentionally use `std`, print to the terminal, and use test
assertions. They still use `forbid(unsafe_code)` and most of the strict clippy
set. `qwp-bench`, `qwp-tests`, `qwp-verify`, and `qwp-e-size` use a reduced lint
set because they are not production crypto code.

## 3. Tooling matrix

Tooling-only workspaces are under `fuzz/` and `tools/`; they are standalone
Cargo workspaces and do not add dependencies to the production workspace.

| Requested tool | Status | Actual evidence |
|---|---|---|
| Kani | **Used** | 24/24 parser/bounds proofs; not a full functional-correctness proof |
| Creusot | **Used** | 7/7 contracts proved on the QHS-E digit/checksum/Merkle model; `docs/evidence/qhse-creusot.txt` |
| AORAI | **Used** | Frama-C 33 AORAI + WP on the QHS-E order model: 1050/1051 goals, 1 tool-generated typing timeout; `docs/evidence/qhse-aorai.txt` |
| cargo-fuzz / libFuzzer | **Used** | 17,961,180 QHS-E runs / 61 s; 29,378,990 parser runs / 46 s; 28,951,672 QHS-6 parser runs / 46 s; 0 crashes; `docs/evidence/qhse-libfuzzer.txt` |
| Proptest | **Used** | 5 properties × 64 cases, plus 4 regression tests; `docs/evidence/qhse-proptest.txt` |
| cargo-tarpaulin | **Used** | Package/workspace run; line-count differs from llvm-cov because tarpaulin only instruments the selected package tests; `docs/evidence/qhse-tarpaulin.txt` |
| Loom | **Used** | Chunk/join model passed; `docs/evidence/qhse-loom.txt` |
| dudect-bencher | **Used** | Valid-path max \|t\| ≤ 1.07; positive control +25,747; `docs/evidence/qhse-dudect.txt` |
| cargo-show-asm | **Used** | Verifier assembly inspected; no secret-dependent indirect dispatch; `docs/evidence/qhse-asm.txt` |
| Speculative-execution fences | **Not injected — documented** | Pure safe Rust; verification is public; no secret-dependent memory access. LFENCE is x86-specific and not a general Spectre fix. Assembly reviewed with `cargo-show-asm`. |
| Ferrocene | **GAP** | Customer-portal-only toolchain; no public download. Stable rustc 1.99 used. |
| Miri | **Used** | `cargo +nightly-2026-08-21 miri test` on `qwp-classical` and `qwp-e`; see result below |

### Installed tooling

| Tool | Version / source |
|---|---|
| Kani | 0.68.0 (CBMC 6.11.0) |
| cargo-fuzz | 0.13.2 |
| cargo-tarpaulin | 0.37.6 |
| cargo-show-asm | 0.2.64 |
| Miri | nightly-2026-08-21 component |
| Frama-C / AORAI | 33.0 (Arsenic), system package |
| Alt-Ergo | 2.4.3, system package |
| Z3 | 4.16.0, system package |
| Why3 | 1.8.2 system; Creusot uses its pinned opam switch |
| Creusot | 0.15.0-dev, built from source with opam/Why3 |
| opam | 2.6.1, system package |

## 4. Cargo profile

`Cargo.toml` release profile:

```toml
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
overflow-checks = true
debug-assertions = false
incremental = false
```

This matches the requested matrix; `lto = "fat"` is the explicit form of
`lto = true`, and `strip = "symbols"` is equivalent to `strip = true` when
debug info is disabled. The dev profile keeps `overflow-checks` and
`debug-assertions` for tests.

## 5. Evidence commands

Core checks:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --release
cargo kani -p qwp-verify
cargo llvm-cov --release -p qwp-e --summary-only
cargo llvm-cov --release -p qwp-classical --summary-only
cargo llvm-cov --release -p qwp-crypto --lib --summary-only
./scripts/qhse-size.sh
cargo run -q -p qwp-bench --release --bin qhse_timing
cargo run -q -p qwp-tests --release --bin fuzz -- 60
```

Tooling checks:

```text
cargo +nightly-2026-08-21 fuzz run qhse_verify -- -max_total_time=60
cargo +nightly-2026-08-21 fuzz run qhs_parse -- -max_total_time=45
cargo +nightly-2026-08-21 fuzz run qhs6_parse -- -max_total_time=45
(cd tools/proptest-suite && cargo test --release)
(cd tools/loom-model && LOOM_MAX_PREEMPTIONS=2 cargo test --release)
(cd tools/dudect-suite && cargo build --release --bin qhse_dudect && taskset -c 1 ./target/release/qhse_dudect)
(cd tools/creusot-proofs && cargo creusot config --update && cargo creusot)
(cd tools/aorai-model && frama-c qhse_state.c -aorai-automata qhse_state.ya -then-last -wp -wp-rte -wp-timeout 60 -wp-prover alt-ergo,z3)
cargo asm -p qwp-e --lib --release verify_common
cargo tarpaulin --release -p qwp-e --out Xml
cargo run --release -p qwp-attacks --bin attack-suite
cargo run --release -p qwp-attacks --bin byte-sweep
./scripts/soak-72h.sh
cargo +nightly-2026-08-21 miri test -p qwp-classical --lib
cargo +nightly-2026-08-21 miri test -p qwp-e --lib
```

Latest results:

- 304 release tests, 0 failures.
- Clippy workspace clean with `-D warnings`.
- Kani 24/24.
- QHS-E coverage 98.50% lines, 100% functions.
- qwp-classical coverage 99.67% lines, 100% functions.
- qwp-crypto coverage 99.27% lines.
- No external crates in the production dependency graph.
- No `unsafe` code in first-party source.
- QHS-E code size: 12,771 B (thumbv7em) / 14,247 B (riscv32imac).
- QHS-E peak stack frame: ≈6.0 KB (BLAKE3 hasher); `verify_common` ≈256 B.
- 72-hour all-version soak runner is prepared: `scripts/soak-72h.sh` and
  `docs/evidence/soak-72h-plan.md`. It has not been run yet.
- libFuzzer: 17,961,180 QHS-E runs / 61 s; 29,378,990 + 28,951,672
  parser runs / 46 s each; 0 crashes.
- Proptest: 5 properties × 64 cases + 4 regressions.
- Loom: chunk/join model passed.
- dudect: valid paths max |t| ≤ 1.07; positive control +25,747.
- AORAI: 1050/1051 goals; 1 generated typing timeout.
- Miri: qwp-classical 30/30; qwp-e 1/1.
- Tarpaulin: QHS-E 45/47 lines; qwp-classical package-only run 223/502
  (tarpaulin instruments only the package test binary).
- Extended attacks: 20/20; full bit sweep 0 accepted; BL-0031/0032/0033 fixed.
- Mutation: QHS-E 47/46/0/1 equivalent; qwp-classical field 253/229/15/9
  equivalent; scalar 48/40/5/3 equivalent; qwp-crypto qhs 114/110/2/2,
  qhs2 119/113/3/3, qhs3 165/131/7/27, qhs6 66/34/0/32; all missed mutants
  are documented equivalents; evidence in `docs/evidence/classical-mutation-final.txt`
  and `docs/evidence/crypto-mutation-final.txt`.

## 6. Gaps and decisions

1. **100% path execution** is not met. The measured crates are 98.50–99.67%
   line coverage; the remaining lines are defensive fixed-layout branches.
   Raising this to 100% would require tests for unreachable defensive paths.
   cargo-tarpaulin also reports lower line counts than llvm-cov because it
   instruments only the selected package's tests; llvm-cov remains the
   authoritative coverage number.
2. **Ferrocene** cannot be installed: it is distributed through the Ferrocene
   customer portal, not a public toolchain or crates.io. The project builds with
   stable rustc 1.99. This is an open gap for ISO 26262 / IEC 61508 claims.
3. **Creusot** is built from source with opam/Why3 and proves the QHS-E
   digit/checksum/Merkle arithmetic model (7/7). A full Creusot proof of the
   BLAKE3-based verifier is not tractable without modeling the hash function.
4. **AORAI** is a C tool. It was used on an illustrative C model of the QHS-E
   verification order; it cannot analyze the Rust implementation directly.
5. **Speculative-execution fences** are not injected. LFENCE is x86-specific
   and is not a general Spectre mitigation. The verifier operates on public
   data and has no secret-dependent memory access; the assembly was reviewed
   with `cargo-show-asm`. This is a documented decision, not a claim that
   LFENCE was applied.
6. **Host tooling is not `no_std`.** This is intentional; the production crypto
   core and QHS-E are `no_std`.
7. **QHS-E 1-hour soak** passed with 28,798,916 iterations and 0 panics; tagged `qhse-rc1`.

No claim is made that the project is fully compliant with every tool in the
requested matrix. The production crypto core meets the requested security lint
set; the remaining gaps are Ferrocene, 100% coverage, and the QHS-E soak.

## 7. Gaps found by the extended attack suite

The extended suite (20 attack groups, full bit sweep, structural tampering with
repaired checksums) found and closed:

1. **QHS-1/2/3 public-key reserved tail was not validated.** Bytes 36..64 are
   documented as zero, but non-zero tails parsed and verified. Multiple
   encodings of one key were possible. Fixed in all three parsers and in QHS-E;
   public-key mutation and differential tests cover it. `BL-0031`.
2. **QHS-E ignored the same public-key tail.** Fixed with the same zero check;
   `qhse_rejects_nonzero_public_key_tail` compares against `qwp-crypto`.
3. **CLI state guard corruption/missing silently reset rollback protection.**
   A corrupt guard and a missing guard for an advanced key now fail closed;
   only counter 0 may recreate a guard. `BL-0032`.
4. **QHS-6 parser accepted a non-QHS-5 embedded header.** `from_parts` and
   `from_slice` now require `[6,6]`. `BL-0033`.

Residual limitations:

- Deleting the guard and rolling the key counter back to 0 is indistinguishable
  from a fresh key without external trusted state. This is documented, not
  claimed solved.
- QHS-E's peak verifier frame is ≈6.0 KB because of the BLAKE3 hasher. It is
  fixed-size and allocation-free, but small MCUs must budget for it; it is not
  an 8 KB-device profile. See `docs/evidence/qhse-stack.txt`.
- Single-byte mutation and structural transplant attacks are rejected for every
  signature format; no forgery was found.
- Full bit sweep covers all signature bytes. It does not cover every possible
  multi-byte combination; structural transplants and proptest/libFuzzer cover
  representative combinations.
