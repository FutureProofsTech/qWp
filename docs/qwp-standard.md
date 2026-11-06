# qWp Standard v1

**Status:** Adopted  
**Scope:** All qWp code, documentation, tests, and releases  
**Authority:** This document and the gap register. No external standard is authoritative.

---

## 1. Doctrine

qWp is **non-standard, zero-trust, adversarial, and gap-free**.

- We do not claim NIST/ISO/FIPS/RFC compliance.
- We do not use a standardized scheme as a trust anchor or fallback.
- We do not trust external crates, external auditors, or tool output as authority.
- We do trust mathematical proofs, the pinned Rust toolchain, and reproducible in-repo evidence.
- Every function is engineered and attacked by the same team.
- Every function has a Function Adversary Dossier (FAD) and an attack harness.
- Every known gap is tracked, owned, and closed before release.
- There is no standard fallback. If the custom construction fails, qWp stops or remains research.

## 2. Hard constraints

1. **100% safe first-party Rust** — every crate, binary, test, bench, example, build script, and fuzz harness uses `#![forbid(unsafe_code)]`.
2. **Zero external crates** — no `[dependencies]`, `[dev-dependencies]`, or `[build-dependencies]`; only `core`/`std` from the pinned toolchain.
3. **No external trust anchor** — no standard scheme, no external auditor as gate, no tool as oracle.
4. **No gaps** — zero open gaps at release; every requirement traced; every function attacked.
5. **Attack-driven development** — write the abuse case and attack harness before or with the implementation.
6. **No standard fallback** — if the custom scheme cannot be made sound, stop or remain research.

## 3. Trust model

| Thing | Trusted? | Why |
|---|---|---|
| Mathematical proofs | Yes, as evidence | Reproducible and checkable |
| Pinned Rust toolchain | Yes, as a tool | Version/checksum pinned; not a security proof |
| `core`/`std` | Yes, as toolchain code | Host-only `std`; core is `no_std` |
| External crates | No | Zero-dependency policy |
| External standards | No | Non-standard by design |
| External auditors | No, not as a gate | Optional evidence only |
| Kani/Miri/fuzzers | No, not as authority | Results must be reproducible |
| Benchmarks | No | Measurements, not proofs |
| Marketing claims | No | Only measured/proven claims allowed |

## 4. Decision register (closed)

| ID | Decision | Default |
|---|---|---|
| D1 | Project path | QHS-1 production signature; braid/Jones engine research-only |
| D2 | Code policy | Zero external crates; 100% safe first-party Rust; `no_std` core |
| D3 | Platform scope | Unix host first; Windows/embedded/WASM out of scope unless a safe in-tree HAL/binding is added |
| D4 | Hash component | In-tree BLAKE3 as a specified component, not a standard authority |
| D5 | Standard fallback | None; QHS-1 is qWp-defined |
| D6 | External review | Optional evidence, never a gate |
| D7 | Security target | Measured attack cost: ≥2^128 classical and ≥2^64 quantum design goal |
| D8 | Object sizes | QHS-1: 64-byte private key, 64-byte public key, 2408-byte signature; legacy research container 40/516/160 |
| D9 | Gap process | Gap register + traceability + zero-open-gap release gate |
| D10 | Development method | Attack-driven development + FAD per function |
| D11 | Test counts | 100,000 keygen and 50,000 timing runs are minimums |
| D12 | Certification | No ISO/FIPS/Ferrocene compliance claim |
| D13 | Zeroization | Best-effort only; documented limitation |
| D14 | Tooling | External tool binaries allowed; no external Rust crates |
| D15 | BLAKE3 replacement | Only by a written ADR + gap entry + full design/attack plan |
| D16 | Message binding | QHS-1 hashes the full message via BLAKE3; the legacy braid container also binds the full digest |

Any change requires an ADR, a gap-register entry, traceability update, impact analysis, and a second review.

## 5. Quality bar

| Dimension | Requirement |
|---|---|
| Dependencies | Zero external crates |
| Memory safety | 100% safe Rust; Miri; Kani |
| Panic freedom | No `unwrap`/`expect`/`panic`/`todo`/`unimplemented`/`unreachable` |
| Arithmetic | Checked operations; `arithmetic_side_effects` denied |
| Allocation | No heap in core; fixed-size buffers |
| Stack | Proven bounds; no recursion; statically bounded loops |
| Determinism | Same input → same output across supported platforms |
| Constant time | No secret-dependent branches or memory access |
| Correctness | Math spec + KATs + differential + property tests |
| Coverage | 100% core line/branch target; 95% overall; exceptions in gap register |
| Mutation | ≥95% target, 100% goal |
| Fuzzing | 72h clean by default; QHS-1 RC accepted 1h by owner waiver 2026-11-06 |
| Attack coverage | 100% of functions have FAD + attack harness |
| Gap coverage | Zero open gaps at release |
| Supply chain | Zero crates; pinned toolchain; reproducible builds |
| Review | Two-person review; attacker rotation; signed commits |
| Documentation | Math, architecture, threat model, API, security policy |
| Claims | Measured and reproducible; no standard compliance claim |

## 6. Process

1. **FAD** — every function gets a dossier in `docs/adversary/`.
2. **Attack harness** — every function gets an exploit/abuse test in `qwp-attacks`.
3. **Break log** — every attack attempt and result is recorded.
4. **Gap register** — every known gap is tracked with owner, severity, closure criterion, and evidence.
5. **Traceability** — every requirement maps to design, code, test, and evidence.
6. **Red team** — every critical function has an attacker who did not write it.
7. **Release gate** — zero open gaps, 100% FAD coverage, attack suite pass, no unmitigated critical/high finding.

## 7. Definition of done

A function is done only when:

- its FAD is complete and signed by engineer and attacker;
- its attack harness passes;
- its error paths are tested;
- its bounds are proven or measured;
- its docs are written;
- its gaps are closed;
- its traceability entry is complete.

A release is done only when the same is true for every function, plus:

- zero open gaps;
- traceability matrix complete;
- internal red-team sign-off;
- reproducible build;
- zero-dependency SBOM;
- no standard compliance claim;
- accurate, measured security claims.

## 8. Non-standard is not unrigorous

The project rejects external standards as authority, not rigor. qWp Standard v1 is intentionally stricter: zero crates, zero unsafe, zero panics, zero heap in core, every function attacked, every gap tracked. If a rule cannot be met, it is an open gap — not a silent exception.
