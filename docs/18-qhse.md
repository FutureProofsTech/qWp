# QHS-E — Embedded Verifier Profile

**Status:** Design accepted; implementation and local evidence complete; 1-hour soak pending.

**Scope:** verifier-only profile of QHS-1/2/3/3.1. Same public keys, same
signatures, same security proof.

**Rule:** No external standard is accepted as proof. This document is the
profile proof and evidence plan.

---

## 1. Profile parameters

| Parameter | QHS-1 | QHS-2 | QHS-3 / QHS-3.1 |
|---|---:|---:|---:|
| Public key | 64 B | 64 B | 64 B |
| Signature | 2,408 B | 1,704 B | 1,832 B |
| WOTS chains | 67 | 45 | 45 |
| WOTS chain length | 15 | 63 | 63 |
| Message digits | 64 hex + 3 checksum | 43 base-64 + 2 checksum | 43 base-64 + 2 checksum |
| Merkle height | 8 | 8 | 12 |
| Header | `[1,1,8,0]` | `[2,2,8,0]` | `[3,3,12,0]` |

QHS-E adds no new format. It accepts exactly the existing QHS-1/2/3/3.1
signatures and public keys.

## 2. API

```rust
pub fn verify_qhs1(public_key: &[u8; 64], message: &[u8], signature: &[u8; 2408]) -> Result<(), CryptoError>;
pub fn verify_qhs2(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1704]) -> Result<(), CryptoError>;
pub fn verify_qhs3(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1832]) -> Result<(), CryptoError>;
pub fn verify_qhs31(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1832]) -> Result<(), CryptoError>;
```

The functions are `no_std`, allocation-free, and use fixed-size stack buffers.
They return `VerificationFailed` for any invalid signature and
`InvalidLength`/`InvalidPadding` for malformed fixed-layout input where
applicable.

## 3. Verification equations

QHS-E performs the same steps as the base verifier:

1. Check the public-key header and signature header/version.
2. Check the leaf index is `< 256` (QHS-1/2) or `< 4096` (QHS-3).
3. Recompute the signature checksum over the body and compare the trailing
   4 bytes.
4. Recompute the message digits from the message digest.
5. For each WOTS chain, hash `chain_len - digit` times from the revealed value
   and hash the resulting chain ends into the WOTS public-key hash.
6. Hash the leaf index and WOTS public key into the leaf.
7. Climb the Merkle auth path using the leaf-index bits.
8. Accept iff the computed root equals the public-key root.

Domain contexts are the base-version contexts:

- `qWp QHS-1 ...`
- `qWp QHS-2 ...`
- `qWp QHS-3 ...`

No new context is introduced.

## 4. Security proof

QHS-E is a re-implementation of the existing verifier, not a new signature.
The QHS-1/2/3 security proofs apply unchanged if QHS-E computes the same
accept/reject predicate.

### Lemma — Differential equivalence

For every public key, message, and signature in the fixed formats, QHS-E
returns `Ok(())` iff the corresponding `qwp-crypto` verifier returns `Ok(())`.

**Evidence:** differential tests cover:

- known-answer valid signatures for QHS-1/2/3/3.1;
- every header field and leaf-index mutation;
- WOTS, auth-path, and checksum tampering;
- wrong message and wrong key;
- cross-version signatures and keys;
- random malformed signatures.

The verifier uses the same equations and contexts, so a divergence is a
QHS-E implementation bug.

### Theorem

If QHS-1/2/3 are EUF-CMA, then QHS-E accepts only valid signatures for the
same formats. ∎

## 5. Embedded constraints

- `#![no_std]`, `#![forbid(unsafe_code)]`.
- No heap, no `alloc`, no threads.
- Fixed-size arrays only. The largest stack objects are a 32-byte chain value,
  a 32-byte WOTS public-key hash, and the caller-owned signature/key buffers.
- The auth path is read in place; QHS-E does not copy the whole signature.
- QHS-3's 12-level auth path is 384 bytes; the verifier still does not copy it.
- Code size is measured for `thumbv7em-none-eabihf` and
  `riscv32imac-unknown-none-elf` on the release profile.
- Cycle/instruction evidence is measured on the host; actual MCU cycles require
  hardware and are not claimed.

## 6. Code-size and stack evidence

Planned commands:

```text
cargo build --release --target thumbv7em-none-eabihf -p qwp-e --features size-probe
cargo build --release --target riscv32imac-unknown-none-elf -p qwp-e --features size-probe
llvm-size -A <staticlib>
```

The `size-probe` feature adds a minimal panic handler so a `staticlib` can be
built. Normal users provide their own panic handler.

Stack bounds are documented by inspection and, where tooling allows, by
`-Z emit-stack-sizes`; the verifier never allocates and never copies the full
signature.

## 7. Timing evidence

A host timing harness verifies fixed KAT signatures for QHS-1/2/3/3.1 and
reports ns/op, plus `perf stat` cycles/instructions for the verification loop.
This is host evidence, not an MCU cycle claim.

## 8. Limitations

- Verifier-only: no keygen, signing, cache, or state guard.
- The same stateful-signing caveats apply to QHS-1/2/3/3.1.
- No new security level; the base-version proof is inherited.
- Code size depends on the linker, LTO, panic strategy, and target.
- No external audit and no standard-compliance claim.
- No 2^64 variant is planned.

## 9. Attack plan

1. Valid signatures accepted, invalid signatures rejected.
2. Header/version/height/leaf-index tampering.
3. Checksum, WOTS, and auth-path tampering.
4. Wrong message/key.
5. Cross-version confusion (QHS-1/2/3 signatures and keys).
6. Truncated/malformed fixed-layout input.
7. Differential divergence against `qwp-crypto`.
8. Fuzz/panic/DoS.

If any attack succeeds or differential equivalence fails, QHS-E is broken; fix
or stop.

## 10. Implementation and evidence

- Implementation: `crates/qwp-e`.
- ADR: `docs/adr/0011-qhse-embedded.md`.
- Formats: same as QHS-1/2/3/3.1; no new format.
- CLI: `qhse-selftest` and `qhse-verify`.
- Tests: 6 differential tests for QHS-1/2/3/3.1, multiple leaves, random
  signatures, wrong-length WOTS, and negative QHS-3.1 cases.
- Attack harness: `qwp-attacks::attack_qhse`; suite 14/14.
- Kani: inherited QHS-1/2/3 parser/length proofs; QHS-E fixed-size API and
  profile paths are covered by differential tests/fuzz.
- Fuzz: 60-second run 460,745 iterations, 0 panics; 1-hour soak pending in
  `docs/evidence/qhse-fuzz-soak-1h.txt`.
- Timing: host ≈0.14 ms (QHS-1), ≈0.31 ms (QHS-2), ≈0.38 ms (QHS-3/3.1);
  perf ≈3.34M cycles / ≈10.05M instructions per verification.
- Code size: 7,447 B (thumbv7em) / 10,331 B (riscv32imac) for all four verifier
  entry points; evidence in `docs/evidence/qhse-size.txt`.
- Coverage: 98.44% lines; 100% functions; evidence in
  `docs/evidence/qhse-coverage.txt`.
- Mutation: 46 mutants, 45 caught, 0 unviable, 1 equivalent `|`/`^` miss;
  evidence in `docs/evidence/qhse-mutation.txt`.
- Soak: 1-hour run pending before `qhse-rc1`.
