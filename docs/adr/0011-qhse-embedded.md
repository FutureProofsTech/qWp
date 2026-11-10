# ADR-0011: QHS-E Embedded Verifier Profile

**Status:** Accepted, implemented, soaked, and tagged `qhse-rc1`

**Date:** 2026-11-10

**Deciders:** qWp owner, crypto lead, embedded lead

**Related:** `docs/18-qhse.md`, `docs/09-version-family.md`, `docs/03-formats.md`

---

## Context

QHS-1/2/3/3.1 are stateful hash-based signatures. Their existing verifiers live
in `qwp-crypto`, which also contains key generation, signing, caches, and every
other version. An embedded bootloader or MCU needs a small verifier-only
profile with:

- `no_std`, no heap, no `unsafe`;
- fixed-size stack usage;
- the same public keys and signatures as QHS-1/2/3/3.1;
- code-size and cycle evidence on constrained targets.

QHS-E is not a new signature and does not change any format. It is a separate,
minimal verifier implementation that must be differentially equivalent to the
`qwp-crypto` verifiers.

## Decision

Add a first-party `qwp-e` crate with verifier-only entry points:

```rust
verify_qhs1(public_key: &[u8; 64], message: &[u8], signature: &[u8; 2408])
verify_qhs2(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1704])
verify_qhs3(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1832])
verify_qhs31(public_key: &[u8; 64], message: &[u8], signature: &[u8; 1832])
```

QHS-3.1 is an alias for QHS-3 because it uses the same signature format.

The crate depends only on `qwp-core` (error type) and `qwp-hash` (BLAKE3). It
does not depend on `qwp-crypto`, does not include keygen/sign code, and does not
allocate.

## Why this is sound

QHS-E recomputes exactly the same verification equations as QHS-1/2/3:

- the same header/version/height checks;
- the same message-digit encoding (hex for QHS-1, base-64 for QHS-2/3);
- the same WOTS chain length, chain count, and derive-key contexts;
- the same leaf/node hashing and Merkle auth-path climbing;
- the same checksum over the same byte range.

The QHS-1/2/3 proofs therefore carry over unchanged. Differential tests compare
QHS-E against the `qwp-crypto` verifiers for valid signatures, tampered
signatures, wrong messages, wrong keys, and cross-version headers. Any
divergence is a QHS-E bug, not a new security assumption.

## Consequences

- New `qwp-e` crate with verifier-only code.
- New `qhse-*` CLI verification command (optional host convenience).
- Differential tests, attack harness, fuzz coverage, timing, code-size, stack,
  coverage, mutation, and a fresh 1-hour soak.
- Embedded code-size evidence for `thumbv7em-none-eabihf` and
  `riscv32imac-unknown-none-elf`.
- No new key/signature format, no new tag for a signature version; the profile
  gets `qhse-rc1`.
- QHS-1/2/3/3.1 and all later versions remain unchanged.
- No 2^64 variant is planned or claimed.
