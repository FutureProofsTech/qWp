# ADR-0010: QHS-6 Classical Hybrid

**Status:** Accepted and implemented — local evidence; 1-hour soak passed; `qhs6-rc1`

**Date:** 2026-11-09

**Deciders:** qWp owner, crypto lead, red team

**Related:** `docs/17-qhs6.md`, `docs/16-qhs5.md`, `docs/09-version-family.md`, `docs/03-formats.md`

---

## Context

QHS-5 is the 512-bit-hash stateful profile with a 256-bit classical /
~128-bit quantum target. The family plan reserves QHS-6 for a classical hybrid
for migration and compliance. A hybrid is not a parameter tweak: it adds a
classical public-key signature and a composition proof.

The project has a zero-external-crate rule and only in-tree first-party crypto.
The classical primitive must therefore be implemented in-tree. Ed25519 is the
smallest complete classical signature that fits this constraint: it needs
SHA-512 and Curve25519 field/group arithmetic, but no big-integer RSA keygen or
pairing library.

## Decision

QHS-6 is **QHS-5 + Ed25519**, with both signatures over a key-and-message
binding transcript.

| Parameter | Value |
|---|---:|
| Hybrid public key | 108 bytes |
| Hybrid private key | 108 bytes |
| Hybrid signature | 6,284 bytes |
| Key header | `[7, 7, 8, 0]` |
| Signature header | `[7, 7, leaf_index LE]` |
| QHS-5 public key | 72 bytes |
| QHS-5 private key | 72 bytes |
| QHS-5 signature | 6,216 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 seed | 32 bytes |
| Ed25519 signature | 64 bytes |
| QHS-5 signatures/key | 256 |
| QHS-5 cache | 16,452 bytes |
| QHS-5 state guard | 38 bytes |

Layouts:

```
public key:  4 header | 72 QHS-5 public | 32 Ed25519 public
private key: 4 header | 72 QHS-5 private | 32 Ed25519 seed
signature:   4 header | 6,216 QHS-5 signature | 64 Ed25519 signature
```

The transcript is

\[
T = H64_{\text{transcript}}(\text{QHS-5 public key} \parallel \text{Ed25519 public key} \parallel \text{message}).
\]

QHS-5 signs `T`; Ed25519 signs `T`. Verification accepts only if both verify
and the hybrid leaf index matches the QHS-5 signature leaf index.

## Why this is sound

A hybrid signature is an **AND** composition: the forger must produce both a
valid QHS-5 signature and a valid Ed25519 signature on the same transcript.

- If QHS-5 is EUF-CMA, a hybrid forgery yields a QHS-5 forgery on a transcript
  that was not signed, unless the transcript collides. `H64` collision
  resistance is ~`2^256`.
- If Ed25519 is EUF-CMA, a hybrid forgery yields an Ed25519 forgery on a
  transcript that was not signed, unless the transcript collides.
- Therefore breaking the hybrid requires breaking **both** components (or the
  transcript binding). A quantum break of Ed25519 does not help the attacker
  forge the QHS-5 part, so the hybrid retains QHS-5's ~128-bit quantum margin.
- The transcript binds both public keys and the message, preventing
  mix-and-match of a QHS-5 signature and an Ed25519 signature from different
  keys or messages.
- The QHS-5 seed and Ed25519 seed are independent random secrets; compromise of
  one component does not compromise the other.

## Consequences

- New `qwp-classical` crate: in-tree SHA-512, field/scalar/point arithmetic,
  Ed25519 keygen/sign/verify, RFC 8032 vectors.
- New `qhs6-*` CLI, 108-byte keys, 6,284-byte signatures, QHS-6 leaf cache and
  state guard.
- New format version 7 because QHS-5 uses version 6.
- New proof, tests, attacks, Kani parser proofs, fuzz coverage, timing,
  coverage, mutation, and 1-hour soak.
- QHS-5 and all earlier versions remain unchanged.
- The Ed25519 implementation is first-party and must be treated as a new
  cryptographic primitive: RFC 8032 vectors, parser/tamper tests, timing, fuzz,
  and an explicit constant-time review are required.
- No 2^64 variant is planned or claimed.
