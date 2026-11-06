# ADR-0001: Signature Paradigm

**Status:** Superseded by ADR-0002 — Option A retained only as a research module  
**Date:** 2026-11-06  
**Deciders:** qWp owner, crypto lead, red team  
**Related:** `docs/security-memo.md`, `docs/01-math-spec.md`, `docs/03-formats.md`, `docs/05-qhs1.md`, `docs/adr/0002-qhs1.md`, GAP-CRYPTO-0001

---

## Context

The original signature

\[
S = P \cdot M \cdot P^{-1}
\]

is unsound: the closure of a conjugate braid is isotopic to the closure of the original, so every link invariant, including the Jones polynomial, is independent of \(P\). The private key cancels exactly. This is a theorem, not a bug.

Phase 0 therefore cannot "fix" the original equation inside the existing 160-byte topological design. It must choose a new signature paradigm.

## Constraints

- Non-standard: no NIST/ISO/FIPS/RFC compliance claim.
- Zero external crates; safe first-party Rust.
- No standard fallback.
- Measured security, not a compliance claim.
- Current sizes: 40-byte private key, 516-byte public key, 160-byte signature.
- Topological identity is a project goal, but not at the cost of a false security claim.

## Options

### Option A — Topological braid signature, larger signatures

- Keep the braid/Jones system.
- Use a braid signature construction (public braid pair, three-braid signature).
- Parameters: \(B_n\), \(n\ge16\)–20, longer braids.
- Signature size: roughly 2–4 KB; public key changes from a polynomial to a braid pair/commitment.
- Security: research-grade until the internal red team publishes measured attack costs.
- **Pros:** preserves qWp's topological identity.
- **Cons:** violates the 160-byte signature target; large attack surface; no production claim yet.

### Option B — Compact custom group signature

- Keep the 160-byte signature and 516-byte public key.
- Define a qWp custom 256-bit prime-order group (custom curve or equivalent).
- Use a Schnorr-like equation with BLAKE3 challenge derivation.
- Signature: 64–96 bytes; public key: 32–64 bytes (fits 516 with padding).
- **Pros:** fits the size target; can target 128-bit measured security.
- **Cons:** abandons the topological invariant; new group implementation and audit; "Schnorr-like" is a familiar construction even if the group is custom.

### Option C — Research only / stop

- Keep the prototype, publish the break, do not ship a signature.
- **Pros:** honest; no false security.
- **Cons:** not the full product.

## Decision

**Pending owner decision.** The engineering recommendation is:

1. If **topology is non-negotiable**, choose **Option A** and explicitly change the signature size target to 2–4 KB. Do not claim 160-byte compatibility.
2. If **160-byte signature and shippable security are non-negotiable**, choose **Option B** and explicitly change the project identity from "topological signature" to "custom group signature with a topological research module."
3. If neither is acceptable, choose **Option C** and publish the research.

No option may be implemented until this ADR is accepted.

## Consequences

- Option A: update `docs/03-formats.md`, public-key format, signature format, FADs, and attack suite; add a new braid-signature security memo.
- Option B: add a new `qwp-group` module, field/curve arithmetic, constant-time scalar operations, new KATs, new attack suite, and a new security memo.
- Option C: mark the project research-only; close the production path.

## Kill criteria

- If the chosen option cannot survive the internal attack suite, stop or remain research.
- If the measured attack cost is below the target, do not ship.
- Do not switch to a standard scheme as a fallback.
