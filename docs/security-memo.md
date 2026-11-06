# qWp Security Memo — Phase 0

**Status:** C1 original construction rejected; replacement decision required.  
**Date:** 2026-11-06  
**Author:** qWp engineering + red team  
**Rule:** No external standard is accepted as proof.

---

## 1. Executive result

The original signature construction is **unsound**:

\[
S = P \cdot M \cdot P^{-1}.
\]

The private braid cancels under closure:

\[
\widehat{P M P^{-1}} \cong \widehat{M},
\]

so every link invariant, including the Jones polynomial, satisfies

\[
V(\widehat{S}) = V(\widehat{M})
\]

independent of \(P\). \(S=M\) is a universal forgery.

This is not a test failure or an implementation bug. It is a theorem about braid closures. The original construction is rejected.

## 2. What was closed

### C2 — invariant definition

Closed by `docs/01-math-spec.md`: qWp uses the conventional Kauffman bracket and Jones polynomial, not the project document's non-standard recurrence. The conventional definitions specify writhe, orientation, and disjoint-unlink normalization.

### C3 — degree and coefficient bounds

Closed at the format level:

- degree bounds derived for 32/96/144 crossings;
- 129-coefficient public key is sufficient for 32 crossings;
- verifier scratch is 257 coefficients for 96 crossings, 385 for 144;
- `i64` accumulation with checked `i32` conversion;
- keygen rejects any braid whose polynomial coefficient overflows `i32`.

The distribution impact of rejection remains a keygen test obligation (GAP-KEY-0008).

### C4 — solver complexity

Closed by design: Temperley–Lieb DP over 1430 states with a degree sweep, not the \(2^c\) Skein tree. Implementation is tracked separately.

## 3. Why the original construction cannot be repaired

A verification equation that depends only on \(V(\widehat{\cdot})\) cannot authenticate \(P\), because \(V\) is a conjugation invariant. Any repair must introduce a public value that is **not** invariant under the secret conjugation, and the verifier must check a hard problem involving that value.

The project's public key is only a polynomial. That object has no trapdoor and no secret-dependent structure. It cannot serve as a public key for a signature scheme. This is a structural issue, not a tuning issue.

## 4. Candidate replacement analysis

### 4.1 Topological braid signature (preserve topology)

Published braid signature schemes use \(B_n\) with \(n\approx20\)–28 and signatures of roughly 1.6–2.6 kbit (about 207–331 bytes) at rough security levels \(2^{20}\)–\(2^{30}\). qWp's \(B_8\), 32 crossings, and 160-byte signature are far below those parameters.

- **Public key:** a braid pair \((x, x_0)\) is at least 80 bytes, not a 516-byte polynomial; the format changes.
- **Signature:** three braids plus a digest exceed 160 bytes for meaningful parameters; 2–4 KB is more realistic.
- **Security:** B8 with 32 crossings is too small; B16–B20 with longer braids is the minimum research direction.
- **Verdict:** cannot meet 160 bytes and 128-bit security. It is a research path, not a production path.

### 4.2 Hash-based one-time signature

A 160-byte signature with practical Winternitz parameters gives roughly 64–80-bit security, not 128-bit. A Merkle tree for many signatures consumes additional space. The scheme is non-topological.

- **Verdict:** cannot meet 128-bit security at 160 bytes.

### 4.3 Compact custom group signature (preserve size)

A Schnorr-like signature over a custom 256-bit prime-order group fits 32-byte public keys and 64–96-byte signatures. If qWp defines its own curve/group, it is non-standard; it is still a discrete-log scheme and requires a new in-tree implementation and audit.

- **Verdict:** fits the size target, abandons the topological invariant, new implementation risk.

### 4.4 Matrix-group signature

A 2×2 matrix group over a 128-bit field gives roughly 64-bit generic security and a signature larger than 160 bytes. A 256-bit field gives better security but a signature around 288 bytes.

- **Verdict:** does not fit.

## 5. Decision options

### Option A — Preserve topology, enlarge signatures

- Use a braid signature with \(B_n\), \(n\ge16\)–20, longer braids.
- Signature size grows to roughly 2–4 KB.
- Public key changes from a polynomial to a braid pair/commitment.
- Security is research-grade until attacked; no production claim.
- **Pros:** preserves qWp's topological identity.
- **Cons:** violates the 160-byte signature target; large implementation/attack surface.

### Option B — Preserve 160 bytes, change paradigm

- Use a custom compact group signature (custom curve/group, Schnorr-like).
- Public key 32–64 bytes; signature 64–96 bytes.
- Non-standard if qWp defines the group, but non-topological.
- **Pros:** fits sizes; can target 128-bit measured security.
- **Cons:** abandons the braid/Jones invariant; new curve/group implementation and audit.

### Option C — Remain research / stop

- Keep the prototype and publish the break.
- Do not ship a signature scheme.
- **Pros:** honest; no false security.
- **Cons:** not the full product.

## 6. Recommendation

The project doctrine says **topological, non-standard, zero-trust, no gaps**. Under that doctrine:

- If **topology is non-negotiable**, choose **Option A**, accept larger signatures, and keep the project research-grade until the attack suite supports a measured claim.
- If **160 bytes and a shippable signature are non-negotiable**, choose **Option B**, accept that qWp becomes a custom group-signature project rather than a topological one.
- If neither is acceptable, choose **Option C** and publish the research.

No standard fallback is permitted. The decision is recorded in `docs/adr/0001-signature-paradigm.md`.

## 7. Attack obligations for the chosen option

Every candidate must survive:

1. identity/conjugation forgeries;
2. equivalent-object forgeries;
3. key recovery (brute force, algebraic, length-based);
4. signature squeezing/multiple signatures;
5. malleability/replay/cross-protocol;
6. timing/fault/DoS;
7. measured attack-cost publication.

## 8. Current status

- C1 original construction: **closed as rejected**.
- Replacement: **open** (ADR-0001).
- No `sign`/`verify` implementation will be shipped until ADR-0001 is accepted and the replacement survives the attack suite.
