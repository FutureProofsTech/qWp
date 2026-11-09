# qWp Break Log

**Rule:** Every attack attempt and result is recorded. A known unmitigated critical/high break blocks release.

| ID | Date | Target | Attack | Result | Gap | Status |
|---|---|---|---|---|---|---|
| BL-0001 | 2026-11-06 | Signature verification | Identity-key forgery: `S = M` with `P = identity` | **Confirmed break.** Conjugation cancels the private key; `V(S) = V(M)` | GAP-CRYPTO-0001 | **Closed — construction rejected; QHS-1 selected** |
| BL-0002 | 2026-11-06 | Invariant definition | Compare stated recurrence with conventional Jones skein | **Confirmed mismatch.** Recurrence is custom; invariance unproven | GAP-MATH-0002 | **Research-only; not in production path** |
| BL-0003 | 2026-11-06 | Message braid | Birthday collision on 32-crossing / 14-symbol space | **Risk confirmed.** ~61-bit collision; mitigated by D16 full-digest binding | GAP-CRYPTO-0006 | **Research-only; D16 design mitigation** |
| BL-0004 | 2026-11-06 | Skein solver | Exhaustive binary tree at 32/96 crossings | **Confirmed infeasible.** 2^32 / 2^96 states | GAP-SOLVER-0004 | **Research-only; TL DP design** |
| BL-0005 | 2026-11-06 | Public key | Equivalent-braid search | **Open risk.** Any braid with the same invariant may verify | GAP-CRYPTO-0006 | **Research-only; not in production path** |
| BL-0006 | 2026-11-06 | B8 | Garside/conjugacy/length-based attacks | **Open risk.** B8 is small; no security reduction | GAP-CRYPTO-0005 | **Research-only; not in production path** |
| BL-0007 | 2026-11-06 | Secret lifetime | Zeroization in safe Rust | **Accepted limitation.** No guaranteed wipe without unsafe/volatile writes | GAP-POLICY-0013 | **Accepted — documented; no guaranteed wipe in safe Rust** |
| BL-0008 | 2026-11-06 | In-tree BLAKE3 | Implementation fault injection | **Mitigated.** KATs, 13M+ fuzz iterations, Miri, mutation 100/103 viable | GAP-CRYPTO-0014 | **Closed — evidence collected; BLAKE3 hardness remains an assumption** |
| BL-0009 | 2026-11-06 | Parser | Malformed/oversized input | **Mitigated.** Negative tests, Kani parser proofs, 13M+ fuzz iterations | GAP-FMT-0007 | **Closed — parser bounds/negative/fuzz** |
| BL-0010 | 2026-11-06 | Timing | Branch/memory leakage in keygen/sign/verify | **Mitigated.** Welch \|t\| < 4.5; fixed loops; BLAKE3 data-independent | GAP-SIGN-0019 | **Closed for QHS-1 — timing evidence; not a formal CT proof** |
| BL-0011 | 2026-11-06 | QHS-1 | WOTS/Merkle forgery analysis | **Proof reviewed.** EUF-CMA reduction to BLAKE3 preimage/collision; Kani parsers; timing; 1h fuzz soak | GAP-QHS-0021 | **Closed — 72h soak waived by owner** |
| BL-0012 | 2026-11-06 | QHS-1 | Leaf reuse via counter rollback | **Mitigated.** CLI writes updated key with fsync+rename before signature; single-writer lock; keyed state guard detects rollback | GAP-QHS-0020 | **Closed — atomic update + single-writer + state guard** |
| BL-0013 | 2026-11-06 | QHS-1 | Auth path / leaf index tampering | **Mitigated by tests.** Tamper matrix, all-zero/all-0xff, fuzz | GAP-QHS-0022 | **Closed — tamper tests/fuzz** |
| BL-0014 | 2026-11-06 | QHS-1 leaf cache | Poisoned, truncated, or foreign cache injection | **Mitigated.** Cache is public data; fingerprint+keyed MAC reject corruption; verifier recomputes Merkle root | GAP-QHS-0023 | **Closed — tamper/foreign/truncation tests** |
| BL-0015 | 2026-11-06 | QHS-2 | Smaller signature parameter review | **No new break.** 45×63 WOTS, 43+2 base-64 digits, 1,704-byte signature; reduction loss ~2^19.47; 128-bit target retained | GAP-QHS-0024 | **Closed — ADR/proof/tests; combined 1h soak passed** |
| BL-0016 | 2026-11-06 | QHS-3 | High-capacity height-12 tree review | **No new break.** 4,096 leaves, 1,832-byte signature; reduction loss ~2^21.47; 128-bit target retained; slice API avoids 128 KiB stack frames | GAP-QHS-0025 | **Closed — ADR/proof/tests; combined 1h soak passed** |
| BL-0017 | 2026-11-06 | QHS-3.1 tree cache | Poisoned, foreign, or oversized tree cache | **Mitigated.** Public Merkle data; versioned fingerprint + keyed MAC; verifier recomputes root; cache rebuild on mismatch | GAP-QHS-0026 | **Closed — tree/CLI tests; same QHS-3 signature** |
| BL-0018 | 2026-11-06 | Key store | Restore an old private-key backup and reuse leaves | **Mitigated locally.** Keyed `<private-key>.state` guard refuses signing when guard counter is ahead of key counter; missing guard rebuilds | GAP-QHS-0027 | **Closed — rollback test** |

## Rules

- Every entry has an ID, target, attack, result, gap, and status.
- "Confirmed break" requires a reproducible test or proof.
- "Mitigated by design" is not closed until the implementation and test exist.
- "Accepted limitation" requires an explicit decision and compensating controls.
- A break is never deleted; it is closed or superseded with evidence.
