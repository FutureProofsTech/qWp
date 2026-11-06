# qWp Break Log

**Rule:** Every attack attempt and result is recorded. A known unmitigated critical/high break blocks release.

| ID | Date | Target | Attack | Result | Gap | Status |
|---|---|---|---|---|---|---|
| BL-0001 | 2026-11-06 | Signature verification | Identity-key forgery: `S = M` with `P = identity` | **Confirmed break.** Conjugation cancels the private key; `V(S) = V(M)` | GAP-CRYPTO-0001 | Open |
| BL-0002 | 2026-11-06 | Invariant definition | Compare stated recurrence with conventional Jones skein | **Confirmed mismatch.** Recurrence is custom; invariance unproven | GAP-MATH-0002 | Open |
| BL-0003 | 2026-11-06 | Message braid | Birthday collision on 32-crossing / 14-symbol space | **Risk confirmed.** ~61-bit collision; mitigated by D16 full-digest binding | GAP-CRYPTO-0006 | Mitigated by design, verification open |
| BL-0004 | 2026-11-06 | Skein solver | Exhaustive binary tree at 32/96 crossings | **Confirmed infeasible.** 2^32 / 2^96 states | GAP-SOLVER-0004 | Mitigated by TL DP design, implementation open |
| BL-0005 | 2026-11-06 | Public key | Equivalent-braid search | **Open risk.** Any braid with the same invariant may verify | GAP-CRYPTO-0006 | Open |
| BL-0006 | 2026-11-06 | B8 | Garside/conjugacy/length-based attacks | **Open risk.** B8 is small; no security reduction | GAP-CRYPTO-0005 | Open |
| BL-0007 | 2026-11-06 | Secret lifetime | Zeroization in safe Rust | **Accepted limitation.** No guaranteed wipe without unsafe/volatile writes | GAP-POLICY-0013 | Accepted by D13, compensating controls open |
| BL-0008 | 2026-11-06 | In-tree BLAKE3 | Implementation fault injection | **Mitigated by implementation.** KATs pass; fuzz/Kani pending | GAP-CRYPTO-0014 | In progress |
| BL-0009 | 2026-11-06 | Parser | Malformed/oversized input | **Mitigated by implementation.** Negative tests pass; fuzz pending | GAP-FMT-0007 | In progress |
| BL-0010 | 2026-11-06 | Timing | Branch/memory leakage in keygen/sign/verify | **Open risk.** No CT implementation yet | GAP-CRYPTO-0001 | Open |

## Rules

- Every entry has an ID, target, attack, result, gap, and status.
- "Confirmed break" requires a reproducible test or proof.
- "Mitigated by design" is not closed until the implementation and test exist.
- "Accepted limitation" requires an explicit decision and compensating controls.
- A break is never deleted; it is closed or superseded with evidence.
