# FAD: qwp_platform::qhs4_sign_parallel (QHS-4.1)

## Identity

- Function ID: `qhs4_sign_parallel`, `qhs4_signing_plan`, `qhs4_leaf`, `qhs4_fors_leaf`, `qhs4_tree_root_and_auth_from_leaves`, `qhs4_fors_root_and_auth_from_leaves`, `qhs4_sign_with_trees`, `Qhs4Contexts`, CLI `qhs41-*`
- Module: `qwp-platform`, `qwp-crypto/qhs4`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed for the local production path. 1-hour soak pending.

## Contract

- Purpose: parallel fast-signing profile of QHS-4 with byte-identical output.
- Inputs: 68-byte QHS-4 private key, message bytes, QHS-4 signing plan, precomputed trees.
- Outputs: 18,216-byte QHS-4 signature, identical to the sequential signer.
- Secrets handled: `SK.seed`, WOTS chain values, FORS leaf secrets.
- Trust boundary: untrusted signatures/public keys; secret seed; host thread scheduler.
- Preconditions: same key/message/plan; trees derived from the same key and message.
- Postconditions: signature verifies under the QHS-4 public key; key bytes are unchanged.
- Invariants: same QHS-4 parameters, contexts, header, checksum, and proof; sequential `sign` remains the reference; no cache/state.

## Attacker model

- Capabilities: chosen message, signature tampering, wrong key, plan/tree mismatch, worker failure, timing/scheduling, cross-profile confusion.
- Assets targeted: WOTS/FORS tree roots, auth paths, signature bytes, private key file.
- Attack tree: `docs/attack-trees.md` §12 and `docs/14-qhs41.md`.
- Abuse cases:
  - A1: parallel signature differs from sequential.
  - A2: mismatched plan or tree.
  - A3: tampered signature.
  - A4: wrong message/key.
  - A5: worker panic/failure.
  - A6: timing/scheduling leakage.
  - A7: cross-profile verify confusion.
  - A8: key mutation or unexpected cache/state files.

## Evidence

- Direct unit tests: `crates/qwp-crypto/src/qhs4.rs` (plan/tree/leaf APIs, byte-equivalence, wrong plan/tree rejection); `crates/qwp-crypto/tests/qhs4_kat.rs`.
- Platform equivalence: `qhs4_parallel_sign_matches_sequential`.
- Negative/abuse tests: `qwp_attacks::attack_qhs41`; suite 10/10.
- CLI tests: `qhs41_parallel_keygen_sign_verify_end_to_end`; `qhs41-selftest`; both verifiers accept the signature; key bytes/mtime unchanged; no cache/state.
- Formal harness: the 15 QHS-4-family Kani parser/bounds proofs remain green.
- Timing: sequential ≈0.815 s, parallel ≈0.110 s, speedup ≈7.4×; Welch `|t| < 4.5`; `docs/evidence/qhs41-timing.txt`.
- Coverage: QHS-4 crypto 99.28% lines; `docs/evidence/qhs41-coverage.txt`.
- Fuzz: the QHS-4 fuzz driver uses the parallel signer on longer runs; 1-hour soak pending.
- Break-log entries: BL-0022, BL-0023.
- Gap IDs: GAP-QHS-0029 — closed; 1-hour soak pending.

## Closure

- Abuse cases covered: A1–A8 in tests/attack/CLI.
- Error paths tested: wrong plan, wrong tree, worker/join failure, tampering, wrong key/message.
- Bounds proven: same QHS-4 proof; byte-equivalence tests; checked arithmetic; Kani parser proofs.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-09
