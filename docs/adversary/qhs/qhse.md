# FAD: qwp_e (QHS-E embedded verifier)

## Identity

- Function ID: `verify_qhs1`, `verify_qhs2`, `verify_qhs3`, `verify_qhs31`; CLI `qhse-verify`
- Module: `qwp-e`
- Visibility: public
- Owner (engineer): Embedded lead
- Owner (attacker): Red team
- Status: attacked; FAD open until the 1-hour soak.

## Contract

- Purpose: verifier-only QHS-1/2/3/3.1 profile for bootloaders/MCUs.
- Inputs: 64-byte public key, message, fixed-size signature.
- Outputs: `Ok(())` or `CryptoError`.
- Secrets handled: none; verification is public.
- Trust boundary: untrusted public keys, signatures, and messages.
- Preconditions: exact fixed-size key/signature buffers.
- Postconditions: accepts iff the corresponding `qwp-crypto` verifier accepts.
- Invariants: no heap, no `unsafe`, no full-signature copy, same domain
  contexts and verification equations as the base versions.

## Attacker model

- Capabilities: malformed fixed-layout keys/signatures, tampering, wrong
  message/key, cross-version substitution, timing/DoS.
- Assets targeted: verifier acceptance predicate, parser, stack/heap.
- Attack tree: `docs/attack-trees.md` §16 and `docs/18-qhse.md` §9.
- Abuse cases:
  - A1: valid/invalid differential divergence.
  - A2: header/version/height/leaf tampering.
  - A3: checksum/WOTS/auth-path tampering.
  - A4: wrong message/key.
  - A5: cross-version QHS-1/2/3 confusion.
  - A6: truncated/fixed-layout parser panic.
  - A7: heap/stack exhaustion.
  - A8: timing/fault/DoS.

## Evidence

- Differential tests: 5 tests comparing QHS-E against `qwp-crypto` for valid,
  tampered, wrong-message, wrong-key, random signatures, and multiple leaves.
- Attack harness: `qwp-attacks::attack_qhse`; suite 14/14.
- Fuzz: random fixed-layout keys/signatures/messages through QHS-E.
- Code size: 7,447 B (thumbv7em) / 10,331 B (riscv32imac), text+rodata for the
  QHS-E probe/verifier/BLAKE3/error objects.
- Timing: host ≈0.14 ms (QHS-1), ≈0.31 ms (QHS-2), ≈0.38 ms (QHS-3/3.1);
  perf counters ≈3.34M cycles / ≈10.05M instructions per verification.
- Coverage: 98.44% lines; 100% functions.
- Mutation: 46 mutants, 45 caught, 1 equivalent `|`/`^` miss.
- Gap IDs: GAP-QHS-0033.
- Break-log entry: BL-0030.

## Closure

- Abuse cases covered: A1–A8 in differential/attack/fuzz/timing.
- Error paths tested: fixed-layout header, leaf, checksum, WOTS, auth path,
  wrong message/key, random signatures.
- Bounds: no heap; fixed buffers; exact-size public API.
- Red-team sign-off: role-separated review complete.
- Date: 2026-11-10
