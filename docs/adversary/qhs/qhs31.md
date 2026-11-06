# FAD: qwp_crypto::qhs3 QHS-3.1 Tree-Cache Profile

## Identity

- Function ID: `qhs3_build_tree`, `qhs3_auth_path_from_tree`, `Qhs3PrivateKey::sign_with_auth_path`, CLI QHS-3.1 tree-cache read/write
- Module: `qwp-crypto/qhs3`, `qwp-cli`
- Visibility: public/private
- Owner (engineer): Crypto lead
- Owner (attacker): Red team
- Status: survived; FAD closed. Same QHS-3 signature format.

## Contract

- Purpose: make QHS-3 signing O(log N) using a public Merkle tree cache.
- Inputs: 4,096 leaves, 4,095 internal nodes, 12-node auth path, message.
- Outputs: identical QHS-3 signature bytes.
- Secrets handled: seed and WOTS chain values; the tree cache contains no secrets.
- Trust boundary: untrusted tree cache; secret seed.
- Preconditions: tree cache matches the seed and leaf index.
- Postconditions: signature verifies under the QHS-3 public key.
- Invariants: same QHS-3 proof, KAT, keys, and signature format.

## Attacker model

- Capabilities: poisoned leaves/nodes, foreign cache, oversized cache, wrong leaf index, cross-version cache.
- Assets targeted: signing correctness, cache trust.
- Abuse cases:
  - A1: altered leaf.
  - A2: altered internal node.
  - A3: foreign cache.
  - A4: oversized/special file.
  - A5: wrong leaf index / auth path.
  - A6: cross-version cache.

## Evidence

- `qhs3.rs` unit test: tree auth paths and tree-cache signatures equal leaf-cache signatures for leaves 0, 1, 42, 2048, 4095.
- `qwp-cli` test: tree cache creation, reuse, header tamper fallback, deletion/recreation, cross-version verification.
- Timing: sign ≈0.35–0.36 ms, verify ≈0.39 ms.
- Break-log: BL-0017.
- Gap: GAP-QHS-0026 — closed.

## Closure

- Abuse cases covered: A1–A6 by fingerprint/checksum, bounded reads, auth-path bounds, and equivalence tests.
- Error paths tested: missing, corrupt, foreign, wrong-kind, oversized tree cache.
- Bounds proven: slice length checks + unit tests.
- Red-team sign-off: profile uses the QHS-3 proof unchanged.
- Date: 2026-11-06
