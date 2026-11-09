# ADR-0005: QHS-3.1 Tree-Cache Signing Profile

**Status:** Accepted — implementation complete  
**Date:** 2026-11-06  
**Deciders:** qWp owner, crypto lead, red team  
**Related:** `docs/10-qhs3.md`, `docs/12-qhs31.md`, `docs/09-version-family.md`

---

## Context

QHS-3 signs in ≈1.6–1.7 ms because it extracts the 12-node Merkle auth path
from the leaf cache by recomputing range roots — about 4,095 hashes per
signature. The WOTS signature itself is much cheaper.

The owner wants QHS-3 to be competitive on signing speed without changing the
1,832-byte signature, the 64-byte keys, the 4,096-signature capacity, or the
security proof.

## Decision

QHS-3.1 is a **tree-cache profile of QHS-3**, not a new signature format:

- Same keys, same QHS-3 signature bytes, same KAT, same version/algorithm `3/3`.
- New optional `<private-key>.treecache` file (262,180 bytes):
  - 4-byte header `[3, 3, 12, 3]`
  - 32-byte fingerprint
  - 131,072 bytes of leaves (4,096 × 32)
  - 131,040 bytes of internal nodes (4,095 × 32)
  - 32-byte keyed BLAKE3 MAC
- New `Qhs3PrivateKey::sign_with_auth_path` API.
- New `qhs3_build_tree` and `qhs3_auth_path_from_tree` APIs.
- New `qhs31-*` CLI commands.

QHS-3 remains available with its 131,140-byte leaf cache and its original
`qhs3-*` commands.

## Security

The tree cache contains only public Merkle data. It is validated by a versioned
fingerprint and keyed MAC; a corrupt or foreign cache is ignored and rebuilt.
The verifier still recomputes the Merkle root, so a poisoned cache cannot
produce a valid forgery. The QHS-3 proof, assumptions, signature bytes, and KAT
are unchanged.

## Measured performance

On the 16-thread reference host, release build:

| Operation | QHS-3 | QHS-3.1 |
|---|---:|---:|
| Keygen | ≈0.40–0.44 s | ≈0.40–0.41 s |
| Cached sign | ≈1.60–1.70 ms | **≈0.35–0.36 ms** |
| Verify | ≈0.39 ms | ≈0.39 ms |
| Signature | 1,832 B | 1,832 B |
| Tree/leaf cache | 131,140 B | 262,180 B |

Signing is about 4.5× faster. Keygen and verification are unchanged.

## Consequences

- New `qhs31-selftest`, `qhs31-keygen`, `qhs31-sign`, `qhs31-verify` commands.
- New `.treecache` format and fingerprint context.
- QHS-3 remains fully supported.
- The 1-hour soak covers the same QHS-3 signature format; cache paths are
  covered by CLI tests.
