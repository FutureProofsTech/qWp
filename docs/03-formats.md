# qWp Format Specification (Phase 0)

**Status:** Foundation formats frozen; production signatures are QHS-1/2/3/3.1 (ADR-0002–0005), QHS-4 (ADR-0006), and the QHS-4.1 fast-signing profile (ADR-0007, same QHS-4 formats). The 160-byte container is legacy research v0.

**Rule:** Every format is versioned, canonical, fixed-size, and little-endian. No external crates.

---

## 1. Constants

| Name | Value | Meaning |
|---|---:|---|
| `STRANDS` | 8 | Braid group rank |
| `MAX_CROSSINGS` | 32 | Private/message braid capacity |
| `BRAID_BYTES` | 40 | 32 `i8` + 8-byte length |
| `COEFF_COUNT` | 129 | Polynomial coefficients |
| `PUBLIC_KEY_BYTES` | 516 | 129 × `i32` |
| `SIGNATURE_BYTES` | 160 | Signature container |
| `MAX_SIGNATURE_CROSSINGS` | 120 | Braid bytes inside signature |
| `MESSAGE_BRAID_CROSSINGS` | 32 | Derived from BLAKE3 |
| `MAX_SCRATCH_DEGREES` | 385 | 144-crossing worst case |

## 2. Private key

Exact 40 bytes:

```
offset  size  field
0       32    crossings: [i8; 32]   // ±1..±7, 0 padding
32      8     length: u64 LE        // 0..=32
```

Canonical rules:

- `length <= 32`.
- Active crossings are non-zero and in `-7..=7`.
- Inactive crossings are zero.
- Reject non-canonical padding.

## 3. Public key

Exact 516 bytes:

```
offset  size  field
0       516   coefficients: [i32; 129] LE
```

Degree mapping:

```
index = degree + 64,  degree ∈ [-64, 64]
```

Canonical rules:

- Every 4-byte word is a valid `i32`.
- No canonicality constraint beyond the range; the polynomial is the key.
- If a coefficient is outside `i32`, the key is invalid (format version change required).

## 4. Signature container (v0 research)

Exact 160 bytes:

```
offset  size  field
0       1     version        // 0x01
1       1     flags          // reserved, must be 0 for v0
2       1     length         // active braid crossings, 0..=120
3       1     reserved       // must be 0
4       32    message_digest // full BLAKE3 digest
36      120   braid: [i8; 120]
156     4     checksum       // BLAKE3-derived 4-byte checksum
```

Canonical rules:

- `version == 1`.
- `flags == 0`.
- `length <= 120`.
- Active braid bytes are non-zero and in `-7..=7`.
- Inactive braid bytes are zero.
- `reserved == 0`.
- Checksum matches the first 156 bytes.
- The signature semantics are **not frozen**; ADR-0001 selects the equation. The container is designed to carry a full digest plus up to 120 crossings (enough for a 32+32+32 = 96-crossing product).

## 5. Message braid

Derived, not serialized:

1. `BLAKE3::derive_key("qWp v1 message braid", message)` → 32 bytes.
2. Base-14 mapping to 32 crossings.
3. Full 32-byte digest is stored in the signature (D16).

## 6. Legacy research signature container (v0)

The 160-byte container in section 4 is **legacy research v0**. The original equation `S = P·M·P⁻¹` is rejected (see `docs/security-memo.md`). Production signatures use QHS-1 (section 10, ADR-0002).

The v0 container may be parsed and attacked, but no `sign`/`verify` function may use it for production.

## 7. Checksum

The 4-byte checksum is:

```
BLAKE3("qWp v1 signature checksum" || first 156 bytes)[0..4]
```

It detects accidental corruption only; it is not authentication.

## 8. Versioning

- A format change increments the version byte and gets a new ADR/gap entry.
- Old versions are rejected unless a migration is explicitly implemented.
- No format is silently extended.

## 9. QHS-1 constants

| Name | Value |
|---|---:|
| `QHS_PUBLIC_KEY_BYTES` | 64 |
| `QHS_PRIVATE_KEY_BYTES` | 64 |
| `QHS_SIGNATURE_BYTES` | 2408 |
| `QHS_MAX_SIGNATURES` | 256 |
| `QHS_LEAF_COUNT` | 256 |
| `QHS_LEAF_BYTES` | 32 |
| WOTS chains | 67 |
| WOTS chain length | 15 |
| Merkle height | 8 |
| `QHS2_PUBLIC_KEY_BYTES` | 64 |
| `QHS2_PRIVATE_KEY_BYTES` | 64 |
| `QHS2_SIGNATURE_BYTES` | 1704 |
| `QHS2_MAX_SIGNATURES` | 256 |
| QHS-2 WOTS chains | 45 |
| QHS-2 WOTS chain length | 63 |
| QHS-2 message digits | 43 base-64 |
| QHS-2 checksum digits | 2 base-64 |
| `QHS3_PUBLIC_KEY_BYTES` | 64 |
| `QHS3_PRIVATE_KEY_BYTES` | 64 |
| `QHS3_SIGNATURE_BYTES` | 1832 |
| `QHS3_MAX_SIGNATURES` | 4096 |
| QHS-3 Merkle height | 12 |
| QHS-3 WOTS chains | 45 |
| QHS-3 WOTS chain length | 63 |
| QHS-3.1 tree cache | 262,180 |
| Key state guard | 38 |
| `QHS4_PUBLIC_KEY_BYTES` | 68 |
| `QHS4_PRIVATE_KEY_BYTES` | 68 |
| `QHS4_SIGNATURE_BYTES` | 18,216 |
| `QHS4_TOTAL_HEIGHT` | 64 |
| `QHS4_FORS_BYTES` | 4,608 |
| QHS-4 hypertree layers | 8 |
| QHS-4 subtree height | 8 |
| QHS-4 FORS trees | 16 |
| QHS-4 FORS height | 8 |

## 10. QHS production formats

### 10.1 QHS-1 public key (64 bytes)

```
offset  size  field
0       1     version        // 1
1       1     algorithm      // 1 = QHS-1
2       1     height         // 8
3       1     reserved       // 0
4       32    merkle_root
36      28    reserved       // 0
```

### 10.2 QHS-1 private key (64 bytes)

```
offset  size  field
0       1     version        // 1
1       1     algorithm      // 1
2       1     height         // 8
3       1     reserved       // 0
4       32    seed
36      2     next_leaf      // 0..=256, little-endian
38      26    reserved       // 0
```

The private key is stateful. `next_leaf` must be persisted atomically after every signature. Reusing or rolling back a leaf is a security break.

### 10.3 QHS-1 signature (2408 bytes)

```
offset  size  field
0       1     version        // 1
1       1     algorithm      // 1
2       2     leaf_index     // 0..=255, little-endian
4       2144  wots_signature // 67 × 32 bytes
2148    256   auth_path      // 8 × 32 bytes
2404    4     checksum       // BLAKE3-derived
```

Canonical rules:

- `version == 1`, `algorithm == 1`.
- `leaf_index < 256`.
- The checksum matches the first 2404 bytes.
- The auth path is exactly 8 nodes.
- No non-canonical trailing data.

### 10.4 Checksum

```
BLAKE3("qWp QHS-1 signature-checksum" || first 2404 bytes)[0..4]
```

The checksum detects accidental corruption; the Merkle root and WOTS chains provide authentication.

### 10.5 QHS-1 public-leaf cache (8,260 bytes, optional)

The CLI may store the 256 public Merkle leaves next to the private key as
`<private-key>.cache`. The cache is a performance aid, not a key and not part of
the signature format.

```
offset  size  field
0       1     version        // 1
1       1     algorithm      // 1
2       1     height         // 8
3       1     kind           // 2 = keyed leaf cache
4       32    fingerprint    // BLAKE3 derive-key("qWp QHS-1 cache fingerprint", seed)
36      8192  leaves         // 256 × 32 bytes, leaf 0 first
8228    32    mac            // BLAKE3 keyed MAC("qWp QHS-1 cache mac", first 8228 bytes)
```

Canonical rules:

- The file is exactly 8,260 bytes; any other length is ignored.
- The CLI reads at most 8,261 bytes, so an oversized or special file cannot force an unbounded allocation.
- Header is `[1, 1, 8, 2]`.
- The fingerprint must match the private key seed; a foreign cache is ignored.
- The keyed MAC must match the first 8,228 bytes; a corrupt or forged cache is ignored.
- A rejected or missing cache causes the leaves to be recomputed.
- The file is written atomically with mode `0600` on Unix.

The cache contains only public Merkle commitments. It never contains the seed,
WOTS secrets, or chain values. A poisoned cache cannot produce a valid forgery:
the verifier recomputes the Merkle root, so altered leaves yield an invalid
signature. The cache is therefore outside the production security boundary.

### 10.6 QHS-2 public key (64 bytes)

```
offset  size  field
0       1     version        // 2
1       1     algorithm      // 2 = QHS-2
2       1     height         // 8
3       1     reserved       // 0
4       32    merkle_root
36      28    reserved       // 0
```

### 10.7 QHS-2 private key (64 bytes)

```
offset  size  field
0       1     version        // 2
1       1     algorithm      // 2
2       1     height         // 8
3       1     reserved       // 0
4       32    seed
36      2     next_leaf      // 0..=256, little-endian
38      26    reserved       // 0
```

The QHS-2 private key is stateful exactly like QHS-1.

### 10.8 QHS-2 signature (1,704 bytes)

```
offset  size  field
0       1     version        // 2
1       1     algorithm      // 2
2       2     leaf_index     // 0..=255, little-endian
4       1440  wots_signature // 45 × 32 bytes
1444    256   auth_path      // 8 × 32 bytes
1700    4     checksum       // BLAKE3-derived
```

Canonical rules:

- `version == 2`, `algorithm == 2`.
- `leaf_index < 256`.
- The checksum matches the first 1,700 bytes.
- The auth path is exactly 8 nodes.
- No non-canonical trailing data.

### 10.9 QHS-2 checksum

```
BLAKE3("qWp QHS-2 signature-checksum" || first 1700 bytes)[0..4]
```

The checksum detects accidental corruption; the Merkle root and WOTS chains
provide authentication.

### 10.10 QHS-2 public-leaf cache (8,260 bytes, optional)

The QHS-2 cache has the same layout as QHS-1 with different header,
fingerprint, and MAC contexts:

```
offset  size  field
0       1     version        // 2
1       1     algorithm      // 2
2       1     height         // 8
3       1     kind           // 2 = keyed leaf cache
4       32    fingerprint    // BLAKE3 derive-key("qWp QHS-2 cache fingerprint", seed)
36      8192  leaves         // 256 × 32 bytes, leaf 0 first
8228    32    mac            // BLAKE3 keyed MAC("qWp QHS-2 cache mac", first 8228 bytes)
```

QHS-1, QHS-2, QHS-3, and QHS-3.1 caches are not interchangeable: the header,
length, and fingerprint context differ, and a mismatched cache is ignored and
recomputed.

### 10.11 QHS-3 public key (64 bytes)

```
offset  size  field
0       1     version        // 3
1       1     algorithm      // 3 = QHS-3
2       1     height         // 12
3       1     reserved       // 0
4       32    merkle_root
36      28    reserved       // 0
```

### 10.12 QHS-3 private key (64 bytes)

```
offset  size  field
0       1     version        // 3
1       1     algorithm      // 3
2       1     height         // 12
3       1     reserved       // 0
4       32    seed
36      2     next_leaf      // 0..=4096, little-endian
38      26    reserved       // 0
```

### 10.13 QHS-3 signature (1,832 bytes)

```
offset  size  field
0       1     version        // 3
1       1     algorithm      // 3
2       2     leaf_index     // 0..=4095, little-endian
4       1440  wots_signature // 45 × 32 bytes
1444    384   auth_path      // 12 × 32 bytes
1828    4     checksum       // BLAKE3-derived
```

Canonical rules:

- `version == 3`, `algorithm == 3`.
- `leaf_index < 4096`.
- The checksum matches the first 1,828 bytes.
- The auth path is exactly 12 nodes.
- No non-canonical trailing data.

### 10.14 QHS-3 checksum

```
BLAKE3("qWp QHS-3 signature-checksum" || first 1828 bytes)[0..4]
```

### 10.15 QHS-3 public-leaf cache (131,140 bytes, optional)

```
offset   size    field
0        1       version        // 3
1        1       algorithm      // 3
2        1       height         // 12
3        1       kind           // 2 = keyed leaf cache
4        32      fingerprint    // BLAKE3 derive-key("qWp QHS-3 cache fingerprint", seed)
36       131072  leaves         // 4096 × 32 bytes, leaf 0 first
131108   32      mac            // BLAKE3 keyed MAC("qWp QHS-3 cache mac", first 131108 bytes)
```

QHS-3 caches are not interchangeable with QHS-1, QHS-2, or QHS-3.1 caches.

### 10.16 QHS-3.1 tree cache (262,180 bytes, optional)

QHS-3.1 is the tree-cache profile of QHS-3. Keys and signatures are identical
to QHS-3; only the signing cache differs.

```
offset    size    field
0         1       version        // 3
1         1       algorithm      // 3
2         1       height         // 12
3         1       kind           // 3 = keyed tree cache
4         32      fingerprint    // BLAKE3 derive-key("qWp QHS-3.1 cache fingerprint", seed)
36        131072  leaves         // 4096 × 32 bytes
131108    131040  nodes          // 4095 internal nodes, level 1..12
262148    32      mac            // BLAKE3 keyed MAC("qWp QHS-3.1 tree cache mac", first 262148 bytes)
```

The internal nodes are stored level by level: 2,048 nodes at level 1, 1,024 at
level 2, and so on, with the root at offset 4,094 within the node region.
QHS-3.1 signatures verify with QHS-3 verifiers and vice versa.

### 10.17 Key state guard (38 bytes, optional)

The CLI may write `<private-key>.state` to detect accidental counter rollback
(e.g., restoring an old private-key backup).

```
offset  size  field
0       1     version        // 1, 2, or 3
1       1     algorithm      // 1, 2, or 3
2       1     height         // 8 or 12
3       1     reserved       // 0
4       2     counter        // last known next_leaf, little-endian
6       32    mac            // BLAKE3 keyed MAC("qWp key state guard", first 6 bytes)
```

Rules:

- Written atomically with mode `0600`.
- If the guard counter is greater than the key counter, signing is refused
  with a rollback error.
- If the guard counter is behind the key counter, it is advanced to the key
  counter.
- A missing or corrupt guard is rebuilt from the key.
- A guard belonging to a different key is refused; delete the guard only when
  intentionally resetting the key state.

This detects accidental rollback of the key file. If the key and guard are
restored together, or copied together from another host, local detection is
impossible without a hardware monotonic counter; hardware-backed counters are
outside the local threat model.

### 10.18 QHS-4 public key (68 bytes)

```
offset  size  field
0       1     version        // 4
1       1     algorithm      // 4 = QHS-4
2       1     height         // 64
3       1     reserved       // 0
4       32    PK.seed
36      32    hypertree_root
```

### 10.19 QHS-4 private key (68 bytes)

```
offset  size  field
0       1     version        // 4
1       1     algorithm      // 4
2       1     height         // 64
3       1     reserved       // 0
4       32    SK.seed
36      32    PK.seed
```

The QHS-4 private key is stateless. There is no `next_leaf`, no cache, and no
state guard. Signing must not modify the key file.

### 10.20 QHS-4 signature (18,216 bytes)

```
offset   size    field
0        1       version        // 4
1        1       algorithm      // 4
2        1       height         // 64
3        1       reserved       // 0
4        32      randomizer     // R
36       4608    fors_signature // 16 × (32 secret + 256 auth)
4644     13568   hypertree      // 8 × (1,440 WOTS + 256 auth)
18212    4       checksum       // BLAKE3-derived
```

Canonical rules:

- Header is exactly `[4, 4, 64, 0]`.
- The checksum matches the first 18,212 bytes.
- The FORS region is 16 entries of 32-byte secret + 8×32-byte auth path.
- The hypertree region is eight layers of 1,440-byte WOTS signature + 8×32-byte
  auth path.
- No non-canonical trailing data.

### 10.21 QHS-4 checksum

```
BLAKE3("qWp QHS-4 signature-checksum" || first 18212 bytes)[0..4]
```

The checksum detects accidental corruption; the FORS/WOTS hash chains and
hypertree paths provide authentication.

### 10.22 QHS-4 state and cache

QHS-4 has no counter, no public-leaf cache, and no key state guard. The CLI
`qhs4-sign` command reads the 68-byte private key and writes only the signature.
It does not create `.cache`, `.treecache`, or `.state` files and does not update
the key file. This is the intended stateless profile.

### 10.23 QHS-4.1 fast-signing profile

QHS-4.1 is a performance profile of QHS-4, not a new format. It uses the same
68-byte keys, the same 18,216-byte signature, the same header `[4, 4, 64, 0]`,
and the same checksum. The `qhs41-*` CLI commands use the parallel signer; the
`qhs4-*` commands remain the sequential reference. `qhs4-verify` and
`qhs41-verify` accept both profiles. There is no cache or state file.

## 11. Open items

No open production format items. QHS-1, QHS-2, QHS-3, QHS-3.1, QHS-4, the
QHS-4.1 fast-signing profile (same QHS-4 formats), the QHS-3.1 tree cache, and
the key state guard are frozen and version-separated. The legacy 160-byte v0
container remains research-only and is not used for production signing or
verification.
