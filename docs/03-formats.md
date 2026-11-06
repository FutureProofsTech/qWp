# qWp Format Specification (Phase 0)

**Status:** Foundation formats frozen; production signature is QHS-1 (ADR-0002). The 160-byte container is legacy research v0.  
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

## 10. QHS-1 production formats

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

### 10.5 QHS-1 public-leaf cache (8,232 bytes, optional)

The CLI may store the 256 public Merkle leaves next to the private key as
`<private-key>.cache`. The cache is a performance aid, not a key and not part of
the signature format.

```
offset  size  field
0       1     version        // 1
1       1     algorithm      // 1
2       1     height         // 8
3       1     reserved       // 0
4       32    fingerprint    // BLAKE3 derive-key("qWp QHS-1 cache fingerprint", seed)
36      8192  leaves         // 256 × 32 bytes, leaf 0 first
8228    4     checksum       // BLAKE3(first 8228 bytes)[0..4]
```

Canonical rules:

- The file is exactly 8,232 bytes; any other length is ignored.
- The CLI reads at most 8,233 bytes, so an oversized or special file cannot force an unbounded allocation.
- Header is `[1, 1, 8, 0]`.
- The fingerprint must match the private key seed; a foreign cache is ignored.
- The checksum must match the first 8,228 bytes; a corrupt cache is ignored.
- A rejected or missing cache causes the leaves to be recomputed.
- The file is written atomically with mode `0600` on Unix.

The cache contains only public Merkle commitments. It never contains the seed,
WOTS secrets, or chain values. A poisoned cache cannot produce a valid forgery:
the verifier recomputes the Merkle root, so altered leaves yield an invalid
signature. The cache is therefore outside the production security boundary.

## 11. Open items

No open production format items. The legacy 160-byte v0 container remains
research-only and is not used for production signing or verification.
