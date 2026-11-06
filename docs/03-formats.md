# qWp Format Specification (Phase 0)

**Status:** Foundation formats frozen; signature semantics pending ADR-0001.  
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

## 6. Signature semantics

The original equation `S = P·M·P⁻¹` is rejected (see `docs/security-memo.md`). The replacement is selected by `docs/adr/0001-signature-paradigm.md`. Until that ADR is accepted:

- the container may be parsed and attacked;
- no `sign` or `verify` function may be shipped;
- the signature format is marked **research v0**.

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

## 9. Open items

- ADR-0001 signature paradigm (critical).
- Public key may need to grow if the chosen signature uses a different public object.
- Signature may need to grow for a topological construction.
- These are tracked in `docs/gap-register.md`, not hidden.
