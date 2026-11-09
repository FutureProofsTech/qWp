# qWp QHS Version Family

**Status:** Design baseline for versioned QHS variants.  
**Rule:** Every version gets its own ADR, proof, format version, domain contexts, cache context, KAT, tests, attack harness, Kani proofs, fuzz coverage, timing, and 1-hour soak. A version is never silently extended.

---

## 1. Design axes

The version family is organized around six axes:

1. **Stateful vs stateless** — can the signer keep a monotonic counter and never clone the key?
2. **Signatures per key** — 256, 4,096, 65,536, or unbounded.
3. **Signature size** — 1.3–3.4 KB for hash-based stateful variants; 7–30 KB for stateless.
4. **Signing latency** — offline signing can tolerate hundreds of milliseconds; interactive services cannot.
5. **Quantum margin** — 128-bit classical / 64-bit quantum baseline; optional 256-bit quantum margin.
6. **Verifier profile** — server, bootloader, MCU, or long-term archive.

## 2. Version matrix

| Version | Construction | Stateful | Sigs/key | Signature | Keygen | Cached sign | Verify | Best use |
|---|---|---:|---:|---:|---:|---:|---:|---|
| **QHS-1** | b=4, h=8 | Yes | 256 | 2,408 B | 10–13 ms | 0.21–0.33 ms | 0.14 ms | speed-first offline signing |
| **QHS-2** | b=6, h=8 | Yes | 256 | 1,704 B | 27–28 ms | 0.46–0.61 ms | 0.41 ms | compact firmware/release signing |
| **QHS-3** | b=6, h=12 | Yes | 4,096 | 1,832 B | ≈0.40–0.44 s | ≈1.60–1.70 ms | ≈0.39 ms | high-volume release pipelines |
| **QHS-3.1** | b=6, h=12, tree cache | Yes | 4,096 | 1,832 B | ≈0.40–0.41 s | **≈0.35–0.36 ms** | ≈0.39 ms | high-volume signing with fast sign |
| QHS-4 (planned) | stateless hypertree/FORS | No | unbounded | 7–30 KB | fast | slow | ≈ms | concurrent/high-volume services |
| QHS-5 (planned) | 512-bit hash, h=8 | Yes | 256 | ≈3.4 KB | ≈2× QHS-2 | ≈2× QHS-2 | ≈2× QHS-2 | 256-bit quantum margin |
| QHS-6 (planned) | QHS + classical hybrid | Yes | 256 | QHS + classical | QHS + classical | QHS + classical | QHS + classical | migration/compliance |
| QHS-E | QHS verifier profile | n/a | n/a | QHS-1/2/3/3.1 | n/a | n/a | same | bootloader/MCU verifier |

## 3. Decision guide

1. **Can the key stay stateful and single-writer?**
   - Yes → QHS-1/2/3/3.1.
   - No → QHS-4 (stateless); this is a major new design, not a parameter tweak.

2. **How many signatures per key?**
   - ≤256 → QHS-1 or QHS-2.
   - ≤4,096 → QHS-3.
   - >4,096 → QHS-3 with multiple keys, or a future hypertree variant. A single tree beyond h=12 makes keygen/cache large.

3. **What matters more: size or speed?**
   - Speed → QHS-1.
   - Size → QHS-2.
   - Both, with more capacity → QHS-3.
   - More capacity and faster signing → QHS-3.1.

4. **Do you need 256-bit quantum margin?**
   - No → QHS-1/2/3/3.1.
   - Yes → QHS-5 (new hash-output profile).

5. **Do you need standards, HSM, or classical hybrid?**
   - Hybrid → QHS-6.
   - Standards/HSM → a deployment profile and independent audit, not a new hash-based parameter set.

6. **Is the verifier a constrained MCU/bootloader?**
   - Use QHS-E: the same signatures, a no_std verifier profile, code-size and stack benchmarks.

## 4. QHS-3: high-capacity stateful

QHS-3 is the next implemented version. It keeps the QHS-2 WOTS parameters and extends the Merkle tree from height 8 to height 12:

| Parameter | QHS-3 |
|---|---:|
| WOTS base | 64 |
| Chains | 45 × 63 steps |
| Merkle height | 12 |
| Leaves/signatures | 4,096 |
| Public key | 64 B |
| Private key | 64 B |
| Auth path | 384 B |
| Signature | **1,832 B** |
| Cache | 131,112 B (128 KiB leaves) |
| Keygen | ≈0.40–0.44 s |
| Cached sign | ≈1.60–1.70 ms |
| Verify | ≈0.39 ms |

QHS-3.1 is the tree-cache profile of QHS-3: identical keys, signature bytes,
KAT, capacity, and proof; signing drops to ≈0.35–0.36 ms using a 262,152-byte
tree cache. Use QHS-3.1 when signing latency matters; QHS-3 remains available.

Why h=12:

- 4,096 signatures per key is enough for years of CI/release activity.
- `next_leaf` still fits the 64-byte key format (`u16`, max 4,096).
- Keygen stays under a second with parallel leaf derivation.
- The cache is 128 KiB, acceptable for a host signer.
- The signature grows by only 128 bytes over QHS-2.

h=16 (65,536 signatures) would require a `u32` counter and a 2 MiB cache; h=12 is the better first high-capacity step.

## 5. QHS-4: stateless (planned, not implemented)

A stateless version cannot reuse the single-tree stateful design. It needs a hypertree and a few-time signature layer (SPHINCS+-style) or another stateless construction. That means:

- 7–30 KB signatures;
- much slower signing;
- a new proof, new formats, new tests, and a new implementation;
- no 256-signature state limit.

It is a separate project and must not be presented as a parameter tweak.

## 6. QHS-5: 256-bit quantum margin (planned)

QHS-5 would use a 512-bit hash output (or a 512-bit mode built from BLAKE3 XOF):

- WOTS chains: 45 × 64 B = 2,880 B;
- auth path: 8 × 64 B = 512 B;
- signature: ≈3,400 B;
- roughly 2× hashing cost;
- 256-bit classical / 128-bit quantum margin.

This requires a 64-byte hash mode and a new proof/format version.

## 7. QHS-6: classical hybrid (planned)

A hybrid would carry both a QHS signature and a classical signature (for example Ed25519 or RSA). Verification accepts only if both verify. This provides migration safety but requires a classical implementation and a new hybrid proof. It is not part of the zero-dependency hash-only core unless the classical primitive is also in-tree.

## 8. QHS-E: embedded verifier profile

QHS-E is not a new signature. It is a `no_std` verifier profile of QHS-1/2/3/3.1 with:

- fixed-size stack usage;
- no heap;
- code-size and cycle benchmarks on constrained targets;
- the same public keys and signatures.

## 9. Release rule

Each signature version is independently gated:

1. ADR accepted.
2. Proof written and reviewed.
3. Format version and domain contexts fixed.
4. KAT, unit, integration, attack, Kani, fuzz, timing, mutation, coverage.
5. 1-hour soak on the exact release commit.
6. Versioned tag; older versions remain available.

Profiles such as QHS-3.1 share the base signature version, proof, KAT, and
signature bytes. They still get their own ADR, cache format, tests, timing, and
release tag.
